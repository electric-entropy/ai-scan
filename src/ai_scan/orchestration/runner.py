"""Execute a plan as a resumable, checkpointed state machine.

State machine: ``planned → authorized → running → confirming → cleaning_up →
completed | completed_with_gaps | cancelled | failed``.

Classification goes through the M7 confidence path (``_select_validators`` +
``_evaluate_pack_case`` — the same single confirmation predicate used by
``run_injection_pack``), so the runner never re-decides ``confirmed`` on its own.
Checkpoints are written after every physical attempt (so a resumed run never
repeats one), budget exhaustion / scope denial become structured coverage gaps,
and cancellation runs authorized cleanup. The runner constructs no transport —
the caller supplies a ``responder`` (broker+adapter wired, or a stub in tests).
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ai_scan.core.modes import resolve_policy
from ai_scan.injection import (
    ExchangeOutcome,
    InjectionCase,
    InjectionFinding,
    InjectionStatus,
    _evaluate_pack_case,
    _select_validators,
)
from ai_scan.orchestration.checkpoint import Checkpoint, load_checkpoint, write_checkpoint_atomic
from ai_scan.orchestration.planner import Plan, PlanError, PlannedCase
from ai_scan.orchestration.scheduler import schedule
from ai_scan.packs import Pack, resolve_packs

Responder = Callable[[InjectionCase], ExchangeOutcome]
Cleanup = Callable[[Plan], None]


class RunState(enum.StrEnum):
    """Plan runner states, matching the Milestone 8 state-machine contract."""

    PLANNED = "planned"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    CONFIRMING = "confirming"
    CLEANING_UP = "cleaning_up"
    COMPLETED = "completed"
    COMPLETED_WITH_GAPS = "completed_with_gaps"
    CANCELLED = "cancelled"
    FAILED = "failed"


@dataclass(frozen=True)
class RunResult:
    """Final run output and accounting."""

    state: RunState
    findings: tuple[InjectionFinding, ...]
    request_count: int
    coverage_gaps: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> InjectionStatus:
        if any(f.status is InjectionStatus.CONFIRMED for f in self.findings):
            return InjectionStatus.CONFIRMED
        if any(f.status is InjectionStatus.POTENTIAL for f in self.findings):
            return InjectionStatus.POTENTIAL
        if any(f.status is InjectionStatus.INCONCLUSIVE for f in self.findings):
            return InjectionStatus.INCONCLUSIVE
        return InjectionStatus.NOT_OBSERVED


def run_plan(
    plan: Plan,
    responder: Responder,
    *,
    canary: str,
    goal: str = "",
    checkpoint_path: str | None = None,
    authorized_plan_digest: str | None = None,
    cleanup: Cleanup | None = None,
) -> RunResult:
    """Run ``plan`` as a resumable state machine through the M7 confidence path.

    ``authorized_plan_digest`` is the receipt-bound digest: when supplied it must
    exactly match ``plan.digest`` before any responder call. Checkpoints are
    secret-free and keyed by deterministic case ids; completed ids are never
    re-run after resume.
    """
    if authorized_plan_digest is not None and authorized_plan_digest != plan.digest:
        raise PlanError("plan digest does not match authorization receipt")

    packs = _resolve_plan_packs(plan)
    checkpoint = _initial_checkpoint(plan, checkpoint_path)
    checkpoint.state = RunState.AUTHORIZED.value
    _persist(checkpoint_path, checkpoint)

    findings: list[InjectionFinding] = [
        _finding_from_record(v) for v in checkpoint.completed.values() if v.get("kind") == "attack"
    ]
    completed = set(checkpoint.completed)
    control_results = dict(checkpoint.control_results)
    coverage_gaps: list[str] = []

    try:
        checkpoint.state = RunState.RUNNING.value
        _persist(checkpoint_path, checkpoint)

        # Controls run before attacks; a control that emits the canary blocks
        # confirmation for its family.
        for case in plan.control_cases():
            if case.case_id in completed:
                continue
            if checkpoint.request_count >= plan.limits.max_physical_requests:
                coverage_gaps.append(f"{case.case_id}: budget exhausted before control")
                break
            outcome = _send(case, responder, canary)
            checkpoint.request_count += max(1, outcome.attempts)
            if _usable(outcome) and canary in outcome.body:
                control_results[_family_key(case)] = True
            checkpoint.control_results = control_results
            checkpoint.completed[case.case_id] = {
                "family": case.family,
                "status": InjectionStatus.NOT_OBSERVED.value,
                "prompt": case.template,
                "proof": None,
                "kind": "control",
            }
            completed.add(case.case_id)
            _persist(checkpoint_path, checkpoint)

        checkpoint.state = RunState.CONFIRMING.value
        _persist(checkpoint_path, checkpoint)

        for case in schedule(plan).order:
            if case.case_id in completed:
                continue
            if checkpoint.request_count >= plan.limits.max_physical_requests:
                coverage_gaps.append(f"{case.case_id}: budget exhausted")
                continue
            outcome = _send(case, responder, canary)
            checkpoint.request_count += max(1, outcome.attempts)
            finding = _classify_case(
                case, outcome, canary,
                pack=packs[case.pack_id],
                control_succeeded=control_results.get(_family_key(case), False),
            )
            findings.append(finding)
            checkpoint.completed[case.case_id] = _record_from_finding(finding, kind="attack")
            completed.add(case.case_id)
            _persist(checkpoint_path, checkpoint)
    except (KeyboardInterrupt, SystemExit):
        checkpoint.state = RunState.CLEANING_UP.value
        _persist(checkpoint_path, checkpoint)
        if cleanup is not None:
            cleanup(plan)
        checkpoint.state = RunState.CANCELLED.value
        _persist(checkpoint_path, checkpoint)
        return RunResult(
            RunState.CANCELLED, tuple(findings), checkpoint.request_count, tuple(coverage_gaps)
        )

    state = RunState.COMPLETED_WITH_GAPS if coverage_gaps else RunState.COMPLETED
    checkpoint.state = RunState.CLEANING_UP.value
    _persist(checkpoint_path, checkpoint)
    if cleanup is not None:
        cleanup(plan)
    checkpoint.state = state.value
    _persist(checkpoint_path, checkpoint)
    return RunResult(state, tuple(findings), checkpoint.request_count, tuple(coverage_gaps))


def _family_key(case: PlannedCase) -> str:
    return f"{case.pack_id}:{case.family}"


def _resolve_plan_packs(plan: Plan) -> dict[str, Pack]:
    try:
        policy = resolve_policy(plan.mode)
        resolved = {p.id: p for p in resolve_packs(plan.mode, trust=policy.pack_trust)}
    except Exception as exc:  # PolicyError / PackResolutionError
        raise PlanError(f"cannot resolve packs for plan in mode {plan.mode!r}: {exc}") from exc
    missing = {c.pack_id for c in plan.cases} - set(resolved)
    if missing:
        raise PlanError("plan references packs that no longer resolve")
    return resolved


def _initial_checkpoint(plan: Plan, checkpoint_path: str | None) -> Checkpoint:
    if checkpoint_path is None:
        return Checkpoint(plan_digest=plan.digest, state=RunState.PLANNED.value)
    try:
        return load_checkpoint(checkpoint_path, expected_plan_digest=plan.digest)
    except FileNotFoundError:
        return Checkpoint(plan_digest=plan.digest, state=RunState.PLANNED.value)


def _persist(path: str | None, checkpoint: Checkpoint) -> None:
    if path is not None:
        write_checkpoint_atomic(path, checkpoint)


def _send(case: PlannedCase, responder: Responder, canary: str) -> ExchangeOutcome:
    prompt = case.template.replace("{canary}", canary)
    return responder(InjectionCase(case.family, case.template, prompt))


def _usable(outcome: ExchangeOutcome) -> bool:
    return (
        outcome.transport_ok
        and not outcome.redirected
        and outcome.status < 400
        and not outcome.truncated
    )


def _classify_case(
    case: PlannedCase,
    outcome: ExchangeOutcome,
    canary: str,
    *,
    pack: Pack,
    control_succeeded: bool,
) -> InjectionFinding:
    """Classify one attack case through the single M7 confidence predicate."""
    rendered = case.template.replace("{canary}", canary)
    validators = _select_validators(pack.validators)
    status, proof = _evaluate_pack_case(
        outcome, canary, rendered, validators,
        control_succeeded=control_succeeded,
        trial=pack.trial_policy,
        requires_state_change=pack.side_effects,
    )
    return InjectionFinding(case.family, status, rendered, proof)


def _record_from_finding(finding: InjectionFinding, *, kind: str) -> dict[str, Any]:
    return {
        "family": finding.family,
        "status": finding.status.value,
        "prompt": finding.prompt,
        "proof": finding.proof,
        "kind": kind,
    }


def _finding_from_record(record: dict[str, Any]) -> InjectionFinding:
    return InjectionFinding(
        family=str(record["family"]),
        status=InjectionStatus(str(record["status"])),
        prompt=str(record["prompt"]),
        proof=None if record.get("proof") is None else str(record["proof"]),
    )


__all__ = ["Cleanup", "Responder", "RunResult", "RunState", "run_plan"]
