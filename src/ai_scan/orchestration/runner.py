"""Execute a plan as a resumable, checkpointed state machine.

State machine: ``planned → validated → running → confirming → cleaning_up →
completed | completed_with_gaps | cancelled | failed``.

Classification goes through the shared evidence contract
(:mod:`~ai_scan.orchestration.evidence`, over the M7 ``evaluate_trials``
predicate) — the same derivation checkpoints, bundles and replay re-run over the
persisted per-trial evidence — so the runner never re-decides ``confirmed`` on
its own.
Checkpoints are written after every physical attempt (so a resumed run never
repeats one), budget exhaustion / scope denial become structured coverage gaps,
and cancellation/error pass through a CLEANING_UP phase to a terminal state
(side-effect cleanup for stateful families is a budgeted broker step, never an
unaccounted callback). The runner constructs no transport —
the caller supplies a ``responder`` (broker+adapter wired, or a stub in tests).
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ai_scan.core.modes import resolve_policy
from ai_scan.injection import (
    CONTROL_GAP,
    ExchangeOutcome,
    InjectionCase,
    InjectionFinding,
    InjectionStatus,
    merge_control_results,
    physical_attempts,
)
from ai_scan.orchestration.checkpoint import Checkpoint, load_checkpoint, write_checkpoint_atomic
from ai_scan.orchestration.evidence import (
    CONTROL_STATUS,
    derive_attack,
    derive_control,
    disclosure_semantic,
    family_key,
    rendered_prompt,
    trial_from_dict,
    trial_to_dict,
)
from ai_scan.orchestration.planner import Plan, PlanError, PlannedCase
from ai_scan.orchestration.scheduler import schedule
from ai_scan.packs import Pack, resolve_packs

Responder = Callable[[InjectionCase], ExchangeOutcome]
# Observes each completed case's (case, response, finding) — used to capture
# redacted evidence for bundle export. A plain callable: the runner imports no
# evidence-graph module, so there is no cycle.
Observer = Callable[[PlannedCase, ExchangeOutcome, InjectionFinding], None]


class RunState(enum.StrEnum):
    """Plan runner states, matching the Milestone 8 state-machine contract."""

    PLANNED = "planned"
    VALIDATED = "validated"
    RUNNING = "running"
    CONFIRMING = "confirming"
    CLEANING_UP = "cleaning_up"
    COMPLETED = "completed"
    COMPLETED_WITH_GAPS = "completed_with_gaps"
    CANCELLED = "cancelled"
    FAILED = "failed"


# Aggregate severity across the full seven-state vocabulary (highest wins).
_STATUS_SEVERITY = {
    InjectionStatus.CONFIRMED: 6,
    InjectionStatus.LIKELY: 5,
    InjectionStatus.SUSPECTED: 4,
    InjectionStatus.POTENTIAL: 4,
    InjectionStatus.INCONCLUSIVE: 2,
    InjectionStatus.BLOCKED: 1,
    InjectionStatus.NOT_OBSERVED: 0,
    InjectionStatus.NOT_TESTED: 0,
}


@dataclass(frozen=True)
class RunResult:
    """Final run output and accounting."""

    state: RunState
    findings: tuple[InjectionFinding, ...]
    request_count: int
    coverage_gaps: tuple[str, ...] = field(default_factory=tuple)

    @property
    def status(self) -> InjectionStatus:
        """The highest-severity finding status — full seven-state, no collapse.

        ``likely``/``suspected``/``blocked``/``not_tested`` are preserved as the
        run's aggregate (never flattened to ``not_observed``).
        """
        if not self.findings:
            return InjectionStatus.NOT_OBSERVED
        return max((f.status for f in self.findings), key=lambda s: _STATUS_SEVERITY[s])


def run_plan(
    plan: Plan,
    responder: Responder,
    *,
    canary: str,
    disclosure_marker: str | None = None,
    goal: str = "",
    checkpoint_path: str | None = None,
    expected_plan_digest: str | None = None,
    observer: Observer | None = None,
) -> RunResult:
    """Run ``plan`` as a resumable state machine through the M7 confidence path.

    ``expected_plan_digest`` is a plan-integrity guard: when supplied it must
    exactly match ``plan.digest`` before any responder call. Checkpoints are
    secret-free and keyed by deterministic case ids; completed ids are never
    re-run after resume.
    """
    if expected_plan_digest is not None and expected_plan_digest != plan.digest:
        raise PlanError("plan digest does not match the expected plan")

    packs = _resolve_plan_packs(plan)
    checkpoint = _initial_checkpoint(plan, checkpoint_path, disclosure_marker=disclosure_marker)
    # A resumed checkpoint carries the original canary; reuse it so rendered
    # prompts stay consistent with the already-completed (plan-bound) records.
    canary = checkpoint.canary or canary
    checkpoint.canary = canary
    # Reflected/known secrets observed across the run, threaded into every
    # checkpoint write so persisted proof/prompt state is redacted on disk.
    run_secrets: set[str] = set()
    if disclosure_marker is not None and disclosure_marker != canary:
        run_secrets.add(disclosure_marker)
    checkpoint.state = RunState.VALIDATED.value
    _persist(checkpoint_path, checkpoint, frozenset(run_secrets))

    # Control coverage is re-derived from persisted control *evidence* only; a
    # stored control result (or a legacy control record) without trials is never
    # trusted — those controls are re-run for real before any attack.
    for case_id, record in list(checkpoint.completed.items()):
        if record.get("kind") == "control" and "trials" not in record:
            del checkpoint.completed[case_id]
    control_results: dict[str, str] = {}
    plan_cases = {c.case_id: c for c in plan.cases}
    for case_id, record in checkpoint.completed.items():
        if record.get("kind") == "control":
            trials = [trial_from_dict(t) for t in record["trials"]]
            case = plan_cases[case_id]
            key = family_key(case)
            control_results[key] = merge_control_results(
                control_results.get(key),
                derive_control(plan, case, packs[case.pack_id], trials, canary, disclosure_marker),
            )
    checkpoint.control_results = dict(control_results)
    # M3: a prior in-flight attempt was physically issued (already counted) but its
    # outcome was never recorded. Reconcile it as one uncertain, unusable trial —
    # fail closed, never reissue — so resume neither re-counts nor repeats it.
    _reconcile_in_flight(checkpoint, plan_cases)
    _persist(checkpoint_path, checkpoint, frozenset(run_secrets))

    findings: list[InjectionFinding] = [
        _finding_from_record(v) for v in checkpoint.completed.values() if v.get("kind") == "attack"
    ]
    completed = set(checkpoint.completed)
    coverage_gaps: list[str] = []

    try:
        checkpoint.state = RunState.RUNNING.value
        _persist(checkpoint_path, checkpoint, frozenset(run_secrets))

        min_control_trials = plan.trial_policy[2]
        min_attack_trials = plan.trial_policy[0]

        # Controls run before attacks; a family confirms only against a usable
        # clean control. A control that emits the canary poisons the baseline; a
        # control that cannot be fully, usably exercised is a coverage gap.
        for case in plan.control_cases():
            if case.case_id in completed:
                continue
            if _requires_explicit_marker(packs[case.pack_id], case, disclosure_marker):
                coverage_gaps.append(f"{case.case_id}: LLM02 disclosure marker not supplied")
                family = family_key(case)
                control_results[family] = merge_control_results(
                    control_results.get(family), CONTROL_GAP
                )
                checkpoint.control_results = dict(control_results)
                checkpoint.progress.pop(case.case_id, None)
                continue
            outcomes = _run_trials(
                case, responder, canary, min_control_trials,
                checkpoint, plan, run_secrets, checkpoint_path,
                pack=packs[case.pack_id], disclosure_marker=disclosure_marker,
            )
            if not outcomes:
                coverage_gaps.append(f"{case.case_id}: control coverage incomplete")
                continue
            result = derive_control(
                plan, case, packs[case.pack_id], outcomes, canary, disclosure_marker
            )
            status = CONTROL_STATUS[result]
            if result == CONTROL_GAP:
                coverage_gaps.append(f"{case.case_id}: control coverage incomplete")
            family = family_key(case)
            control_results[family] = merge_control_results(control_results.get(family), result)
            checkpoint.control_results = dict(control_results)
            control_finding = InjectionFinding(
                case.family, status, case.template, None,
                attack_trials=0, successes=0, evidence=tuple(outcomes),
            )
            checkpoint.completed[case.case_id] = _record_from_finding(
                control_finding, kind="control"
            )
            checkpoint.progress.pop(case.case_id, None)
            completed.add(case.case_id)
            _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
            if observer is not None:
                observer(case, outcomes[-1], control_finding)

        checkpoint.state = RunState.CONFIRMING.value
        _persist(checkpoint_path, checkpoint, frozenset(run_secrets))

        for case in schedule(plan).order:
            if case.case_id in completed:
                continue
            if _requires_explicit_marker(packs[case.pack_id], case, disclosure_marker):
                coverage_gaps.append(f"{case.case_id}: LLM02 disclosure marker not supplied")
                finding = _inconclusive_disclosure_finding(case, canary)
                findings.append(finding)
                checkpoint.progress.pop(case.case_id, None)
                continue
            outcomes = _run_trials(
                case, responder, canary, min_attack_trials,
                checkpoint, plan, run_secrets, checkpoint_path,
                pack=packs[case.pack_id], disclosure_marker=disclosure_marker,
            )
            if not outcomes:
                coverage_gaps.append(f"{case.case_id}: budget exhausted")
                continue
            finding, representative = _classify_case(
                plan, case, outcomes, canary,
                pack=packs[case.pack_id],
                control=control_results.get(family_key(case)),
                disclosure_marker=disclosure_marker,
            )
            findings.append(finding)
            checkpoint.completed[case.case_id] = _record_from_finding(finding, kind="attack")
            checkpoint.progress.pop(case.case_id, None)
            completed.add(case.case_id)
            _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
            if observer is not None:
                observer(case, representative, finding)
    except (KeyboardInterrupt, SystemExit):
        # Operator interrupt: clean up and end in the CANCELLED terminal state.
        _run_cleanup(checkpoint_path, checkpoint, run_secrets, RunState.CANCELLED)
        return RunResult(
            RunState.CANCELLED, tuple(findings), checkpoint.request_count, tuple(coverage_gaps)
        )
    except Exception:
        # Ordinary error mid-run: pass through the CLEANING_UP phase to the FAILED
        # terminal state (finally-style), then propagate the error.
        _run_cleanup(checkpoint_path, checkpoint, run_secrets, RunState.FAILED)
        raise

    state = RunState.COMPLETED_WITH_GAPS if coverage_gaps else RunState.COMPLETED
    _run_cleanup(checkpoint_path, checkpoint, run_secrets, state)
    return RunResult(state, tuple(findings), checkpoint.request_count, tuple(coverage_gaps))


def _run_cleanup(
    checkpoint_path: str | None,
    checkpoint: Checkpoint,
    run_secrets: set[str],
    terminal: RunState,
) -> None:
    """Persist the transition through the CLEANING_UP phase to ``terminal``.

    The runner exposes **no** arbitrary, network-capable cleanup callback — that
    would be an unaccounted execution path. Side-effect cleanup for a stateful
    family is a budgeted, broker-mediated responder step (see
    :mod:`ai_scan.orchestration.stateful`), counted like any active probe.
    """
    checkpoint.state = RunState.CLEANING_UP.value
    _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
    checkpoint.state = terminal.value
    _persist(checkpoint_path, checkpoint, frozenset(run_secrets))


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


def _initial_checkpoint(
    plan: Plan, checkpoint_path: str | None, *, disclosure_marker: str | None = None
) -> Checkpoint:
    if checkpoint_path is None:
        return Checkpoint(plan_digest=plan.digest, state=RunState.PLANNED.value)
    try:
        return load_checkpoint(
            checkpoint_path,
            expected_plan_digest=plan.digest,
            plan=plan,
            disclosure_marker=disclosure_marker,
        )
    except FileNotFoundError:
        return Checkpoint(plan_digest=plan.digest, state=RunState.PLANNED.value)


def _persist(
    path: str | None, checkpoint: Checkpoint, known_secrets: frozenset[str] = frozenset()
) -> None:
    if path is not None:
        write_checkpoint_atomic(path, checkpoint, known_secrets=known_secrets)


def _send(case: PlannedCase, responder: Responder, canary: str) -> ExchangeOutcome:
    return responder(InjectionCase(case.family, case.template, rendered_prompt(case, canary)))


def _intent(case: PlannedCase, canary: str) -> dict[str, str]:
    return {
        "case_id": case.case_id,
        "kind": case.kind,
        "family": case.family,
        "prompt": rendered_prompt(case, canary),
    }


def _reconcile_in_flight(checkpoint: Checkpoint, plan_cases: dict[str, PlannedCase]) -> None:
    """Turn a resumed in-flight attempt into one uncertain, unusable, spent trial.

    The attempt was physically issued (and already counted) before the crash; its
    outcome is unknown, so it is recorded fail-closed (never reissued, never
    re-counted) and fills exactly one of its case's trial slots.
    """
    inf = checkpoint.in_flight
    if inf is None:
        return
    case = plan_cases.get(inf["case_id"])
    if case is not None:
        record = checkpoint.progress.setdefault(
            case.case_id,
            {"kind": case.kind, "family": case.family, "prompt": inf["prompt"], "trials": []},
        )
        record["trials"].append(trial_to_dict(ExchangeOutcome(body="", transport_ok=False)))
    checkpoint.in_flight = None


def _run_trials(
    case: PlannedCase,
    responder: Responder,
    canary: str,
    trials: int,
    checkpoint: Checkpoint,
    plan: Plan,
    run_secrets: set[str],
    checkpoint_path: str | None,
    *,
    pack: Pack,
    disclosure_marker: str | None,
) -> list[ExchangeOutcome]:
    """Run up to ``trials`` physical attempts for one case, write-ahead accounted.

    Each attempt's intent (and its budget cost) is persisted *before* the
    responder call, so an attempt issued but interrupted before its outcome is
    recorded is still counted (M3). Completed trials are persisted per case so a
    resumed run continues rather than repeating them.
    """
    prior = checkpoint.progress.get(case.case_id)
    outcomes: list[ExchangeOutcome] = (
        [trial_from_dict(t) for t in prior["trials"]] if prior else []
    )
    while len(outcomes) < trials:
        if checkpoint.request_count >= plan.limits.max_physical_requests:
            break
        remaining = plan.limits.max_physical_requests - checkpoint.request_count
        # Write-ahead intent: persist the attempt and its cost BEFORE issuing it.
        checkpoint.in_flight = _intent(case, canary)
        checkpoint.request_count += 1
        _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
        outcome = _send(case, responder, canary)
        if disclosure_marker is not None and _requires_semantic(pack, case):
            outcome = ExchangeOutcome(
                body=outcome.body,
                status=outcome.status,
                redirected=outcome.redirected,
                truncated=outcome.truncated,
                transport_ok=outcome.transport_ok,
                attempts=outcome.attempts,
                known_secrets=outcome.known_secrets,
                semantic=disclosure_semantic(plan, case, disclosure_marker, outcome.body),
            )
        run_secrets.update(outcome.known_secrets)
        try:
            attempts = physical_attempts(outcome)
        except ValueError:
            # The public responder boundary returned malformed retry accounting
            # after one physical request was already issued. Fail closed: keep the
            # write-ahead unit, discard the untrusted body, and exhaust the
            # remaining run budget so resume cannot reissue the trial.
            checkpoint.request_count = plan.limits.max_physical_requests
            outcome = ExchangeOutcome(body="", transport_ok=False, attempts=1)
        else:
            if attempts > remaining:
                # A broker/controller should prevent this. If it still happens,
                # never persist a count or trial above the canonical plan budget,
                # and never accept the over-budget response as evidence.
                checkpoint.request_count = plan.limits.max_physical_requests
                outcome = ExchangeOutcome(body="", transport_ok=False, attempts=remaining)
            else:
                # Account any retries the broker made beyond the write-ahead unit.
                checkpoint.request_count += attempts - 1
        checkpoint.in_flight = None
        outcomes.append(outcome)
        checkpoint.progress[case.case_id] = {
            "kind": case.kind,
            "family": case.family,
            "prompt": rendered_prompt(case, canary),
            "trials": [trial_to_dict(o) for o in outcomes],
        }
        _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
        if checkpoint.request_count >= plan.limits.max_physical_requests:
            break
    return outcomes


def _requires_semantic(pack: Pack, case: PlannedCase) -> bool:
    categories = frozenset(pack.mappings.get("owasp-llm", ()))
    return (
        case.family.startswith("prompt_disclosure")
        and "LLM02" in categories
        and "LLM01" not in categories
    )


def _requires_explicit_marker(
    pack: Pack, case: PlannedCase, disclosure_marker: str | None
) -> bool:
    return disclosure_marker is None and _requires_semantic(pack, case)


def _inconclusive_disclosure_finding(case: PlannedCase, canary: str) -> InjectionFinding:
    return InjectionFinding(
        case.family,
        InjectionStatus.INCONCLUSIVE,
        rendered_prompt(case, canary),
        None,
        attack_trials=0,
        successes=0,
        evidence=(),
    )


def _classify_case(
    plan: Plan,
    case: PlannedCase,
    outcomes: list[ExchangeOutcome],
    canary: str,
    *,
    pack: Pack,
    control: str | None,
    disclosure_marker: str | None,
) -> tuple[InjectionFinding, ExchangeOutcome]:
    """Classify one attack case's repeated trials through the evidence contract.

    Uses the resolved *plan* trial policy (not weaker pack-local values) and
    requires a matched clean control to reach ``confirmed``. Returns the finding
    (carrying its counts and every trial outcome) plus the representative outcome.
    """
    derived, representative = derive_attack(
        plan, case, pack, outcomes, canary, disclosure_marker, control
    )
    finding = InjectionFinding(
        case.family, derived.status, rendered_prompt(case, canary), derived.proof,
        attack_trials=derived.attack_trials, successes=derived.successes,
        evidence=tuple(outcomes),
    )
    return finding, representative if representative is not None else outcomes[-1]


def _record_from_finding(finding: InjectionFinding, *, kind: str) -> dict[str, Any]:
    return {
        "family": finding.family,
        "status": finding.status.value,
        "prompt": finding.prompt,
        "proof": finding.proof,
        "kind": kind,
        # Trial counts plus every persisted physical trial let a plan-bound load
        # re-derive the status through the shared evidence contract.
        "attack_trials": finding.attack_trials,
        "successes": finding.successes,
        "trials": [trial_to_dict(o) for o in finding.evidence],
    }


def _finding_from_record(record: dict[str, Any]) -> InjectionFinding:
    return InjectionFinding(
        family=str(record["family"]),
        status=InjectionStatus(str(record["status"])),
        prompt=str(record["prompt"]),
        proof=None if record.get("proof") is None else str(record["proof"]),
        attack_trials=int(record.get("attack_trials", 1)),
        successes=int(record.get("successes", 0)),
        evidence=tuple(trial_from_dict(t) for t in record.get("trials", ())),
    )


__all__ = ["Responder", "RunResult", "RunState", "run_plan"]
