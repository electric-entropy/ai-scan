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

from ai_scan.core.accounting import PhysicalCounter
from ai_scan.core.accounting import delta as ledger_delta
from ai_scan.core.accounting import require as require_ledger
from ai_scan.core.accounting import snapshot as snapshot_ledger
from ai_scan.core.modes import resolve_policy
from ai_scan.core.run_identity import RunIdentity, canary_commitment, evidence_canary
from ai_scan.injection import (
    CONTROL_GAP,
    ExchangeOutcome,
    InjectionCase,
    InjectionFinding,
    InjectionStatus,
    merge_control_results,
)
from ai_scan.orchestration.checkpoint import (
    Checkpoint,
    CheckpointError,
    load_checkpoint,
    marker_commitment,
    write_checkpoint_atomic,
)
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
from ai_scan.transport.redaction import scrub_text

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
    physical_request_count: PhysicalCounter | None = None,
) -> RunResult:
    """Run ``plan`` as a resumable state machine through the M7 confidence path.

    ``expected_plan_digest`` is a plan-integrity guard: when supplied it must
    exactly match ``plan.digest`` before any responder call. Checkpoints are
    secret-free and keyed by deterministic case ids; completed ids are never
    re-run after resume.
    """
    require_ledger(physical_request_count)
    if expected_plan_digest is not None and expected_plan_digest != plan.digest:
        raise PlanError("plan digest does not match the expected plan")

    packs = _resolve_plan_packs(plan)
    try:
        checkpoint = _initial_checkpoint(
            plan, checkpoint_path, canary=canary, disclosure_marker=disclosure_marker
        )
    except CheckpointError as exc:
        message = str(exc)
        if checkpoint_path is None or "run identity" not in message:
            raise
        if "disclosure marker" in message or "disclosure-marker" in message:
            # A disclosure-marker identity change (old→new, marker→missing,
            # missing→marker) is a loud, fail-closed error: the operator supplied
            # the wrong or no marker for an existing LLM02 run. No request is
            # issued and no prior LLM02 evidence is re-bound, exposed, or relabeled
            # under the new identity — the rejection happens during load, before
            # any responder call and before evidence re-derivation.
            raise
        # A caller supplied a different (randomly generated) canary for an existing
        # run. Preserve all spent work, issue no request, and expose no prior
        # finding under the new identity. Read the prior request_count structurally
        # only — never re-bind evidence under the mismatched identity. The
        # checkpoint is unchanged and still resumes with its original canary.
        prior = load_checkpoint(
            checkpoint_path,
            expected_plan_digest=plan.digest,
        )
        return RunResult(
            RunState.COMPLETED_WITH_GAPS,
            (),
            prior.request_count,
            ("checkpoint run identity mismatch",),
        )
    persisted_canary = evidence_canary(checkpoint.canary_commitment)
    if checkpoint.canary == persisted_canary:
        _rehydrate_checkpoint(checkpoint, persisted_canary, canary)
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
    _reconcile_in_flight(checkpoint, plan, plan_cases, canary, frozenset(run_secrets))
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
                physical_request_count=physical_request_count,
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
                plan, case, control_finding, canary=canary, checkpoint=checkpoint,
                run_secrets=frozenset(run_secrets),
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
                physical_request_count=physical_request_count,
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
            checkpoint.completed[case.case_id] = _record_from_finding(
                plan, case, finding, canary=canary, checkpoint=checkpoint,
                run_secrets=frozenset(run_secrets),
            )
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
    plan: Plan,
    checkpoint_path: str | None,
    *,
    canary: str,
    disclosure_marker: str | None = None,
) -> Checkpoint:
    if checkpoint_path is None:
        return Checkpoint(
            plan_digest=plan.digest,
            state=RunState.PLANNED.value,
            canary=canary,
            canary_commitment=canary_commitment(plan.digest, canary),
            marker_commitment=marker_commitment(plan.digest, disclosure_marker),
        )
    try:
        loaded = load_checkpoint(
            checkpoint_path,
            expected_plan_digest=plan.digest,
            plan=plan,
            disclosure_marker=disclosure_marker,
            expected_canary=canary,
            expected_marker_commitment=marker_commitment(plan.digest, disclosure_marker),
        )
        return loaded
    except FileNotFoundError:
        return Checkpoint(
            plan_digest=plan.digest,
            state=RunState.PLANNED.value,
            canary=canary,
            canary_commitment=canary_commitment(plan.digest, canary),
            marker_commitment=marker_commitment(plan.digest, disclosure_marker),
        )


def _persist(
    path: str | None, checkpoint: Checkpoint, known_secrets: frozenset[str] = frozenset()
) -> None:
    if path is not None:
        write_checkpoint_atomic(path, checkpoint, known_secrets=known_secrets)


def _replace_persisted_canary(value: Any, persisted: str, canary: str) -> Any:
    if isinstance(value, str):
        return value.replace(persisted, canary)
    if isinstance(value, dict):
        return {
            key: _replace_persisted_canary(item, persisted, canary)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_persisted_canary(item, persisted, canary) for item in value]
    return value


def _rehydrate_checkpoint(checkpoint: Checkpoint, persisted: str, canary: str) -> None:
    """Restore only this checkpoint's commitment-derived pseudonym in memory."""
    checkpoint.completed = _replace_persisted_canary(checkpoint.completed, persisted, canary)
    checkpoint.progress = _replace_persisted_canary(checkpoint.progress, persisted, canary)
    checkpoint.in_flight = _replace_persisted_canary(checkpoint.in_flight, persisted, canary)


def _send(case: PlannedCase, responder: Responder, canary: str) -> ExchangeOutcome:
    return responder(InjectionCase(case.family, case.template, rendered_prompt(case, canary)))


def _intent(case: PlannedCase, canary: str) -> dict[str, Any]:
    return {
        "case_id": case.case_id,
        "kind": case.kind,
        "family": case.family,
        "prompt": rendered_prompt(case, canary),
        "attempts": 0,
    }


def _reconcile_in_flight(
    checkpoint: Checkpoint,
    plan: Plan,
    plan_cases: dict[str, PlannedCase],
    canary: str,
    run_secrets: frozenset[str],
) -> None:
    """Turn a resumed in-flight attempt into one uncertain, unusable, spent trial.

    The attempt was physically issued (and already counted) before the crash; its
    outcome is unknown, so it is recorded fail-closed (never reissued, never
    re-counted) and fills exactly one of its case's trial slots.
    """
    inf = checkpoint.in_flight
    if inf is None:
        return
    if int(inf.get("attempts", 0)) == 0:
        raise CheckpointError("checkpoint has an unresolved attempt with no trusted ledger count")
    case = plan_cases.get(inf["case_id"])
    if case is not None:
        record = checkpoint.progress.setdefault(
            case.case_id,
            {"kind": case.kind, "family": case.family, "prompt": inf["prompt"], "trials": []},
        )
        record["trials"].append(
            _trial_record(
                plan,
                case,
                ExchangeOutcome(
                    body="", transport_ok=False, attempts=int(inf.get("attempts", 1))
                ),
                canary,
                checkpoint,
                run_secrets,
            )
        )
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
    physical_request_count: PhysicalCounter | None,
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
        # Persist intent before issuance, but claim no request until the trusted
        # controller/broker ledger proves that acquisition occurred.
        checkpoint.in_flight = _intent(case, canary)
        _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
        before = snapshot_ledger(physical_request_count)
        try:
            outcome = _send(case, responder, canary)
        except BaseException:
            try:
                consumed = ledger_delta(before, physical_request_count, remaining=remaining)
            except Exception:
                assert checkpoint.in_flight is not None
                checkpoint.in_flight["attempts"] = 0
                _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
                raise
            checkpoint.request_count += consumed
            assert checkpoint.in_flight is not None
            checkpoint.in_flight["attempts"] = consumed
            _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
            raise
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
        attempts = ledger_delta(before, physical_request_count, remaining=remaining)
        if attempts < 1 or attempts > remaining:
            assert checkpoint.in_flight is not None
            checkpoint.in_flight["attempts"] = 0
            _persist(checkpoint_path, checkpoint, frozenset(run_secrets))
            raise PlanError("trusted physical request ledger delta is invalid")
        checkpoint.request_count += attempts
        outcome = ExchangeOutcome(
            body=outcome.body,
            status=outcome.status,
            redirected=outcome.redirected,
            truncated=outcome.truncated,
            transport_ok=outcome.transport_ok,
            attempts=attempts,
            known_secrets=outcome.known_secrets,
            semantic=outcome.semantic,
        )
        checkpoint.in_flight = None
        outcomes.append(outcome)
        checkpoint.progress[case.case_id] = {
            "kind": case.kind,
            "family": case.family,
            "prompt": rendered_prompt(case, canary),
            "trials": [
                _trial_record(plan, case, o, canary, checkpoint, frozenset(run_secrets))
                for o in outcomes
            ],
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


def _record_from_finding(
    plan: Plan,
    case: PlannedCase,
    finding: InjectionFinding,
    *,
    canary: str,
    checkpoint: Checkpoint,
    run_secrets: frozenset[str],
) -> dict[str, Any]:
    return {
        "family": finding.family,
        "status": finding.status.value,
        "prompt": finding.prompt,
        "proof": finding.proof,
        "kind": case.kind,
        # Trial counts plus every persisted physical trial let a plan-bound load
        # re-derive the status through the shared evidence contract.
        "attack_trials": finding.attack_trials,
        "successes": finding.successes,
        "trials": [
            _trial_record(plan, case, outcome, canary, checkpoint, run_secrets)
            for outcome in finding.evidence
        ],
    }


def _trial_record(
    plan: Plan,
    case: PlannedCase,
    outcome: ExchangeOutcome,
    canary: str,
    checkpoint: Checkpoint,
    run_secrets: frozenset[str],
) -> dict[str, Any]:
    """Bind a canonicalized persistence view to this exact plan case.

    The body is scrubbed with the *complete* cumulative run secret set — the
    disclosure marker and every reflected secret, not merely this outcome's own
    ``known_secrets`` — and the run canary is replaced with its commitment-derived
    pseudonym, all BEFORE :func:`trial_to_dict` seals the commitment digest. The
    outer checkpoint/bundle scrub then finds nothing left to replace, so it is
    idempotent over the committed fields and cannot retroactively mutate (and thus
    self-invalidate) an already-sealed trial. A secret learned in a later case
    cannot appear in an earlier trial's committed body — it was not reflected when
    that body was recorded — so earlier commitments stay valid as the set grows.
    """
    persisted = evidence_canary(checkpoint.canary_commitment)
    secrets = frozenset(
        secret
        for secret in (run_secrets | outcome.known_secrets)
        if secret != canary
    )
    canonical = ExchangeOutcome(
        body=scrub_text(outcome.body.replace(canary, persisted), secrets),
        status=outcome.status,
        redirected=outcome.redirected,
        truncated=outcome.truncated,
        transport_ok=outcome.transport_ok,
        attempts=outcome.attempts,
        semantic=outcome.semantic,
    )
    identity = RunIdentity(
        plan.digest,
        checkpoint.canary_commitment,
        checkpoint.marker_commitment,
        persisted,
        None,
    )
    return trial_to_dict(
        canonical, plan=plan, case=case, canary=persisted, identity=identity
    )


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
