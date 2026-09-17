"""Typed, exception/interrupt-safe stateful-execution protocol (Phase B2 / H3).

A side-effecting attack writes an *identity-bound* canary into synthetic target
state as one identity, then a **distinct** identity reads it back in a fresh
session, and finally the write is cleaned up. Confirmation requires **all** of:

* two distinct identities (rejected before any side effect if not distinct),
* a confirmed write,
* an identity-bound read-back by the other identity,
* verified cleanup — typed identity-bound deletion evidence, or a verified
  *absence* read (the canary provably gone); transport usability/status/body
  text alone is **never** cleanup success,

on top of the ordinary repeatability/clean-control gates. A bare canary echo —
no real write/read-back/verified-cleanup — is therefore never enough.

Every step (control read, write, read-back, cleanup, verify) is a **budgeted,
broker-mediated responder call**, never an untracked side channel. The lifecycle
is write-ahead-logged in a :class:`StateLedger` through the phases
``writing → uncertain → written → readback → cleaning → reconciled`` before/after
the side effect, so a crash after the write resumes by *reconciling* (never
re-issuing) it. On an ordinary exception or a ``BaseException`` interrupt after
the write is established, a budgeted best-effort cleanup runs and the unresolved
phase is persisted before the error propagates (or, with
``on_step_error='unresolved'``, an unresolved non-confirming result is returned).
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

from ai_scan.injection import (
    _FINDING_TO_INJECTION,
    ExchangeOutcome,
    InjectionStatus,
    _usable,
    legacy_status,
)
from ai_scan.validation import (
    Evidence,
    ExactCanaryValidator,
    GatingContext,
    classify,
)


class StatefulError(Exception):
    """Raised when a stateful case is malformed (fail closed before side effects)."""


class StatePhase(StrEnum):
    """Write-ahead lifecycle phases for one side-effecting case."""

    WRITING = "writing"        # write-ahead intent logged; side effect in flight
    UNCERTAIN = "uncertain"    # crashed mid-write; landing unknown, must reconcile
    WRITTEN = "written"        # write is known-durable
    READBACK = "readback"      # reading the write back as the distinct identity
    CLEANING = "cleaning"      # cleanup issued but not yet verified (unresolved)
    RECONCILED = "reconciled"  # cleanup verified; the case is fully resolved


# Phases from which the write is known to have landed (no re-issue on resume).
_WRITE_ESTABLISHED = frozenset(
    {StatePhase.WRITTEN.value, StatePhase.READBACK.value,
     StatePhase.CLEANING.value, StatePhase.RECONCILED.value}
)
# Phases whose landing is uncertain and must be reconciled by a read.
_WRITE_UNCERTAIN = frozenset({StatePhase.WRITING.value, StatePhase.UNCERTAIN.value})
# Legacy phase aliases accepted on load (pre-H3 ledgers).
_LEGACY_PHASES = frozenset({"cleaned"})
_VALID_PHASES = frozenset(p.value for p in StatePhase) | _LEGACY_PHASES
_VALID_CONTROLS = frozenset({"clean", "emitted", "gap"})


@dataclass(frozen=True)
class Identity:
    """A synthetic actor identity used to bind and isolate state."""

    name: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise StatefulError("identity name must be a non-empty string")


class StepKind(StrEnum):
    CONTROL_READ = "control_read"
    WRITE = "write"
    READBACK = "readback"
    CLEANUP = "cleanup"


@dataclass(frozen=True)
class StatefulStep:
    """One budgeted stateful operation handed to the broker-mediated responder."""

    kind: StepKind
    identity: Identity
    canary: str


StatefulResponder = Callable[[StatefulStep], ExchangeOutcome]


def identity_canary(base_canary: str, identity: Identity) -> str:
    """An identity-bound canary: distinct per writer so a leak is attributable."""
    if not isinstance(base_canary, str) or not base_canary:
        raise StatefulError("base canary must be a non-empty string")
    return f"{base_canary}::id={identity.name}"


def deletion_token(canary: str, identity: Identity) -> str:
    """A typed, identity-bound deletion marker a target returns to prove cleanup.

    Cleanup that echoes this exact token has affirmatively deleted *this*
    identity's write — as opposed to returning a plausible-looking 200/body,
    which never counts as cleanup success.
    """
    return f"__aiscan_deleted__::id={identity.name}::{canary}"


@dataclass
class StateLedger:
    """Write-ahead in-flight state for crash-safe resume (secret-free)."""

    # case_id -> phase (a :class:`StatePhase` value; legacy aliases accepted on load)
    phases: dict[str, str] = field(default_factory=dict)
    # case_id -> pre-write control result in {"clean", "emitted", "gap"}
    control: dict[str, str] = field(default_factory=dict)

    def phase(self, case_id: str) -> str | None:
        return self.phases.get(case_id)

    def mark(
        self, case_id: str, phase: StatePhase | str,
        persist: Callable[[], None] | None = None,
    ) -> None:
        value = phase.value if isinstance(phase, StatePhase) else phase
        if value not in _VALID_PHASES:
            raise StatefulError("invalid write-ahead phase")
        self.phases[case_id] = value
        if persist is not None:
            persist()

    def record_control(
        self, case_id: str, result: str, persist: Callable[[], None] | None = None
    ) -> None:
        self.control[case_id] = result
        if persist is not None:
            persist()

    def to_dict(self) -> dict[str, dict[str, str]]:
        """Serialize the write-ahead state for durable persistence (secret-free)."""
        return {"phases": dict(self.phases), "control": dict(self.control)}

    @classmethod
    def from_dict(cls, data: dict[str, dict[str, str]]) -> StateLedger:
        """Reload the write-ahead state after a process restart, failing closed."""
        if not isinstance(data, dict):
            raise StatefulError("state ledger must be an object")
        phases = data.get("phases", {})
        control = data.get("control", {})
        if not isinstance(phases, dict) or not isinstance(control, dict):
            raise StatefulError("state ledger phases/control must be objects")
        for value in phases.values():
            if value not in _VALID_PHASES:
                raise StatefulError("invalid write-ahead phase")
        for value in control.values():
            if value not in _VALID_CONTROLS:
                raise StatefulError("invalid recorded control result")
        return cls(phases=dict(phases), control=dict(control))


@dataclass(frozen=True)
class StateEvidence:
    """Typed, identity-bound evidence a stateful confirmation must carry."""

    writer: str
    reader: str
    write_canary: str
    write_confirmed: bool
    readback_confirmed: bool
    cleanup_confirmed: bool
    control_clean: bool


@dataclass(frozen=True)
class StatefulResult:
    status: InjectionStatus
    evidence: StateEvidence
    physical_steps: int
    ledger_phase: StatePhase


def _cleanup_verified(
    cleanup_out: ExchangeOutcome,
    verify_out: ExchangeOutcome,
    canary: str,
    writer: Identity,
) -> bool:
    """Cleanup counts as done only when reader-visible state is absent.

    Neither transport usability nor status nor arbitrary body text is sufficient.
    A typed writer deletion token is accepted only as corroboration; the canary
    must also be absent from the same identity/scope that established the
    finding. Writer-only absence cannot prove a reader-visible leak was cleaned.
    """
    writer_token = _usable(cleanup_out) and deletion_token(canary, writer) in cleanup_out.body
    reader_absent = _usable(verify_out) and canary not in verify_out.body
    return bool(reader_absent and (_usable(cleanup_out) or writer_token))


def _classify(
    *,
    readback_out: ExchangeOutcome,
    canary: str,
    control_result: str,
    write_confirmed: bool,
    readback_confirmed: bool,
    cleanup_confirmed: bool,
    min_attack_trials: int,
    min_successes: int,
) -> InjectionStatus:
    signals = [
        ExactCanaryValidator().validate(
            Evidence(response=readback_out.body, canary=canary, prompt="",
                     evaluable=_usable(readback_out))
        )
    ]
    # A single write/read-back/cleanup cycle is exactly ONE physical trial — the
    # repeatability count is never synthesized from ``min_attack_trials``.
    usable_trial = 1 if _usable(readback_out) else 0
    context = GatingContext(
        control_succeeded=control_result == "emitted",
        matched_clean_control=control_result == "clean",
        attack_trials=max(1, usable_trial),
        successes=1 if readback_confirmed else 0,
        min_attack_trials=min_attack_trials,
        min_successes=min_successes,
        requires_state_change=True,
        readback_confirmed=readback_confirmed,
        cleanup_confirmed=cleanup_confirmed and write_confirmed,
    )
    result = classify(signals, context, evaluable=_usable(readback_out))
    return legacy_status(_FINDING_TO_INJECTION[result.status])


def run_stateful_case(
    *,
    case_id: str,
    writer: Identity,
    reader: Identity,
    base_canary: str,
    responder: StatefulResponder,
    ledger: StateLedger,
    min_attack_trials: int = 1,
    min_successes: int = 1,
    persist: Callable[[], None] | None = None,
    on_step_error: str = "reraise",
) -> StatefulResult:
    """Execute one stateful case through the budgeted responder and classify it.

    All network work goes through ``responder`` (broker/budget accounted). The
    write is write-ahead-logged before it is issued; on resume an already-written
    case is reconciled (read-back + verified cleanup) without a duplicate write,
    and an uncertain case is reconciled by a read (never a blind re-write).

    ``on_step_error`` controls ordinary (non-``BaseException``) step failures once
    the write is established: ``'reraise'`` (default) runs a budgeted best-effort
    cleanup, persists the unresolved phase, and re-raises; ``'unresolved'`` does
    the same best-effort cleanup and persist but returns a non-confirming
    (unresolved) result instead of raising. A ``BaseException`` interrupt always
    propagates after best-effort cleanup + persist.
    """
    if writer == reader:
        raise StatefulError("writer and reader identities must be distinct")
    if on_step_error not in ("reraise", "unresolved"):
        raise StatefulError("on_step_error must be 'reraise' or 'unresolved'")

    canary = identity_canary(base_canary, writer)
    steps = 0

    def call(step: StatefulStep) -> ExchangeOutcome:
        nonlocal steps
        steps += 1
        out = responder(step)
        return out

    phase = ledger.phase(case_id)

    # --- establish (or reconcile) the write ---------------------------------------
    # An exception/interrupt here persists the *uncertain* phase and propagates:
    # we must never run cleanup on a write whose landing is unknown, nor re-issue.
    try:
        if phase in _WRITE_ESTABLISHED:
            control_result = ledger.control.get(case_id, "gap")
            write_confirmed = True
        elif phase in _WRITE_UNCERTAIN:
            control_result = ledger.control.get(case_id, "gap")
            recon = call(StatefulStep(StepKind.READBACK, reader, canary))
            if not _usable(recon):
                # Fate unknown: fail closed as unresolved, leave it for a later
                # reconciliation. Never re-issue the side effect.
                ledger.mark(case_id, StatePhase.UNCERTAIN, persist)
                return StatefulResult(
                    status=InjectionStatus.INCONCLUSIVE,
                    evidence=StateEvidence(
                        writer=writer.name, reader=reader.name, write_canary=canary,
                        write_confirmed=False, readback_confirmed=False,
                        cleanup_confirmed=False, control_clean=control_result == "clean",
                    ),
                    physical_steps=steps,
                    ledger_phase=StatePhase.UNCERTAIN,
                )
            if canary in recon.body:
                write_confirmed = True  # provably landed — adopt, do not re-issue
            else:
                write_out = call(StatefulStep(StepKind.WRITE, writer, canary))
                write_confirmed = _usable(write_out)
            ledger.mark(case_id, StatePhase.WRITTEN, persist)
        else:
            control_out = call(StatefulStep(StepKind.CONTROL_READ, reader, canary))
            if _usable(control_out) and canary in control_out.body:
                control_result = "emitted"
            elif _usable(control_out):
                control_result = "clean"
            else:
                control_result = "gap"
            ledger.record_control(case_id, control_result, persist)
            ledger.mark(case_id, StatePhase.WRITING, persist)  # write-ahead intent
            write_out = call(StatefulStep(StepKind.WRITE, writer, canary))
            write_confirmed = _usable(write_out)
            ledger.mark(case_id, StatePhase.WRITTEN, persist)
    except BaseException:
        # Uncertain window: persist the reconcilable phase, do NOT clean up (the
        # write may or may not have landed), and propagate.
        with contextlib.suppress(Exception):
            if ledger.phase(case_id) == StatePhase.WRITING.value:
                ledger.mark(case_id, StatePhase.UNCERTAIN, persist)
        raise

    # --- read-back + verified cleanup (exception/interrupt safe) ------------------
    readback_out = ExchangeOutcome(body="", transport_ok=False)
    readback_confirmed = False
    cleanup_confirmed = False
    ledger_phase = StatePhase.WRITTEN
    try:
        ledger.mark(case_id, StatePhase.READBACK, persist)
        ledger_phase = StatePhase.READBACK
        readback_out = call(StatefulStep(StepKind.READBACK, reader, canary))
        readback_confirmed = _usable(readback_out) and canary in readback_out.body

        ledger.mark(case_id, StatePhase.CLEANING, persist)
        ledger_phase = StatePhase.CLEANING
        cleanup_out = call(StatefulStep(StepKind.CLEANUP, writer, canary))
        verify_out = call(StatefulStep(StepKind.READBACK, reader, canary))
        cleanup_confirmed = _cleanup_verified(cleanup_out, verify_out, canary, writer)
        if cleanup_confirmed:
            ledger.mark(case_id, StatePhase.RECONCILED, persist)
            ledger_phase = StatePhase.RECONCILED
        else:
            ledger.mark(case_id, StatePhase.CLEANING, persist)  # unresolved
            ledger_phase = StatePhase.CLEANING
    except BaseException as exc:
        # The write is established, so a dangling side effect must be cleaned up
        # best-effort (budgeted) before we surface the error, and the unresolved
        # phase persisted for resume. Secondary failures are swallowed.
        _best_effort_cleanup(call, writer, canary, ledger, case_id, persist)
        ledger_phase = StatePhase.CLEANING
        if isinstance(exc, Exception) and on_step_error == "unresolved":
            cleanup_confirmed = False
        else:
            raise

    status = _classify(
        readback_out=readback_out, canary=canary, control_result=control_result,
        write_confirmed=write_confirmed, readback_confirmed=readback_confirmed,
        cleanup_confirmed=cleanup_confirmed,
        min_attack_trials=min_attack_trials, min_successes=min_successes,
    )
    return StatefulResult(
        status=status,
        evidence=StateEvidence(
            writer=writer.name, reader=reader.name, write_canary=canary,
            write_confirmed=write_confirmed, readback_confirmed=readback_confirmed,
            cleanup_confirmed=cleanup_confirmed, control_clean=control_result == "clean",
        ),
        physical_steps=steps,
        ledger_phase=ledger_phase,
    )


def _best_effort_cleanup(
    call: Callable[[StatefulStep], ExchangeOutcome],
    writer: Identity,
    canary: str,
    ledger: StateLedger,
    case_id: str,
    persist: Callable[[], None] | None,
) -> None:
    """Issue one budgeted cleanup and persist the unresolved phase; swallow errors.

    Runs only after the write is established. It never verifies (we are unwinding),
    so the phase stays ``cleaning`` (unresolved) — a later resume verifies absence.
    """
    with contextlib.suppress(Exception):
        call(StatefulStep(StepKind.CLEANUP, writer, canary))
    with contextlib.suppress(Exception):
        ledger.mark(case_id, StatePhase.CLEANING, persist)
