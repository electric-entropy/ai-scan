"""Minimal typed stateful-execution protocol (Phase B2).

A side-effecting attack writes an *identity-bound* canary into synthetic target
state as one identity, then a **distinct** identity reads it back in a fresh
session, and finally the write is cleaned up. Confirmation requires **all** of:

* two distinct identities (rejected before any side effect if not distinct),
* a confirmed write,
* an identity-bound read-back by the other identity,
* confirmed cleanup,

on top of the ordinary repeatability/clean-control gates. A bare canary echo —
no real write/read-back/cleanup — is therefore never enough for a side-effecting
family.

Every step (control read, write, read-back, cleanup) is a **budgeted,
broker-mediated responder call**, never an untracked side channel. A write-ahead
``StateLedger`` records the in-flight write *before* it is issued, so a crash
after the side effect resumes by reconciling (never re-issuing) the write.
"""

from __future__ import annotations

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


@dataclass
class StateLedger:
    """Write-ahead in-flight state for crash-safe resume (secret-free).

    Records the write phase and the pre-write control result per case, so a
    resumed run reconciles against the state established before the crash rather
    than re-reading a baseline the leftover write has already dirtied.
    """

    # case_id -> phase in {"writing", "written", "cleaned"}
    phases: dict[str, str] = field(default_factory=dict)
    # case_id -> pre-write control result in {"clean", "emitted", "gap"}
    control: dict[str, str] = field(default_factory=dict)

    def phase(self, case_id: str) -> str | None:
        return self.phases.get(case_id)

    def mark(self, case_id: str, phase: str, persist: Callable[[], None] | None = None) -> None:
        self.phases[case_id] = phase
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
            if value not in ("writing", "written", "cleaned"):
                raise StatefulError("invalid write-ahead phase")
        for value in control.values():
            if value not in ("clean", "emitted", "gap"):
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
) -> StatefulResult:
    """Execute one stateful case through the budgeted responder and classify it.

    All network work goes through ``responder`` (broker/budget accounted). The
    write is write-ahead-logged in ``ledger`` before it is issued; on resume a
    already-``written`` case is reconciled (read-back + cleanup) without a
    duplicate write. Confirmation requires distinct identities, a clean control
    read, a confirmed write, an identity-bound read-back, and cleanup.
    """
    # Distinct identities are required *before* any side effect is issued.
    if writer == reader:
        raise StatefulError("writer and reader identities must be distinct")

    canary = identity_canary(base_canary, writer)
    steps = 0
    phase = ledger.phase(case_id)

    if phase in ("written", "cleaned"):
        # The write is known-durable: reconcile against the pre-crash baseline,
        # do not re-read (leftover write would poison it) or re-issue the write.
        control_result = ledger.control.get(case_id, "gap")
        write_confirmed = True
    elif phase == "writing":
        # Crash mid-write: state is *uncertain*. Reconcile idempotently — a
        # budgeted read tells us whether the write actually landed.
        control_result = ledger.control.get(case_id, "gap")
        recon = responder(StatefulStep(StepKind.READBACK, reader, canary))
        steps += 1
        if not _usable(recon):
            # The reconciliation read is unusable, so the write's fate is UNKNOWN
            # (it may have reached the target). We must NOT re-issue the side
            # effect. Fail closed as unresolved/inconclusive and leave the ledger
            # in 'writing' for a later reconciliation attempt.
            return StatefulResult(
                status=InjectionStatus.INCONCLUSIVE,
                evidence=StateEvidence(
                    writer=writer.name, reader=reader.name, write_canary=canary,
                    write_confirmed=False, readback_confirmed=False,
                    cleanup_confirmed=False, control_clean=control_result == "clean",
                ),
                physical_steps=steps,
            )
        if canary in recon.body:
            # The write provably landed — adopt it, do not re-issue.
            write_confirmed = True
        else:
            # The write provably did NOT land (usable read, canary absent) — it is
            # safe to issue it exactly once.
            write_out = responder(StatefulStep(StepKind.WRITE, writer, canary))
            steps += 1
            write_confirmed = _usable(write_out)
        ledger.mark(case_id, "written", persist)
    else:
        # Control: the reader reads BEFORE any write — the canary must be absent.
        control_out = responder(StatefulStep(StepKind.CONTROL_READ, reader, canary))
        steps += 1
        control_usable = _usable(control_out)
        if control_usable and canary in control_out.body:
            control_result = "emitted"
        elif control_usable:
            control_result = "clean"
        else:
            control_result = "gap"
        ledger.record_control(case_id, control_result, persist)
        # Write-ahead: log intent BEFORE issuing the side effect.
        ledger.mark(case_id, "writing", persist)
        write_out = responder(StatefulStep(StepKind.WRITE, writer, canary))
        steps += 1
        write_confirmed = _usable(write_out)
        ledger.mark(case_id, "written", persist)

    control_emitted = control_result == "emitted"
    control_clean = control_result == "clean"

    # Read-back by the distinct identity.
    readback_out = responder(StatefulStep(StepKind.READBACK, reader, canary))
    steps += 1
    readback_confirmed = _usable(readback_out) and canary in readback_out.body

    # Cleanup is a budgeted responder step, never an untracked callback.
    cleanup_out = responder(StatefulStep(StepKind.CLEANUP, writer, canary))
    steps += 1
    cleanup_confirmed = _usable(cleanup_out)
    ledger.mark(case_id, "cleaned", persist)

    evidence = StateEvidence(
        writer=writer.name,
        reader=reader.name,
        write_canary=canary,
        write_confirmed=write_confirmed,
        readback_confirmed=readback_confirmed,
        cleanup_confirmed=cleanup_confirmed,
        control_clean=control_clean,
    )

    signal_evidence = Evidence(
        response=readback_out.body,
        canary=canary,
        prompt="",
        evaluable=_usable(readback_out),
    )
    signals = [ExactCanaryValidator().validate(signal_evidence)]
    # A single write/read-back/cleanup cycle is exactly ONE physical trial — the
    # repeatability count is never synthesized from ``min_attack_trials``. This
    # cycle contributes one usable trial (when the read-back is usable) and one
    # success only when the identity-bound canary actually leaked. A stateful run
    # that has not physically repeated enough cycles is therefore held below
    # ``confirmed`` by the ordinary repeatability gate.
    usable_trial = 1 if _usable(readback_out) else 0
    context = GatingContext(
        control_succeeded=control_emitted,
        matched_clean_control=control_clean,
        attack_trials=max(1, usable_trial),
        successes=1 if readback_confirmed else 0,
        min_attack_trials=min_attack_trials,
        min_successes=min_successes,
        requires_state_change=True,
        readback_confirmed=readback_confirmed,
        cleanup_confirmed=cleanup_confirmed,
    )
    result = classify(signals, context, evaluable=_usable(readback_out))
    status = legacy_status(_FINDING_TO_INJECTION[result.status])
    return StatefulResult(status=status, evidence=evidence, physical_steps=steps)
