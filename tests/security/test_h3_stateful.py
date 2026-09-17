"""Step 1C / Astra H3 — stateful lifecycle safety and verified cleanup.

A side-effecting case is exception/interrupt safe: the write is write-ahead
logged before it is issued, the lifecycle moves through
``writing → uncertain → written → readback → cleaning → reconciled``, and an
ordinary exception or a ``BaseException`` interrupt triggers a budgeted,
best-effort reconciliation/cleanup before the error propagates, leaving the
ledger in a resumable state. Cleanup counts as done ONLY with typed
identity-bound deletion evidence or a verified absence read — transport
usability, status, or arbitrary body text never mark it cleaned or confirm.
"""

from __future__ import annotations

import json

import pytest

from ai_scan.injection import ExchangeOutcome, InjectionStatus
from ai_scan.orchestration.stateful import (
    Identity,
    StatefulError,
    StatefulStep,
    StateLedger,
    StatePhase,
    StepKind,
    deletion_token,
    run_stateful_case,
)

_BASE = "AISCAN-H3STATE01"


def _run(responder, ledger=None, writer="alice", reader="bob", **kw):  # type: ignore[no-untyped-def]
    return run_stateful_case(
        case_id="c1", writer=Identity(writer), reader=Identity(reader),
        base_canary=_BASE, responder=responder, ledger=ledger or StateLedger(), **kw,
    )


def _leaky_store():  # type: ignore[no-untyped-def]
    """A cross-identity-leaking target that clears state only on real cleanup."""
    store: dict[str, str | None] = {"value": None}
    calls: dict[str, int] = {"write": 0, "cleanup": 0, "readback": 0, "control_read": 0}

    def responder(step: StatefulStep) -> ExchangeOutcome:
        calls[step.kind.value] += 1
        if step.kind is StepKind.WRITE:
            store["value"] = step.canary
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.CLEANUP:
            store["value"] = None
            return ExchangeOutcome(body=deletion_token(step.canary, step.identity))
        return ExchangeOutcome(body=store["value"] or "")

    return responder, store, calls


# --- duplicate identities & write-ahead --------------------------------------------


def test_duplicate_identities_rejected_before_any_responder_call() -> None:
    calls = {"n": 0}

    def responder(step: StatefulStep) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome("x")

    with pytest.raises(StatefulError):
        _run(responder, writer="dup", reader="dup")
    assert calls["n"] == 0


def test_write_ahead_intent_is_persisted_before_the_write_is_issued() -> None:
    responder, _store, _calls = _leaky_store()
    order: list[str] = []
    ledger = StateLedger()

    def tracking(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.WRITE:
            # The write-ahead intent must already be durable before the side effect.
            order.append(f"phase={ledger.phase('c1')}")
        order.append(step.kind.value)
        return responder(step)

    _run(tracking, ledger=ledger)
    assert "phase=writing" in order
    assert order.index("phase=writing") < order.index("write")


# --- verified cleanup contract -----------------------------------------------------


def test_typed_deletion_evidence_confirms() -> None:
    responder, _store, calls = _leaky_store()
    result = _run(responder)
    assert result.status is InjectionStatus.CONFIRMED
    assert result.evidence.cleanup_confirmed
    assert calls["cleanup"] == 1
    assert result.ledger_phase is StatePhase.RECONCILED


def test_verified_absence_read_confirms_cleanup() -> None:
    store: dict[str, str | None] = {"value": None}

    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.WRITE:
            store["value"] = step.canary
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.CLEANUP:
            store["value"] = None  # cleared, but returns no typed token
            return ExchangeOutcome(body="done")
        return ExchangeOutcome(body=store["value"] or "")

    result = _run(responder)
    assert result.status is InjectionStatus.CONFIRMED
    assert result.evidence.cleanup_confirmed  # confirmed via verified-absence read


def test_reader_visible_cleanup_must_be_verified_through_reader_identity() -> None:
    # Regression for H3: cleanup cleared only the writer view, then a writer-only
    # absence read falsely marked the reader-visible leak as cleaned/reconciled.
    store: dict[str, str | None] = {"writer_view": None, "reader_leak": None}
    calls: list[tuple[str, str]] = []

    def responder(step: StatefulStep) -> ExchangeOutcome:
        calls.append((step.kind.value, step.identity.name))
        if step.kind is StepKind.CONTROL_READ:
            return ExchangeOutcome(body="")
        if step.kind is StepKind.WRITE:
            store["writer_view"] = step.canary
            store["reader_leak"] = step.canary
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.READBACK:
            key = "reader_leak" if step.identity.name == "bob" else "writer_view"
            return ExchangeOutcome(body=store[key] or "")
        if step.kind is StepKind.CLEANUP:
            store["writer_view"] = None
            return ExchangeOutcome(body="cleanup ok")
        raise AssertionError(step)

    result = _run(responder)

    assert result.status is not InjectionStatus.CONFIRMED
    assert result.evidence.cleanup_confirmed is False
    assert result.ledger_phase is StatePhase.CLEANING
    assert store["reader_leak"] == result.evidence.write_canary
    assert (StepKind.READBACK.value, "bob") in calls


def test_reader_absence_positive_control_confirms_cleanup() -> None:
    store: dict[str, str | None] = {"writer_view": None, "reader_leak": None}
    calls: list[tuple[str, str]] = []

    def responder(step: StatefulStep) -> ExchangeOutcome:
        calls.append((step.kind.value, step.identity.name))
        if step.kind is StepKind.CONTROL_READ:
            return ExchangeOutcome(body="")
        if step.kind is StepKind.WRITE:
            store["writer_view"] = step.canary
            store["reader_leak"] = step.canary
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.CLEANUP:
            store["writer_view"] = None
            store["reader_leak"] = None
            return ExchangeOutcome(body="cleanup ok")
        if step.kind is StepKind.READBACK:
            key = "reader_leak" if step.identity.name == "bob" else "writer_view"
            return ExchangeOutcome(body=store[key] or "")
        raise AssertionError(step)

    result = _run(responder)

    assert result.status is InjectionStatus.CONFIRMED
    assert result.evidence.cleanup_confirmed is True
    assert result.ledger_phase is StatePhase.RECONCILED
    assert calls.count((StepKind.READBACK.value, "bob")) == 2


def test_transport_ok_cleanup_without_absence_is_not_cleaned() -> None:
    # Cleanup returns 200/usable with plausible text but the state STILL leaks:
    # usability/text alone must never mark cleanup done or confirm.
    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.WRITE:
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body="deleted successfully", status=200)
        return ExchangeOutcome(body=step.canary)  # still present on every read

    result = _run(responder)
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.evidence.cleanup_confirmed is False
    assert result.ledger_phase is StatePhase.CLEANING  # unresolved, resumable


def test_noop_cleanup_is_not_cleaned() -> None:
    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body="ok")  # no-op: state unchanged
        if step.kind is StepKind.WRITE:
            return ExchangeOutcome(body="ok")
        return ExchangeOutcome(body=step.canary)

    result = _run(responder)
    assert result.evidence.cleanup_confirmed is False
    assert result.status is not InjectionStatus.CONFIRMED


def test_unusable_cleanup_is_not_cleaned() -> None:
    responder, _store, _calls = _leaky_store()

    def failing(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body="", transport_ok=False)
        return responder(step)

    result = _run(failing)
    assert result.evidence.cleanup_confirmed is False
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.ledger_phase is StatePhase.CLEANING


def test_forged_deletion_token_for_other_identity_is_rejected() -> None:
    # A deletion token bound to a DIFFERENT identity must not confirm cleanup.
    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.WRITE:
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body=deletion_token(step.canary, Identity("mallory")))
        return ExchangeOutcome(body=step.canary)  # state still leaks

    result = _run(responder)
    assert result.evidence.cleanup_confirmed is False


def test_writer_token_alone_cannot_prove_reader_visible_cleanup() -> None:
    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.WRITE:
            return ExchangeOutcome(body="ok")
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body=deletion_token(step.canary, step.identity))
        return ExchangeOutcome(body=step.canary)

    result = _run(responder)
    assert result.evidence.cleanup_confirmed is False
    assert result.status is not InjectionStatus.CONFIRMED


def test_reader_cleanup_verification_exception_leaves_unresolved() -> None:
    responder, _store, calls = _leaky_store()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.READBACK and calls["readback"] == 1:
            calls["readback"] += 1
            raise RuntimeError("reader verify failed")
        return responder(step)

    result = _run(crashing, on_step_error="unresolved")
    assert result.evidence.cleanup_confirmed is False
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.ledger_phase is StatePhase.CLEANING


def test_cleanup_and_reader_verification_are_both_physical_steps() -> None:
    responder, _store, _calls = _leaky_store()
    result = _run(responder)
    assert result.physical_steps == 5


def test_exhausted_cleanup_budget_does_not_confirm() -> None:
    responder, _store, _calls = _leaky_store()

    def budgeted(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.CLEANUP:
            raise _BudgetExhausted
        return responder(step)

    result = _run(budgeted, on_step_error="unresolved")
    assert result.evidence.cleanup_confirmed is False
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.ledger_phase is StatePhase.CLEANING


class _BudgetExhausted(Exception):
    pass


# --- exception / interrupt safety --------------------------------------------------


@pytest.mark.parametrize("exc", [RuntimeError, KeyboardInterrupt])
def test_exception_during_readback_runs_budgeted_cleanup_then_reraises(exc) -> None:
    responder, store, calls = _leaky_store()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.READBACK and calls["readback"] == 0:
            calls["readback"] += 1
            raise exc
        return responder(step)

    with pytest.raises(exc):
        _run(crashing)
    # A budgeted best-effort cleanup ran before the error propagated, so the
    # synthetic side effect was not left dangling.
    assert calls["cleanup"] == 1
    assert store["value"] is None


def test_write_ahead_survives_process_crash_and_reconciles_without_reissue(tmp_path) -> None:
    responder, _store, calls = _leaky_store()
    path = tmp_path / "state.json"

    def persist(ledger: StateLedger) -> None:
        path.write_text(json.dumps(ledger.to_dict()), encoding="utf-8")

    crash = StateLedger()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        out = responder(step)
        if step.kind is StepKind.WRITE:
            raise KeyboardInterrupt  # after the write landed, before it is durable
        return out

    with pytest.raises(KeyboardInterrupt):
        run_stateful_case(
            case_id="c1", writer=Identity("alice"), reader=Identity("bob"),
            base_canary=_BASE, responder=crashing, ledger=crash,
            persist=lambda: persist(crash), on_step_error="unresolved",
        )
    assert calls["write"] == 1
    reloaded = StateLedger.from_dict(json.loads(path.read_text(encoding="utf-8")))
    assert reloaded.phase("c1") in (StatePhase.WRITING.value, StatePhase.UNCERTAIN.value)

    # Resume: reconciliation read shows the write landed → adopt, never re-issue.
    result = run_stateful_case(
        case_id="c1", writer=Identity("alice"), reader=Identity("bob"),
        base_canary=_BASE, responder=responder, ledger=reloaded,
    )
    assert calls["write"] == 1
    assert result.status is InjectionStatus.CONFIRMED


def test_uncertain_reconciliation_read_never_reissues_write() -> None:
    responder, _store, calls = _leaky_store()
    ledger = StateLedger()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        out = responder(step)
        if step.kind is StepKind.WRITE:
            raise KeyboardInterrupt
        return out

    with pytest.raises(KeyboardInterrupt):
        _run(crashing, ledger=ledger, on_step_error="unresolved")
    assert calls["write"] == 1

    def unusable(step: StatefulStep) -> ExchangeOutcome:
        return ExchangeOutcome(body="", transport_ok=False)

    result = _run(unusable, ledger=ledger)
    assert calls["write"] == 1
    assert result.status is InjectionStatus.INCONCLUSIVE
    assert ledger.phase("c1") == StatePhase.UNCERTAIN.value


def test_persistence_fault_propagates_and_does_not_falsely_confirm() -> None:
    responder, _store, _calls = _leaky_store()

    def persist() -> None:
        raise OSError("disk full")

    with pytest.raises(OSError):
        _run(responder, persist=persist)


# --- ledger phase roundtrip --------------------------------------------------------


def test_state_ledger_roundtrips_all_phases() -> None:
    ledger = StateLedger()
    for i, phase in enumerate(StatePhase):
        ledger.mark(f"c{i}", phase.value)
        ledger.record_control(f"c{i}", "clean")
    restored = StateLedger.from_dict(json.loads(json.dumps(ledger.to_dict())))
    for i, phase in enumerate(StatePhase):
        assert restored.phase(f"c{i}") == phase.value


def test_state_ledger_rejects_unknown_phase() -> None:
    with pytest.raises(StatefulError):
        StateLedger.from_dict({"phases": {"c1": "teleported"}, "control": {}})
