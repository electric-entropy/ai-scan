"""Phase B2 — typed stateful execution, identity binding, cleanup, crash-safe resume."""

from __future__ import annotations

import pytest

from ai_scan.injection import ExchangeOutcome, InjectionStatus
from ai_scan.orchestration.stateful import (
    Identity,
    StatefulError,
    StatefulStep,
    StateLedger,
    StepKind,
    run_stateful_case,
)

_BASE = "AISCAN-STATE01"


def _vulnerable():
    """A cross-identity-leaking synthetic target with a budgeted step responder."""
    store: dict[str, str | None] = {"value": None}
    calls = {"write": 0, "cleanup": 0, "steps": 0}

    def responder(step: StatefulStep) -> ExchangeOutcome:
        calls["steps"] += 1
        if step.kind is StepKind.WRITE:
            calls["write"] += 1
            store["value"] = step.canary
            return ExchangeOutcome(body="written")
        if step.kind is StepKind.CLEANUP:
            calls["cleanup"] += 1
            store["value"] = None
            return ExchangeOutcome(body="cleaned")
        # CONTROL_READ / READBACK reflect current state (leaks the writer's canary).
        return ExchangeOutcome(body=store["value"] or "")

    return responder, store, calls


def _run(responder, ledger=None, writer="alice", reader="bob"):
    return run_stateful_case(
        case_id="c1", writer=Identity(writer), reader=Identity(reader),
        base_canary=_BASE, responder=responder, ledger=ledger or StateLedger(),
    )


def test_duplicate_identities_rejected_before_side_effects() -> None:
    calls = {"n": 0}

    def responder(step: StatefulStep) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome("x")

    with pytest.raises(StatefulError):
        _run(responder, writer="same", reader="same")
    assert calls["n"] == 0  # no responder call ⇒ no side effect was issued


def test_typed_readback_and_cleanup_confirms() -> None:
    responder, _store, calls = _vulnerable()
    result = _run(responder)
    assert result.status is InjectionStatus.CONFIRMED
    ev = result.evidence
    assert ev.control_clean and ev.write_confirmed
    assert ev.readback_confirmed and ev.cleanup_confirmed
    assert ev.writer != ev.reader
    assert calls["cleanup"] == 1  # cleanup ran through the budgeted responder


def test_bare_canary_without_cleanup_cannot_confirm() -> None:
    # Read-back leaks the canary, but cleanup fails ⇒ no state-change corroboration
    # ⇒ a side-effecting case cannot confirm on the bare canary alone.
    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body="x", transport_ok=False)
        if step.kind is StepKind.WRITE:
            return ExchangeOutcome(body="written")
        if step.kind is StepKind.READBACK:
            return ExchangeOutcome(body=step.canary)
        return ExchangeOutcome(body="")  # clean control

    result = _run(responder)
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.evidence.cleanup_confirmed is False


def test_single_cycle_does_not_synthesize_repeatability() -> None:
    # A single physical write/read/cleanup cycle is ONE trial; it must not be
    # inflated to satisfy min_attack_trials. Under Reliable 3/2, one cycle cannot
    # confirm (the ordinary repeatability gate is not bypassed).
    responder, _store, _calls = _vulnerable()
    result = run_stateful_case(
        case_id="c1", writer=Identity("alice"), reader=Identity("bob"),
        base_canary=_BASE, responder=responder, ledger=StateLedger(),
        min_attack_trials=3, min_successes=2,
    )
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.evidence.readback_confirmed  # the leak was observed, but once


def test_no_cross_identity_leak_does_not_confirm() -> None:
    # A resistant target where the reader never sees the writer's canary.
    def responder(step: StatefulStep) -> ExchangeOutcome:
        if step.kind is StepKind.WRITE:
            return ExchangeOutcome(body="written")
        if step.kind is StepKind.CLEANUP:
            return ExchangeOutcome(body="cleaned")
        return ExchangeOutcome(body="only-my-own-state")  # no leak on read

    result = _run(responder)
    assert result.status is not InjectionStatus.CONFIRMED
    assert result.evidence.readback_confirmed is False


def test_cleanup_is_a_budgeted_responder_step() -> None:
    responder, _store, calls = _vulnerable()
    result = _run(responder)
    # control + write + readback + cleanup = four budgeted physical steps.
    assert result.physical_steps == 4
    assert calls["cleanup"] == 1


def test_crash_after_write_resumes_without_duplicate_write() -> None:
    responder, _store, calls = _vulnerable()
    ledger = StateLedger()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        out = responder(step)
        if step.kind is StepKind.READBACK:
            raise KeyboardInterrupt  # crash AFTER the write, during read-back
        return out

    with pytest.raises(KeyboardInterrupt):
        _run(crashing, ledger=ledger)
    assert calls["write"] == 1
    assert ledger.phase("c1") == "written"

    # Resume with the same write-ahead ledger: the write must NOT be re-issued.
    result = _run(responder, ledger=ledger)
    assert calls["write"] == 1  # no duplicate side effect
    assert result.evidence.write_confirmed
    assert result.status is InjectionStatus.CONFIRMED


def test_unusable_reconciliation_read_does_not_reissue_write() -> None:
    # Crash after the write reaches the target but before the ledger advances to
    # 'written'. On resume the reconciliation read is UNUSABLE ⇒ the write's fate
    # is unknown ⇒ we must NOT re-issue it (no duplicate side effect); fail closed.
    responder, _store, calls = _vulnerable()
    ledger = StateLedger()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        out = responder(step)
        if step.kind is StepKind.WRITE:
            raise KeyboardInterrupt  # crash after the write landed, before 'written'
        return out

    with pytest.raises(KeyboardInterrupt):
        _run(crashing, ledger=ledger)
    assert calls["write"] == 1
    assert ledger.phase("c1") == "writing"

    # Resume, but every reconciliation/read is unusable (target unreachable).
    def unusable(step: StatefulStep) -> ExchangeOutcome:
        return ExchangeOutcome(body="", transport_ok=False)

    result = _run(unusable, ledger=ledger)
    assert calls["write"] == 1  # the side effect was NOT re-issued
    assert result.status is InjectionStatus.INCONCLUSIVE
    assert ledger.phase("c1") == "writing"  # left unresolved for later reconciliation


def test_write_ahead_state_survives_process_crash(tmp_path) -> None:
    # The write-ahead state must be durable: a real process crash loses in-memory
    # state, so resume reloads it from disk and still avoids a duplicate write.
    import json

    responder, _store, calls = _vulnerable()
    ledger_path = tmp_path / "state.json"

    def persist_to_disk(ledger: StateLedger) -> None:
        ledger_path.write_text(json.dumps(ledger.to_dict()), encoding="utf-8")

    crash_ledger = StateLedger()

    def crashing(step: StatefulStep) -> ExchangeOutcome:
        out = responder(step)
        if step.kind is StepKind.WRITE:
            # Side effect issued and write-ahead persisted; then the process dies.
            raise KeyboardInterrupt
        return out

    with pytest.raises(KeyboardInterrupt):
        run_stateful_case(
            case_id="c1", writer=Identity("alice"), reader=Identity("bob"),
            base_canary=_BASE, responder=crashing, ledger=crash_ledger,
            persist=lambda: persist_to_disk(crash_ledger),
        )
    assert calls["write"] == 1
    assert ledger_path.exists()

    # Simulate a fresh process: reload the ledger from disk (in-memory state gone).
    reloaded = StateLedger.from_dict(json.loads(ledger_path.read_text(encoding="utf-8")))
    # The write-ahead intent persisted, but the crash left it in the *uncertain*
    # 'writing' phase — resume must reconcile idempotently, not blindly re-write.
    assert reloaded.phase("c1") == "writing"
    run_stateful_case(
        case_id="c1", writer=Identity("alice"), reader=Identity("bob"),
        base_canary=_BASE, responder=responder, ledger=reloaded,
    )
    assert calls["write"] == 1  # durable write-ahead + reconciliation ⇒ no duplicate
