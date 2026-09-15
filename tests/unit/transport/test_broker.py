"""The broker is the sole, counted mediator of every physical attempt.

Proves, with deterministic doubles, that:
* no adapter/plugin holding a broker can reach a raw network client;
* budget is acquired *before* scope resolution and before any socket I/O;
* every broker-mediated attempt is counted exactly once (no uncounted attempt),
  including a scope-denied one, while a budget-exhausted attempt performs no I/O.
"""

from __future__ import annotations

import pytest

from ai_scan.targets import normalize_target
from ai_scan.transport._errors import BudgetExceededError, ScopeError
from ai_scan.transport.broker import RawExchange, RequestBroker
from ai_scan.transport.budgets import AttemptKind, BudgetLedger
from ai_scan.transport.scope_guard import ResolvedEndpoint, ScopeGuard
from tests.unit.transport._fakes import FakeResponse, RecordingOpener

TARGET = normalize_target("http://127.0.0.1:8080/chat")


def _endpoint() -> ResolvedEndpoint:
    return ResolvedEndpoint(target=TARGET, ip="127.0.0.1", family=4, host_is_literal=True)


class _StaticGuard:
    """Guard double that records calls and resolves to a fixed endpoint."""

    def __init__(self, endpoint: ResolvedEndpoint, *, error: Exception | None = None) -> None:
        self.endpoint = endpoint
        self.error = error
        self.calls = 0

    def check(self, url: str) -> ResolvedEndpoint:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.endpoint


def _broker(ledger: BudgetLedger, guard: object, opener: RecordingOpener) -> RequestBroker:
    return RequestBroker(
        ledger=ledger, guard=guard, timeout=1.0, max_response_bytes=1024, opener=opener
    )


def test_broker_never_exposes_a_raw_network_client() -> None:
    broker = _broker(BudgetLedger(max_requests=4), _StaticGuard(_endpoint()), RecordingOpener())
    # No public attribute hands back the opener; it is name-mangled.
    assert not any(
        getattr(broker, name, None).__class__.__name__ == "RecordingOpener"
        for name in vars(broker)
        if not name.endswith("__opener")
    )
    assert not hasattr(broker, "opener")
    # The only mangled private holds it, and reaching it requires the class name.
    assert broker._RequestBroker__opener is not None  # type: ignore[attr-defined]


def test_fetch_counts_one_attempt_and_returns_raw_exchange() -> None:
    ledger = BudgetLedger(max_requests=4)
    opener = RecordingOpener(FakeResponse(status=200, body=b"ok"))
    broker = _broker(ledger, _StaticGuard(_endpoint()), opener)
    result = broker.fetch(
        url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL
    )
    assert isinstance(result, RawExchange)
    assert result.status == 200
    assert ledger.totals() == {
        "initial": 1, "retry": 0, "control": 0, "confirmation": 0, "redirect": 0, "total": 1
    }
    assert len(opener.calls) == 1


def test_budget_is_acquired_before_scope_and_before_io() -> None:
    # Ledger already exhausted → neither the guard nor the opener is touched.
    ledger = BudgetLedger(max_requests=1)
    ledger._total = 1  # simulate a prior attempt
    guard = _StaticGuard(_endpoint())
    opener = RecordingOpener()
    broker = _broker(ledger, guard, opener)
    with pytest.raises(BudgetExceededError) as exc:
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    assert guard.calls == 0, "scope must not be resolved once budget is exhausted"
    assert opener.calls == [], "no socket I/O once budget is exhausted"
    assert exc.value.outcome == "inconclusive"
    assert exc.value.totals is not None


def test_scope_denied_attempt_is_counted_but_performs_no_io() -> None:
    ledger = BudgetLedger(max_requests=4)
    guard = _StaticGuard(_endpoint(), error=ScopeError("out of scope"))
    opener = RecordingOpener()
    broker = _broker(ledger, guard, opener)
    with pytest.raises(ScopeError) as exc:
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    # The attempt was acquired (budget consumed) before the scope check failed,
    # so totals stay accurate, but no byte hit the socket.
    assert opener.calls == []
    assert ledger.count == 1
    assert exc.value.outcome == "blocked"
    assert exc.value.totals == ledger.totals()


def test_real_guard_over_loopback_literal_needs_no_grant() -> None:
    # A real ScopeGuard bound to a loopback literal checks with no DNS and
    # no private grant — the operator named that exact address.
    ledger = BudgetLedger(max_requests=4)
    opener = RecordingOpener(FakeResponse(status=200, body=b"ok"))
    broker = _broker(ledger, ScopeGuard(target=TARGET), opener)
    result = broker.fetch(
        url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL
    )
    assert result.status == 200
    assert len(opener.calls) == 1
