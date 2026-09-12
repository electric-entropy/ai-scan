"""Physical-request budgets are acquired before I/O and counted accurately.

Covers all four budgets (count / rate / time / concurrency) and the per-kind
accounting guarantee: initial, retry, control, confirmation, and authorized
redirect attempts are counted as separate physical counters that still sum to
the accurate total.
"""

from __future__ import annotations

import pytest

from ai_scan.targets import normalize_target
from ai_scan.transport._errors import BudgetExceededError
from ai_scan.transport.broker import RequestBroker
from ai_scan.transport.budgets import AttemptKind, BudgetLedger
from ai_scan.transport.scope_guard import ResolvedEndpoint
from tests.unit.transport._fakes import FakeResponse, RecordingOpener

TARGET = normalize_target("http://127.0.0.1:8080/chat")


class _OkGuard:
    def authorize(self, url: str) -> ResolvedEndpoint:
        return ResolvedEndpoint(target=TARGET, ip="127.0.0.1", family=4, host_is_literal=True)


def _broker(ledger: BudgetLedger, opener: RecordingOpener) -> RequestBroker:
    return RequestBroker(
        ledger=ledger, guard=_OkGuard(), timeout=1.0, max_response_bytes=1024, opener=opener
    )


# --- request-count budget -------------------------------------------------------

def test_request_budget_stops_before_socket_io() -> None:
    ledger = BudgetLedger(max_requests=2)
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    with pytest.raises(BudgetExceededError):
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    # The exhausted third attempt never reached the socket.
    assert len(opener.calls) == 2
    assert ledger.count == 2


# --- per-kind accounting --------------------------------------------------------

def test_per_kind_counters_are_separate_and_sum_to_total() -> None:
    ledger = BudgetLedger(max_requests=16)
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    plan = [
        AttemptKind.INITIAL,
        AttemptKind.RETRY, AttemptKind.RETRY,
        AttemptKind.CONTROL,
        AttemptKind.CONFIRMATION, AttemptKind.CONFIRMATION,
        AttemptKind.REDIRECT,
    ]
    for kind in plan:
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=kind)
    totals = ledger.totals()
    assert totals == {
        "initial": 1, "retry": 2, "control": 1, "confirmation": 2, "redirect": 1, "total": 7
    }
    assert sum(v for k, v in totals.items() if k != "total") == totals["total"]


# --- rate budget ----------------------------------------------------------------

def test_rate_budget_sleeps_between_attempts() -> None:
    slept: list[float] = []
    clock = {"now": 1000.0}
    ledger = BudgetLedger(
        max_requests=8,
        min_interval=0.5,
        clock=lambda: clock["now"],
        sleeper=lambda s: (slept.append(s), clock.__setitem__("now", clock["now"] + s)) and None,
    )
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    for _ in range(3):
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    assert [s for s in slept if s > 0] == [0.5, 0.5]


# --- time budget ----------------------------------------------------------------

def test_time_budget_is_enforced() -> None:
    clock = {"now": 0.0}
    ledger = BudgetLedger(
        max_requests=8, max_duration_seconds=10.0, clock=lambda: clock["now"]
    )
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    clock["now"] = 11.0  # wall clock advanced past the budget
    with pytest.raises(BudgetExceededError, match="time budget"):
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    assert len(opener.calls) == 1


# --- concurrency budget ---------------------------------------------------------

def test_concurrency_budget_is_enforced() -> None:
    ledger = BudgetLedger(max_requests=8, max_concurrency=1)
    # Hold one attempt open and try to acquire a second concurrently.
    with ledger.attempt(AttemptKind.INITIAL):
        with pytest.raises(BudgetExceededError, match="concurrency"):
            with ledger.attempt(AttemptKind.CONTROL):
                pass
    # Released after the outer attempt; a fresh acquire now succeeds.
    with ledger.attempt(AttemptKind.RETRY):
        pass
    assert ledger.totals()["total"] == 2  # initial + retry (the blocked one never counted)


def test_budget_error_carries_outcome_and_totals() -> None:
    ledger = BudgetLedger(max_requests=1)
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    with pytest.raises(BudgetExceededError) as exc:
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    assert exc.value.outcome == "inconclusive"
    assert exc.value.totals == {
        "initial": 1, "retry": 0, "control": 0, "confirmation": 0, "redirect": 0, "total": 1
    }
