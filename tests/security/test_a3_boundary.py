"""Phase A3 — broker/target/budget trust boundary.

Covers: caller-supplied authority (`Host`) header rejection + pinning from the
authorized target; raw-URL whitespace/control-char rejection (no normalize-into-
validity); synchronized budget check-and-reserve (deterministic two-thread
barrier); duration re-checked after a rate-limit sleep; finite/non-boolean
constructor validation; and physical attempts cannot overrun the request budget.
"""

from __future__ import annotations

import threading

import pytest

from ai_scan.targets import TargetError, normalize_target
from ai_scan.transport._errors import BudgetExceededError, ScopeError
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


# --- A3.1 Host authority header -------------------------------------------------

def test_caller_supplied_host_header_is_rejected() -> None:
    ledger = BudgetLedger(max_requests=4)
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    with pytest.raises(ScopeError):
        broker.fetch(
            url=TARGET.url, method="GET", data=None,
            headers={"Host": "evil.example"}, kind=AttemptKind.INITIAL,
        )
    # Rejected before any socket I/O.
    assert opener.calls == []


def test_host_header_is_pinned_from_authorized_target() -> None:
    ledger = BudgetLedger(max_requests=4)
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    sent = {k.lower(): v for k, v in opener.calls[0]["headers"].items()}
    assert sent.get("host") == "127.0.0.1:8080"


# --- A3.2 raw-URL hygiene -------------------------------------------------------

@pytest.mark.parametrize(
    "raw",
    [
        " http://127.0.0.1:8080/chat",
        "http://127.0.0.1:8080/chat ",
        "http://127.0.0.1:8080/chat\n",
        "\thttp://127.0.0.1:8080/chat",
        "http://127.0.0.1:8080/ch\tat",
        "http://127.0.0.1:8080/ch\x00at",
        "http://127.0.0.1:8080/ch\x7fat",
    ],
)
def test_raw_target_with_whitespace_or_control_chars_is_rejected(raw: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(raw)


# --- A3.3 synchronized check-and-reserve (deterministic barrier) ----------------

class _Concurrency:
    """Tracks the maximum number of attempts simultaneously inside the section."""

    def __init__(self) -> None:
        self.inside = 0
        self.observed_max = 0
        self._lock = threading.Lock()

    def enter(self) -> None:
        with self._lock:
            self.inside += 1
            self.observed_max = max(self.observed_max, self.inside)

    def leave(self) -> None:
        with self._lock:
            self.inside -= 1


def _barrier_worker(
    ledger: BudgetLedger, barrier: threading.Barrier, tracker: _Concurrency
) -> None:
    barrier.wait(timeout=2)
    try:
        with ledger.attempt(AttemptKind.INITIAL):
            tracker.enter()
            tracker.leave()
    except BudgetExceededError:
        pass


def test_barrier_aligned_acquisitions_never_both_enter() -> None:
    # Invariant guard: with max_concurrency=1, two barrier-aligned acquisitions
    # must never both be inside the critical section at once. The ledger's lock
    # makes the check-and-reserve atomic (this matters under a free-threaded
    # interpreter; under the GIL the short section is already serialized).
    tracker = _Concurrency()
    for _ in range(50):
        ledger = BudgetLedger(max_requests=8, max_concurrency=1)
        barrier = threading.Barrier(2)
        threads = [
            threading.Thread(target=_barrier_worker, args=(ledger, barrier, tracker))
            for _ in range(2)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=2)

    assert tracker.observed_max == 1


# --- A3.4 duration re-check after rate sleep ------------------------------------

def test_duration_is_rechecked_after_rate_sleep() -> None:
    clock = {"now": 0.0}

    def sleeper(seconds: float) -> None:
        clock["now"] += seconds

    ledger = BudgetLedger(
        max_requests=8, min_interval=20.0, max_duration_seconds=10.0,
        clock=lambda: clock["now"], sleeper=sleeper,
    )
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    # The rate-limit sleep (20s) pushes the wall clock past the 10s duration
    # budget; the attempt must fail closed rather than send after the sleep.
    with pytest.raises(BudgetExceededError, match="time budget"):
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    assert len(opener.calls) == 1


# --- A3.5 finite / non-boolean constructor validation ---------------------------

@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_requests": True},
        {"max_requests": 0},
        {"max_requests": -1},
        {"max_requests": 4, "min_interval": float("nan")},
        {"max_requests": 4, "min_interval": float("inf")},
        {"max_requests": 4, "min_interval": -1.0},
        {"max_requests": 4, "min_interval": True},
        {"max_requests": 4, "max_duration_seconds": float("nan")},
        {"max_requests": 4, "max_duration_seconds": float("inf")},
        {"max_requests": 4, "max_duration_seconds": 0},
        {"max_requests": 4, "max_duration_seconds": -5},
        {"max_requests": 4, "max_duration_seconds": True},
        {"max_requests": 4, "max_concurrency": True},
        {"max_requests": 4, "max_concurrency": 0},
    ],
)
def test_budget_ledger_rejects_invalid_numeric_inputs(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        BudgetLedger(**kwargs)  # type: ignore[arg-type]


def test_budget_ledger_allows_unbounded_duration_as_none() -> None:
    # Unbounded duration is expressed by absence (None), never a non-finite float.
    ledger = BudgetLedger(max_requests=2, max_duration_seconds=None)
    with ledger.attempt(AttemptKind.INITIAL):
        pass
    assert ledger.count == 1


# --- A3.6 physical attempts cannot overrun the request budget -------------------

def test_attempts_cannot_overrun_request_budget() -> None:
    ledger = BudgetLedger(max_requests=256)
    opener = RecordingOpener(FakeResponse())
    broker = _broker(ledger, opener)
    for _ in range(256):
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    with pytest.raises(BudgetExceededError):
        broker.fetch(url=TARGET.url, method="GET", data=None, headers={}, kind=AttemptKind.RETRY)
    assert ledger.count == 256
    assert len(opener.calls) == 256
