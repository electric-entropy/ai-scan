"""Physical-request budgets with per-category accounting.

The :class:`BudgetLedger` is acquired once per physical attempt, *before* any
socket I/O, and enforces four independent budgets — request count, rate
(minimum inter-attempt interval), wall-clock duration, and concurrency — while
counting attempts by :class:`AttemptKind` (initial / retry / control /
confirmation / authorized redirect). The per-kind counts always sum to the
total, so accounting stays accurate even across retries and redirects.

Time and sleep come from injected ``clock``/``sleeper`` callables so rate and
duration limits are testable without real delays.
"""

from __future__ import annotations

import enum
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from ai_scan.transport._errors import BudgetExceededError


class AttemptKind(enum.StrEnum):
    """The category of a physical request attempt, for separate accounting."""

    INITIAL = "initial"
    RETRY = "retry"
    CONTROL = "control"
    CONFIRMATION = "confirmation"
    REDIRECT = "redirect"


@dataclass
class BudgetLedger:
    """Enforces request/rate/time/concurrency budgets and counts by kind."""

    max_requests: int
    min_interval: float = 0.0
    max_duration_seconds: float = float("inf")
    max_concurrency: int = 1
    clock: Callable[[], float] = time.monotonic
    sleeper: Callable[[float], None] = time.sleep
    _counts: dict[AttemptKind, int] = field(
        default_factory=lambda: {kind: 0 for kind in AttemptKind}, repr=False
    )
    _total: int = 0
    _active: int = 0
    _last: float | None = field(default=None, repr=False)
    _start: float | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if self.min_interval < 0:
            raise ValueError("min_interval must be non-negative")
        if self.max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be positive")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")

    @contextmanager
    def attempt(self, kind: AttemptKind) -> Iterator[None]:
        """Reserve one physical attempt of ``kind``, enforcing every budget.

        Budgets are checked *before* yielding (i.e. before the caller performs
        any socket I/O). Raises :class:`BudgetExceededError` when exhausted.
        """
        now = self.clock()
        if self._start is None:
            self._start = now
        if self._active >= self.max_concurrency:
            raise BudgetExceededError(f"concurrency budget of {self.max_concurrency} exceeded")
        if self._total >= self.max_requests:
            raise BudgetExceededError(f"request budget of {self.max_requests} exhausted")
        if now - self._start > self.max_duration_seconds:
            raise BudgetExceededError(f"time budget of {self.max_duration_seconds}s exceeded")
        if self.min_interval > 0 and self._last is not None:
            wait = self.min_interval - (now - self._last)
            if wait > 0:
                self.sleeper(wait)
        self._last = self.clock()
        self._total += 1
        self._counts[kind] += 1
        self._active += 1
        try:
            yield
        finally:
            self._active -= 1

    @property
    def count(self) -> int:
        """Total physical attempts acquired (all kinds)."""
        return self._total

    def totals(self) -> dict[str, int]:
        """Per-kind counts plus the grand total (the parts sum to ``total``)."""
        result = {kind.value: self._counts[kind] for kind in AttemptKind}
        result["total"] = self._total
        return result
