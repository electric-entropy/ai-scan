"""Physical-request budgets with per-category accounting.

The :class:`BudgetLedger` is acquired once per physical attempt, *before* any
socket I/O, and enforces four independent budgets — request count, rate
(minimum inter-attempt interval), wall-clock duration, and concurrency — while
counting attempts by :class:`AttemptKind` (initial / retry / control /
confirmation / redirect). The per-kind counts always sum to the
total, so accounting stays accurate even across retries and redirects.

Time and sleep come from injected ``clock``/``sleeper`` callables so rate and
duration limits are testable without real delays.
"""

from __future__ import annotations

import enum
import math
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

from ai_scan.transport._errors import BudgetExceededError


def _require_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def _require_finite_non_negative(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _require_finite_positive(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a number")
    if not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


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
    max_duration_seconds: float | None = None
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
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Every budget is finite and non-boolean; an unbounded duration is
        # expressed as ``None`` (absence of a limit), never a non-finite float.
        _require_positive_int("max_requests", self.max_requests)
        _require_finite_non_negative("min_interval", self.min_interval)
        if self.max_duration_seconds is not None:
            _require_finite_positive("max_duration_seconds", self.max_duration_seconds)
        _require_positive_int("max_concurrency", self.max_concurrency)

    def _over_duration(self, now: float) -> bool:
        return (
            self.max_duration_seconds is not None
            and self._start is not None
            and now - self._start > self.max_duration_seconds
        )

    def remaining(self) -> float | None:
        """Seconds left until the wall-clock deadline, or ``None`` if unbounded.

        The deadline is a single monotonic absolute bound anchored at the first
        reserved attempt (the run start). It is negative once the budget is
        exhausted. Callers use it to bound resolution, connect, and response/
        error-body I/O so no single blocking operation can overrun the run.
        """
        if self.max_duration_seconds is None:
            return None
        with self._lock:
            start = self._start if self._start is not None else self.clock()
            return self.max_duration_seconds - (self.clock() - start)

    def check_deadline(self) -> None:
        """Raise if the wall-clock deadline has passed (no partial credit)."""
        remaining = self.remaining()
        if remaining is not None and remaining <= 0:
            raise BudgetExceededError(
                f"time budget of {self.max_duration_seconds}s exceeded"
            )

    @contextmanager
    def attempt(self, kind: AttemptKind) -> Iterator[None]:
        """Reserve one physical attempt of ``kind``, enforcing every budget.

        Budgets are checked *before* yielding (i.e. before the caller performs
        any socket I/O). The check-and-reserve is guarded by a lock so the
        counters stay consistent and ``max_concurrency`` holds under true
        parallelism. Raises :class:`BudgetExceededError` when exhausted.
        """
        with self._lock:
            now = self.clock()
            if self._start is None:
                self._start = now
            if self._active >= self.max_concurrency:
                raise BudgetExceededError(f"concurrency budget of {self.max_concurrency} exceeded")
            if self._total >= self.max_requests:
                raise BudgetExceededError(f"request budget of {self.max_requests} exhausted")
            if self._over_duration(now):
                raise BudgetExceededError(
                    f"time budget of {self.max_duration_seconds}s exceeded"
                )
            if self.min_interval > 0 and self._last is not None:
                wait = self.min_interval - (now - self._last)
                if wait > 0:
                    self.sleeper(wait)
            # Re-check duration after any rate-limit sleep: a long throttle can
            # push the attempt past the wall-clock budget.
            now = self.clock()
            if self._over_duration(now):
                raise BudgetExceededError(
                    f"time budget of {self.max_duration_seconds}s exceeded"
                )
            self._last = now
            self._total += 1
            self._counts[kind] += 1
            self._active += 1
        try:
            yield
        finally:
            with self._lock:
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
