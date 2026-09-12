"""Transport exception hierarchy (single source of truth).

Kept in a dependency-free module so ``budgets``, ``scope_guard``, ``broker`` and
``http`` can all raise and catch the same types without import cycles. Messages
are always secret-free (callers scrub untrusted values before constructing
these).

Terminal denials carry a structured :attr:`TransportError.outcome`
(``"blocked"`` for a scope/authorization denial, ``"inconclusive"`` for budget
exhaustion) and the physical-attempt ``totals`` observed at denial time, so the
CLI/report boundary can emit an accurate outcome without re-deriving counts.
"""

from __future__ import annotations


class TransportError(Exception):
    """Raised on a transport-level failure. Never contains secret material.

    Attributes:
        outcome: Structured classification for terminal denials — ``"blocked"``
            (scope/authorization boundary) or ``"inconclusive"`` (budget
            exhaustion). ``None`` for ordinary (e.g. connection) failures.
        totals: Per-kind physical-attempt counts at the time of the failure, if
            a budget ledger was in play.
    """

    outcome: str | None = None

    def __init__(self, message: str, *, totals: dict[str, int] | None = None) -> None:
        super().__init__(message)
        self.totals = totals


class BudgetExceededError(TransportError):
    """Raised when a physical-request budget (count/rate/time/concurrency) is hit."""

    outcome = "inconclusive"


class ScopeError(TransportError):
    """Raised when an attempt would leave the authorized scope.

    Covers a non-canonical scheme/host/port/path, a disallowed IP family, a
    resolved IP outside scope, a mixed public/private answer, or DNS rebinding.
    """

    outcome = "blocked"
