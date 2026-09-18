"""Authoritative trusted physical-request accounting.

Public active engines accept one independently owned monotonic counter. They
snapshot it immediately around each logical exchange and use only the validated
delta as canonical physical usage. Responder, response, and exception metadata
is never an accounting source.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, TypeAlias, runtime_checkable


class LedgerError(ValueError):
    """The trusted counter is absent, malformed, incoherent, or non-monotonic."""


@runtime_checkable
class CounterObject(Protocol):
    """RequestController-compatible cumulative counter."""

    @property
    def count(self) -> int: ...


CounterValue: TypeAlias = int | Mapping[str, int]
PhysicalCounter: TypeAlias = CounterObject


@dataclass(frozen=True)
class LedgerSnapshot:
    """Validated cumulative total and optional per-kind cumulative counts."""

    total: int
    kinds: tuple[tuple[str, int], ...] | None = None


def _exact_nonnegative(value: object) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= (1 << 63) - 1
    )


def _read(source: PhysicalCounter) -> object:
    ledger = getattr(source, "ledger", None)
    totals = getattr(ledger, "totals", None)
    if callable(totals):
        return totals()
    return source.count


def require(source: PhysicalCounter | None) -> PhysicalCounter:
    """Reject legacy active execution without an independent trusted counter."""
    if source is None:
        raise LedgerError("trusted physical request counter is required")
    if callable(source) or not hasattr(source, "count"):
        raise LedgerError("trusted counter must be a RequestController-compatible object")
    return source


def snapshot(source: PhysicalCounter | None) -> LedgerSnapshot:
    """Read and validate one cumulative snapshot."""
    counter = require(source)
    try:
        raw = _read(counter)
    except LedgerError:
        raise
    except BaseException as exc:
        raise LedgerError("trusted physical request counter could not be read") from exc
    if (
        isinstance(raw, int)
        and not isinstance(raw, bool)
        and 0 <= raw <= (1 << 63) - 1
    ):
        return LedgerSnapshot(raw)
    if not isinstance(raw, Mapping) or "total" not in raw:
        raise LedgerError("trusted physical request counter is malformed")
    if not all(isinstance(key, str) and _exact_nonnegative(value) for key, value in raw.items()):
        raise LedgerError("trusted physical request counter is malformed")
    total = raw["total"]
    kinds = tuple(sorted((key, value) for key, value in raw.items() if key != "total"))
    if sum(value for _key, value in kinds) != total:
        raise LedgerError("trusted physical request counter totals are incoherent")
    return LedgerSnapshot(total=int(total), kinds=kinds)


def delta(
    before: LedgerSnapshot,
    source: PhysicalCounter | None,
    *,
    remaining: int | None = None,
) -> int:
    """Return the exact validated monotonic delta since ``before``."""
    after = snapshot(source)
    if after.total < before.total:
        raise LedgerError("trusted physical request counter is non-monotonic")
    consumed = after.total - before.total
    if (before.kinds is None) != (after.kinds is None):
        raise LedgerError("trusted physical request counter shape changed")
    if before.kinds is not None and after.kinds is not None:
        old = dict(before.kinds)
        new = dict(after.kinds)
        if set(old) != set(new) or any(new[key] < old[key] for key in old):
            raise LedgerError("trusted physical request counter kinds are non-monotonic")
        if sum(new[key] - old[key] for key in old) != consumed:
            raise LedgerError("trusted physical request counter delta is incoherent")
    if remaining is not None:
        if not _exact_nonnegative(remaining):
            raise LedgerError("canonical remaining request budget is malformed")
        if consumed > remaining:
            raise LedgerError("trusted physical request counter exceeds the remaining budget")
    return consumed


__all__ = [
    "CounterObject",
    "LedgerError",
    "LedgerSnapshot",
    "PhysicalCounter",
    "delta",
    "require",
    "snapshot",
]
