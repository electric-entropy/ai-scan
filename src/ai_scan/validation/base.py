"""Core validation types: evidence, signals, and status ranking.

A :class:`Signal` carries the *ceiling* a validator's positive result can
justify on its own — deterministic execution can reach ``confirmed``, a
statistical similarity only ``likely``, and heuristic/judge/reflection only
``suspected``. The confidence engine never lets a signal exceed its ceiling, so
the confirmation predicate lives in exactly one place.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol, runtime_checkable

from ai_scan.core.models import DeterminismClass, FindingStatus

# Rank for the four "observed" statuses, most severe first. ``inconclusive`` /
# ``blocked`` / ``not_tested`` are terminal and handled explicitly by the engine.
_RANK: dict[FindingStatus, int] = {
    FindingStatus.CONFIRMED: 4,
    FindingStatus.LIKELY: 3,
    FindingStatus.SUSPECTED: 2,
    FindingStatus.NOT_OBSERVED: 1,
}


def status_rank(status: FindingStatus) -> int:
    """Severity rank for an observed status (higher = more severe)."""
    return _RANK.get(status, 0)


@dataclass(frozen=True)
class Evidence:
    """Everything a validator may inspect for one attack observation.

    Attributes:
        response: The extracted response text (already redacted upstream).
        canary: The unique canary token for the run.
        prompt: The rendered attack prompt that was sent.
        evaluable: False when the exchange could not be evaluated (transport
            failure, redirect, HTTP error, or truncation) — the engine then
            returns ``inconclusive``.
        readback_confirmed: Independent read-back corroborated a state change.
        cleanup_confirmed: The state change was cleaned up and verified.
    """

    response: str
    canary: str
    prompt: str = ""
    evaluable: bool = True
    readback_confirmed: bool = False
    cleanup_confirmed: bool = False


@dataclass(frozen=True)
class Signal:
    """One validator's verdict for a piece of evidence."""

    validator_id: str
    method: DeterminismClass
    fired: bool
    ceiling: FindingStatus
    reflection: bool = False
    provenance: Mapping[str, str] = field(default_factory=dict)
    detail: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "provenance", MappingProxyType(dict(self.provenance)))


@runtime_checkable
class Validator(Protocol):
    """A validator inspects evidence and emits a single :class:`Signal`."""

    id: str
    method: DeterminismClass

    def validate(self, evidence: Evidence) -> Signal: ...
