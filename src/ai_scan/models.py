"""Shared data models and the pluggable fingerprint-backend protocol.

These types are deliberately transport-agnostic and JSON-serializable so the
same structures flow from the engines into reports. The
:class:`FingerprintBackend` protocol leaves room for a future upstream
PyTorch/academic LLMmap backend without changing the CLI or reporting layers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

# Milestone 1 bridge: re-export the shared core domain types through the legacy
# `ai_scan.models` path so callers can migrate gradually. The existing legacy
# types below are unchanged. Explicit `as` aliases keep these re-exports visible
# under strict mypy (no implicit re-export).
from ai_scan.core.models import DeterminismClass as DeterminismClass
from ai_scan.core.models import Finding as Finding
from ai_scan.core.models import FindingStatus as FindingStatus
from ai_scan.core.models import PackTrust as PackTrust
from ai_scan.core.models import Severity as Severity

SignalKind = Literal["header", "self_id", "behavioral"]


@dataclass(frozen=True)
class Probe:
    """A single fingerprint probe definition (data-driven).

    Attributes:
        id: Stable, unique probe identifier.
        prompt: The prompt text sent to the target.
        category: Human-readable grouping (e.g. ``refusal``, ``identity``).
    """

    id: str
    prompt: str
    category: str = "general"


@dataclass(frozen=True)
class Marker:
    """A behavioral/self-id marker that contributes weight to a model family.

    Attributes:
        pattern: Lowercased substring searched for in a probe response.
        family: Model family this marker points at.
        weight: Positive contribution when the pattern is observed.
        kind: Signal strength category.
    """

    pattern: str
    family: str
    weight: float
    kind: SignalKind = "behavioral"


@dataclass(frozen=True)
class Evidence:
    """One observed signal supporting a family candidate."""

    probe_id: str
    family: str
    pattern: str
    weight: float
    kind: SignalKind

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "family": self.family,
            "pattern": self.pattern,
            "weight": self.weight,
            "kind": self.kind,
        }


@dataclass
class Candidate:
    """A ranked model-family candidate with its normalized score."""

    family: str
    score: float
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "score": round(self.score, 6),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass
class FingerprintResult:
    """The outcome of a fingerprint run.

    ``method`` is always ``heuristic`` for the built-in engine; it must never
    be presented as equivalent to academic LLMmap pretrained inference.

    ``inconclusive`` marks a run where probes were attempted but no usable
    response was obtained (all redirected, errored, truncated, or failed).
    ``request_count`` sums physical attempts made, retries included.
    """

    candidates: list[Candidate]
    is_unknown: bool
    method: str = "heuristic"
    inconclusive: bool = False
    request_count: int = 0

    @property
    def top(self) -> Candidate | None:
        """The best candidate, or ``None`` when the result is inconclusive."""
        if self.is_unknown or not self.candidates:
            return None
        return self.candidates[0]

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "is_unknown": self.is_unknown,
            "inconclusive": self.inconclusive,
            "top_family": self.top.family if self.top else None,
            "candidates": [c.to_dict() for c in self.candidates],
        }


@runtime_checkable
class FingerprintBackend(Protocol):
    """Protocol for a fingerprint backend.

    A future upstream PyTorch/academic LLMmap adapter can implement this to
    replace the heuristic engine without touching callers.
    """

    def identify(
        self, probes: list[Probe], responder: Any
    ) -> FingerprintResult:  # pragma: no cover - protocol definition
        ...
