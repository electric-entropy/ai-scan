"""Repeatability thresholds and a bounded statistical similarity signal.

:class:`RepeatabilityCalculator` is pure arithmetic over trial counts (no I/O,
bounded), enforcing a pack/mode's minimum successes and attack trials.
:class:`SimilarityValidator` emits a *statistical* signal capped at ``likely`` —
it can contribute to, but never alone produce, a confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

from ai_scan.core.models import DeterminismClass, FindingStatus
from ai_scan.validation.base import Evidence, Signal


@dataclass(frozen=True)
class RepeatabilityCalculator:
    """Deterministic trial-threshold check (Reliable/pack trial policy)."""

    min_attack_trials: int
    min_successes: int

    def __post_init__(self) -> None:
        if self.min_attack_trials <= 0 or self.min_successes <= 0:
            raise ValueError("repeatability minima must be positive")
        if self.min_successes > self.min_attack_trials:
            raise ValueError("min_successes cannot exceed min_attack_trials")

    def meets_threshold(self, *, attack_trials: int, successes: int) -> bool:
        """True iff enough trials were run and enough of them succeeded."""
        return attack_trials >= self.min_attack_trials and successes >= self.min_successes


@dataclass
class SimilarityValidator:
    """Fuzzy-match a response against an expected exemplar (statistical, ≤ likely)."""

    expected: str
    threshold: float = 0.85
    id = "similarity"
    method = DeterminismClass.STATISTICAL

    def __post_init__(self) -> None:
        if not 0.0 < self.threshold <= 1.0:
            raise ValueError("similarity threshold must be in (0, 1]")

    def ratio(self, response: str) -> float:
        if not self.expected:
            return 0.0
        return SequenceMatcher(None, self.expected, response).ratio()

    def validate(self, evidence: Evidence) -> Signal:
        score = self.ratio(evidence.response)
        hit = score >= self.threshold
        return Signal(
            validator_id=self.id,
            method=self.method,
            fired=hit,
            ceiling=FindingStatus.LIKELY,
            detail=f"similarity={score:.2f}",
        )
