"""Aggregate probe observations into a deterministic, non-confirming fingerprint.

Combines per-response provider-shape votes and behavioral features over a bounded
probe set into a :class:`Fingerprint`: calibrated top-k shape scores, a
minimum-margin gate, and an explicit open-set classification
(``identified`` / ``unknown`` / ``inconsistent`` / ``inconclusive``). A router
fixture (different shapes across probes) reports ``inconsistent`` rather than a
false single identity. The result is content-digested and never feeds the
confirmation predicate.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ai_scan.fingerprint import ProbeExchange
from ai_scan.fingerprinting.features import extract_features
from ai_scan.fingerprinting.shapes import infer_shape
from ai_scan.packs.signatures import compute_digest

_FEATURE_KEYS = ("refusal", "tool_call_json", "markdown", "code_fence", "reflects_prompt")


class FingerprintError(Exception):
    """Raised for invalid fingerprinting parameters (fail closed)."""


@dataclass(frozen=True)
class Fingerprint:
    """A deterministic, advisory (never confirming) behavioral fingerprint."""

    classification: str  # identified | unknown | inconsistent | inconclusive
    shapes: tuple[tuple[str, float], ...]
    margin: float
    confidence: float
    sample_size: int
    features: Mapping[str, int] = field(default_factory=dict)
    digest: str = ""

    def to_canonical(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "shapes": [[shape, round(score, 4)] for shape, score in self.shapes],
            "margin": round(self.margin, 4),
            "confidence": round(self.confidence, 4),
            "sample_size": self.sample_size,
            "features": {key: int(self.features.get(key, 0)) for key in _FEATURE_KEYS},
        }


def build_fingerprint(
    exchanges: Sequence[ProbeExchange],
    *,
    prompts: Mapping[str, str] | None = None,
    min_score: float = 0.5,
    min_margin: float = 0.25,
    top_k: int = 3,
) -> Fingerprint:
    """Aggregate ``exchanges`` into a deterministic :class:`Fingerprint`."""
    if not 0.0 < min_score <= 1.0 or not 0.0 <= min_margin <= 1.0:
        raise FingerprintError("min_score/min_margin out of range")
    if top_k <= 0:
        raise FingerprintError("top_k must be positive")
    prompts = prompts or {}

    usable = [e for e in exchanges if e.usable]
    feature_counts: Counter[str] = Counter()
    for exchange in usable:
        features = extract_features(exchange.response_text, prompts.get(exchange.probe_id, ""))
        for key, present in features.to_dict().items():
            if present:
                feature_counts[key] += 1

    if not usable:
        return _finalize("inconclusive", (), 0.0, 0.0, 0, feature_counts)

    votes: Counter[str] = Counter(infer_shape(e.response_text, e.headers) for e in usable)
    total = sum(votes.values())
    ranked = sorted(votes.items(), key=lambda kv: (-kv[1], kv[0]))
    scores = [(shape, count / total) for shape, count in ranked]
    top_scores = tuple(scores[:top_k])

    top_shape, top_score = scores[0]
    runner_up = scores[1][1] if len(scores) > 1 else 0.0
    margin = top_score - runner_up
    known_with_votes = [s for s, _ in scores if s != "unknown"]

    if top_shape == "unknown":
        classification = "unknown"
    elif len(known_with_votes) >= 2 and margin < min_margin:
        # Votes split across multiple provider shapes (e.g. a router) → report
        # the inconsistency rather than a false single identity.
        classification = "inconsistent"
    elif top_score >= min_score and margin >= min_margin:
        classification = "identified"
    else:
        classification = "unknown"

    return _finalize(classification, top_scores, margin, top_score, len(usable), feature_counts)


def _finalize(
    classification: str,
    shapes: tuple[tuple[str, float], ...],
    margin: float,
    confidence: float,
    sample_size: int,
    feature_counts: Mapping[str, int],
) -> Fingerprint:
    features = {key: int(feature_counts.get(key, 0)) for key in _FEATURE_KEYS}
    draft = Fingerprint(
        classification=classification,
        shapes=shapes,
        margin=margin,
        confidence=confidence,
        sample_size=sample_size,
        features=features,
    )
    digest = compute_digest(draft.to_canonical())
    return Fingerprint(
        classification=classification,
        shapes=shapes,
        margin=margin,
        confidence=confidence,
        sample_size=sample_size,
        features=features,
        digest=digest,
    )
