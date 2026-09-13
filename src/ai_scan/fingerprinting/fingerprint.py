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

import json
import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ai_scan.fingerprint import ProbeExchange
from ai_scan.fingerprinting.features import extract_features
from ai_scan.fingerprinting.shapes import PROVIDER_SHAPES, infer_shape
from ai_scan.packs.signatures import compute_digest

_FEATURE_KEYS = ("refusal", "tool_call_json", "markdown", "code_fence", "reflects_prompt")
# Advisory, open-set labels only. ``confirmed`` is deliberately absent: a
# fingerprint can never assert a confirmed finding.
_CLASSIFICATIONS = frozenset({"identified", "unknown", "inconsistent", "inconclusive"})
_DOC_FIELDS = frozenset(
    {"classification", "shapes", "margin", "confidence", "sample_size", "features", "digest"}
)
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
# Tolerance for comparing derived scores/margins (values round to 4 dp in the
# canonical form); the summed-score check allows for accumulated rounding.
_TOL = 1e-6
_SUM_TOL = 1e-3


class FingerprintError(Exception):
    """Raised for invalid fingerprint parameters, states, or documents (fail closed)."""


@dataclass(frozen=True)
class Fingerprint:
    """A deterministic, advisory (never confirming) behavioral fingerprint.

    The object is self-validating: an instance with an invalid state (a
    ``confirmed`` label, a non-finite or out-of-range score/margin/confidence, a
    negative sample size, an unknown provider shape, or a stray feature key)
    cannot be constructed — ``__post_init__`` raises :class:`FingerprintError`.
    """

    classification: str  # identified | unknown | inconsistent | inconclusive
    shapes: tuple[tuple[str, float], ...]
    margin: float
    confidence: float
    sample_size: int
    features: Mapping[str, int] = field(default_factory=dict)
    digest: str = ""

    def __post_init__(self) -> None:
        if self.classification not in _CLASSIFICATIONS:
            raise FingerprintError("invalid fingerprint classification")

        try:
            shapes = tuple((name, score) for name, score in self.shapes)
        except (TypeError, ValueError) as exc:
            raise FingerprintError("fingerprint shapes must be shape/score pairs") from exc
        object.__setattr__(self, "shapes", shapes)
        for name, score in shapes:
            if name not in PROVIDER_SHAPES:
                raise FingerprintError("unknown provider shape in fingerprint")
            _require_unit("shape score", score)
        _require_unit("margin", self.margin)
        _require_unit("confidence", self.confidence)
        if isinstance(self.sample_size, bool) or not isinstance(self.sample_size, int):
            raise FingerprintError("sample_size must be an integer")
        if self.sample_size < 0:
            raise FingerprintError("sample_size must be non-negative")
        try:
            features = dict(self.features.items())
        except AttributeError as exc:
            raise FingerprintError("fingerprint features must be a mapping") from exc
        for key, count in features.items():
            if key not in _FEATURE_KEYS:
                raise FingerprintError("unknown feature key in fingerprint")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise FingerprintError("feature counts must be non-negative integers")
        object.__setattr__(self, "features", MappingProxyType(features))
        if self.digest and not _SHA256_HEX_RE.fullmatch(self.digest):
            raise FingerprintError("fingerprint digest must be a sha-256 hex string")
        self._check_consistency()

    def _check_consistency(self) -> None:
        """Reject semantically impossible states (cross-field invariants).

        Digest equality only proves content integrity; these checks ensure a
        document cannot claim a contradictory fingerprint even when re-digested.
        The invariants mirror exactly what :func:`build_fingerprint` can emit.
        """
        if self.classification == "inconclusive":
            # Inconclusive means no usable probe evidence at all.
            if self.shapes or self.sample_size != 0 or self.confidence != 0.0 or self.margin != 0.0:
                raise FingerprintError("inconclusive fingerprint must carry no evidence")
            return
        # Every other classification rests on usable evidence.
        if not self.shapes or self.sample_size <= 0:
            raise FingerprintError("classification requires usable probe evidence")
        scores = [score for _, score in self.shapes]
        # Scores are vote fractions: non-increasing and summing to at most one.
        if any(later > earlier + _TOL for earlier, later in zip(scores, scores[1:], strict=False)):
            raise FingerprintError("shape scores must be non-increasing")
        if sum(scores) > 1.0 + _SUM_TOL:
            raise FingerprintError("shape scores cannot sum above 1.0")
        # Confidence is the top shape's score; margin is the lead over the
        # runner-up and so can never exceed the confidence.
        if abs(self.confidence - scores[0]) > _SUM_TOL:
            raise FingerprintError("confidence must equal the top shape score")
        if self.margin > self.confidence + _TOL:
            raise FingerprintError("margin cannot exceed confidence")
        if self.classification == "identified":
            if self.shapes[0][0] == "unknown":
                raise FingerprintError("identified fingerprint cannot have an unknown top shape")
            if self.margin <= 0.0:
                raise FingerprintError("identified fingerprint requires a positive margin")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "shapes": [[shape, round(score, 4)] for shape, score in self.shapes],
            "margin": round(self.margin, 4),
            "confidence": round(self.confidence, 4),
            "sample_size": self.sample_size,
            "features": {key: int(self.features.get(key, 0)) for key in _FEATURE_KEYS},
        }

    def to_document(self) -> dict[str, Any]:
        """Canonical content plus the integrity ``digest`` (a persistable document)."""
        return {**self.to_canonical(), "digest": self.digest}


def _require_unit(label: str, value: Any) -> None:
    """Require a finite real number in the closed unit interval ``[0.0, 1.0]``."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FingerprintError(f"{label} must be a number")
    if not math.isfinite(value):
        raise FingerprintError(f"{label} must be finite")
    if not 0.0 <= float(value) <= 1.0:
        raise FingerprintError(f"{label} out of range")


def _require_positive_unit(label: str, value: Any) -> float:
    """Require a finite real number in ``(0.0, 1.0]``."""
    _require_unit(label, value)
    number = float(value)
    if number <= 0.0:
        raise FingerprintError(f"{label} out of range")
    return number


def build_fingerprint(
    exchanges: Sequence[ProbeExchange],
    *,
    prompts: Mapping[str, str] | None = None,
    min_score: float = 0.5,
    min_margin: float = 0.25,
    top_k: int = 3,
) -> Fingerprint:
    """Aggregate ``exchanges`` into a deterministic :class:`Fingerprint`."""
    min_score = _require_positive_unit("min_score", min_score)
    min_margin = _require_positive_unit("min_margin", min_margin)
    # A zero margin would let a tie be reported as a single identified model,
    # defeating the router/false-single-model guard; require a positive lead.
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise FingerprintError("top_k must be an integer")
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


# -- strict document boundary (closed schema, finite, tamper-rejecting) ---------

def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise FingerprintError("duplicate key in fingerprint document")
        out[key] = value
    return out


def parse_fingerprint_document(text: str) -> Fingerprint:
    """Parse fingerprint JSON ``text`` (rejecting duplicate keys) and validate it."""
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FingerprintError("fingerprint document is not valid JSON") from exc
    if not isinstance(data, dict):
        raise FingerprintError("fingerprint document must be a JSON object")
    return load_fingerprint_document(data)


def load_fingerprint_document(data: Mapping[str, Any]) -> Fingerprint:
    """Validate a parsed fingerprint ``data`` mapping into a :class:`Fingerprint`.

    Fails closed on unknown or missing fields, malformed enums/shapes, non-finite
    values, and (via digest re-computation) any semantic tamper.
    """
    if not isinstance(data, Mapping):
        raise FingerprintError("fingerprint document must be a JSON object")
    unknown = set(data) - _DOC_FIELDS
    if unknown:
        raise FingerprintError(f"unknown fingerprint field(s) not permitted ({len(unknown)})")
    missing = _DOC_FIELDS - set(data)
    if missing:
        raise FingerprintError(f"missing required fingerprint field(s): {len(missing)}")

    shapes = _as_shapes(data["shapes"])
    features = _as_features(data["features"])
    digest = data["digest"]
    if not isinstance(digest, str) or not _SHA256_HEX_RE.fullmatch(digest):
        raise FingerprintError("fingerprint digest must be a sha-256 hex string")

    # Construction re-validates classification/margin/confidence/sample_size and
    # finiteness via __post_init__.
    fingerprint = Fingerprint(
        classification=data["classification"],
        shapes=shapes,
        margin=data["margin"],
        confidence=data["confidence"],
        sample_size=data["sample_size"],
        features=features,
        digest=digest,
    )
    # Re-digest the canonical content and reject any mismatch (semantic tamper).
    if compute_digest(fingerprint.to_canonical()) != digest:
        raise FingerprintError("fingerprint digest does not match its content")
    return fingerprint


def _as_shapes(value: Any) -> tuple[tuple[str, float], ...]:
    if not isinstance(value, list):
        raise FingerprintError("fingerprint 'shapes' must be a list")
    out: list[tuple[str, float]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise FingerprintError("each shape must be a [name, score] pair")
        name, score = item
        if not isinstance(name, str):
            raise FingerprintError("shape name must be a string")
        if isinstance(score, bool) or not isinstance(score, (int, float)):
            raise FingerprintError("shape score must be a number")
        out.append((name, float(score)))
    return tuple(out)


def _as_features(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise FingerprintError("fingerprint 'features' must be an object")
    out: dict[str, int] = {}
    for key, count in value.items():
        if not isinstance(key, str):
            raise FingerprintError("feature keys must be strings")
        if isinstance(count, bool) or not isinstance(count, int):
            raise FingerprintError("feature counts must be integers")
        out[key] = count
    return out
