"""Behavioral fingerprinting v2: deterministic, non-confirming target features.

Extends the heuristic family fingerprint into deterministic behavioral features
(refusal/safety phrasing, tool-call-looking JSON, markdown/code tendency,
echo/reflection tendency), provider *response-shape* inference, and streaming
capability inference — aggregated into a content-digested :class:`Fingerprint`
with calibrated top-k shape scores, a minimum-margin gate, and an explicit
open-set ``unknown``/``inconsistent``/``inconclusive`` classification.

Fingerprinting is advisory only: it selects safe follow-up packs/adapters and is
**never** an input to the confirmation predicate. All inference is pure and
offline; active probes go through the broker like any other request.
"""

from __future__ import annotations

from ai_scan.fingerprinting.features import BehavioralFeatures, extract_features
from ai_scan.fingerprinting.fingerprint import (
    Fingerprint,
    FingerprintError,
    build_fingerprint,
    load_fingerprint_document,
    parse_fingerprint_document,
)
from ai_scan.fingerprinting.shapes import PROVIDER_SHAPES, infer_shape

__all__ = [
    "BehavioralFeatures",
    "Fingerprint",
    "FingerprintError",
    "PROVIDER_SHAPES",
    "build_fingerprint",
    "extract_features",
    "infer_shape",
    "load_fingerprint_document",
    "parse_fingerprint_document",
]
