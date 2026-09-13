"""Strict fingerprint document boundary: closed schema, finite, tamper-rejecting."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ai_scan.fingerprint import ProbeExchange
from ai_scan.fingerprinting import build_fingerprint
from ai_scan.fingerprinting.fingerprint import (
    Fingerprint,
    FingerprintError,
    load_fingerprint_document,
    parse_fingerprint_document,
)
from ai_scan.packs.signatures import compute_digest


def _redigest(doc: dict[str, Any]) -> dict[str, Any]:
    """Recompute a consistent integrity digest after mutating a document."""
    doc = dict(doc)
    doc.pop("digest", None)
    doc["digest"] = compute_digest(doc)
    return doc

_OPENAI = json.dumps({"choices": [{"message": {"content": "hi"}}]})


def _ex(pid: str, body: str) -> ProbeExchange:
    return ProbeExchange(probe_id=pid, response_text=body, headers={}, status=200)


def _valid_fp() -> Fingerprint:
    return build_fingerprint([_ex("a", _OPENAI), _ex("b", _OPENAI)])


def test_round_trip_document() -> None:
    fp = _valid_fp()
    text = json.dumps(fp.to_document())
    loaded = parse_fingerprint_document(text)
    assert loaded == fp
    assert loaded.digest == fp.digest


def test_duplicate_keys_rejected() -> None:
    fp = _valid_fp()
    body = json.dumps(fp.to_document())
    dup = body[:-1] + ', "classification": "unknown"}'
    with pytest.raises(FingerprintError):
        parse_fingerprint_document(dup)


def test_unknown_field_rejected() -> None:
    doc = _valid_fp().to_document()
    doc["surprise"] = 1
    with pytest.raises(FingerprintError):
        load_fingerprint_document(doc)


def test_missing_required_field_rejected() -> None:
    doc = _valid_fp().to_document()
    del doc["margin"]
    with pytest.raises(FingerprintError):
        load_fingerprint_document(doc)


def test_malformed_enum_rejected() -> None:
    doc = _valid_fp().to_document()
    doc["classification"] = "confirmed"
    with pytest.raises(FingerprintError):
        load_fingerprint_document(doc)


def test_non_finite_value_rejected() -> None:
    doc = _valid_fp().to_document()
    # NaN survives a json round-trip under the stdlib default; the loader must
    # still reject it (finite canonical/digest requirement).
    text = json.dumps(doc).replace('"margin": ' + json.dumps(doc["margin"]), '"margin": NaN')
    with pytest.raises(FingerprintError):
        parse_fingerprint_document(text)


def test_invalid_shape_name_rejected() -> None:
    doc = _valid_fp().to_document()
    doc["shapes"] = [["not_a_provider", 1.0]]
    with pytest.raises(FingerprintError):
        load_fingerprint_document(doc)


def test_semantic_tamper_rejected() -> None:
    # Flip a field to a different *valid* enum without re-digesting: the declared
    # digest no longer matches the content, so the document is rejected.
    doc = _valid_fp().to_document()
    doc["classification"] = "unknown"
    with pytest.raises(FingerprintError):
        load_fingerprint_document(doc)


def test_non_object_document_rejected() -> None:
    with pytest.raises(FingerprintError):
        parse_fingerprint_document("[]")


def test_redigested_identified_with_unknown_top_rejected() -> None:
    # A digest-consistent document that claims "identified" on an unknown top
    # shape is semantically impossible and must still reject.
    doc = _redigest(
        {
            "classification": "identified",
            "shapes": [["unknown", 1.0]],
            "margin": 1.0,
            "confidence": 1.0,
            "sample_size": 3,
            "features": {k: 0 for k in ("refusal", "tool_call_json", "markdown",
                                        "code_fence", "reflects_prompt")},
        }
    )
    with pytest.raises(FingerprintError):
        load_fingerprint_document(doc)


def test_redigested_inconclusive_with_evidence_rejected() -> None:
    doc = _valid_fp().to_document()
    doc["classification"] = "inconclusive"  # but sample_size > 0 and shapes present
    with pytest.raises(FingerprintError):
        load_fingerprint_document(_redigest(doc))


def test_redigested_scores_summing_above_one_rejected() -> None:
    doc = _valid_fp().to_document()
    doc["shapes"] = [["openai_compatible", 0.8], ["anthropic", 0.5]]
    doc["confidence"] = 0.8
    doc["margin"] = 0.3
    with pytest.raises(FingerprintError):
        load_fingerprint_document(_redigest(doc))


def test_redigested_identified_with_zero_margin_rejected() -> None:
    doc = _valid_fp().to_document()
    doc["classification"] = "identified"
    doc["shapes"] = [["openai_compatible", 0.5], ["anthropic", 0.5]]
    doc["confidence"] = 0.5
    doc["margin"] = 0.0
    with pytest.raises(FingerprintError):
        load_fingerprint_document(_redigest(doc))


def test_redigested_confidence_not_top_score_rejected() -> None:
    doc = _valid_fp().to_document()  # openai 1.0, confidence 1.0
    doc["confidence"] = 0.4
    doc["margin"] = 0.4
    with pytest.raises(FingerprintError):
        load_fingerprint_document(_redigest(doc))


def test_direct_invalid_construction_is_rejected() -> None:
    # The domain object is self-validating: an invalid state cannot exist.
    with pytest.raises(FingerprintError):
        Fingerprint(
            "confirmed",
            (("openai_compatible", float("nan")),),
            float("inf"),
            float("-inf"),
            -1,
            {"unknown_feature": 1},
        )


def test_direct_construction_defensively_freezes_nested_collections() -> None:
    mutable_shapes: list[list[object]] = [["openai_compatible", 1.0]]
    mutable_features = {
        k: 0 for k in ("refusal", "tool_call_json", "markdown", "code_fence", "reflects_prompt")
    }
    fp = Fingerprint("identified", mutable_shapes, 1.0, 1.0, 1, mutable_features)  # type: ignore[arg-type]

    mutable_shapes[0][0] = "unknown"
    mutable_features["refusal"] = 99

    assert fp.shapes == (("openai_compatible", 1.0),)
    assert fp.features["refusal"] == 0
    with pytest.raises(TypeError):
        fp.features["refusal"] = 1  # type: ignore[index]
