"""Fingerprint aggregation: classification matrix, determinism, never-confirming."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ai_scan.fingerprint import ProbeExchange
from ai_scan.fingerprinting import Fingerprint, build_fingerprint
from ai_scan.fingerprinting.fingerprint import FingerprintError

_OPENAI = json.dumps({"choices": [{"message": {"content": "hi"}}]})
_ANTHROPIC = json.dumps({"role": "assistant", "content": [{"type": "text", "text": "hi"}],
                         "stop_reason": "end_turn"})
_CLASSIFICATIONS = {"identified", "unknown", "inconsistent", "inconclusive"}


def _ex(pid: str, body: str, *, status: int = 200, truncated: bool = False) -> ProbeExchange:
    return ProbeExchange(
        probe_id=pid, response_text=body, headers={}, status=status, truncated=truncated
    )


def test_consistent_shape_is_identified() -> None:
    fp = build_fingerprint([_ex("a", _OPENAI), _ex("b", _OPENAI), _ex("c", _OPENAI)])
    assert fp.classification == "identified"
    assert fp.shapes[0][0] == "openai_compatible"
    assert fp.confidence == 1.0


def test_router_reports_inconsistent_not_a_single_model() -> None:
    fp = build_fingerprint(
        [_ex("a", _OPENAI), _ex("b", _OPENAI), _ex("c", _ANTHROPIC), _ex("d", _ANTHROPIC)]
    )
    assert fp.classification == "inconsistent"
    assert {s for s, _ in fp.shapes} >= {"openai_compatible", "anthropic"}


def test_unrecognized_shapes_are_unknown() -> None:
    fp = build_fingerprint([_ex("a", "prose"), _ex("b", "more prose")])
    assert fp.classification == "unknown"


def test_no_usable_responses_is_inconclusive() -> None:
    fp = build_fingerprint([_ex("a", _OPENAI, status=500), _ex("b", _OPENAI, truncated=True)])
    assert fp.classification == "inconclusive"
    assert fp.sample_size == 0


def test_fingerprint_is_deterministic_and_digested() -> None:
    a = build_fingerprint([_ex("a", _OPENAI), _ex("b", _OPENAI)])
    b = build_fingerprint([_ex("a", _OPENAI), _ex("b", _OPENAI)])
    assert a.digest == b.digest and a.digest
    assert a.to_canonical() == b.to_canonical()


def test_top_k_bounds_reported_shapes() -> None:
    # top_k caps how many shapes are reported; with three distinct shapes and
    # top_k=2 only two are kept (the runner-up is always retained for audit).
    gemini = json.dumps({"candidates": [{"content": {"parts": [{"text": "hi"}]}}]})
    fp = build_fingerprint(
        [_ex("a", _OPENAI), _ex("b", _ANTHROPIC), _ex("c", gemini)], top_k=2
    )
    assert len(fp.shapes) == 2


def test_features_are_aggregated_as_counts() -> None:
    refusal = json.dumps({"choices": [{"message": {"content": "I cannot do that"}}]})
    fp = build_fingerprint([_ex("a", refusal), _ex("b", _OPENAI)])
    assert fp.features["refusal"] == 1


def test_classification_is_never_a_confirmation_label() -> None:
    # A fingerprint can never assert a confirmed finding; its label is always one
    # of the advisory, open-set classifications.
    for exchanges in (
        [_ex("a", _OPENAI)],
        [_ex("a", _OPENAI), _ex("b", _ANTHROPIC)],
        [_ex("a", "prose")],
        [_ex("a", _OPENAI, status=500)],
    ):
        fp = build_fingerprint(exchanges)
        assert fp.classification in _CLASSIFICATIONS
        assert fp.classification != "confirmed"


@pytest.mark.parametrize("kwargs", [{"min_score": 0.0}, {"min_score": 1.5}, {"min_score": True},
                                    {"min_score": "0.5"}, {"min_margin": -0.1},
                                    {"min_margin": 0.0}, {"min_margin": float("inf")},
                                    {"top_k": 0}, {"top_k": True}, {"top_k": 1.5}])
def test_invalid_parameters_fail_closed(kwargs: dict[str, Any]) -> None:
    with pytest.raises(FingerprintError):
        build_fingerprint([_ex("a", _OPENAI)], **kwargs)


def test_fingerprint_type() -> None:
    assert isinstance(build_fingerprint([_ex("a", _OPENAI)]), Fingerprint)
