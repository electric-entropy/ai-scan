"""Tests for the heuristic behavioral fingerprint engine."""

from __future__ import annotations

from ai_scan.fingerprint import (
    DEFAULT_PROBES,
    ProbeExchange,
    run_fingerprint,
)
from ai_scan.models import FingerprintResult


def _responder(mapping):
    """Build a responder that returns a fixed body per probe id."""

    def respond(probe) -> ProbeExchange:
        return ProbeExchange(
            probe_id=probe.id,
            response_text=mapping.get(probe.id, ""),
            headers={},
        )

    return respond


def test_probes_are_data_driven_and_nonempty() -> None:
    assert len(DEFAULT_PROBES) >= 3
    ids = [p.id for p in DEFAULT_PROBES]
    assert len(ids) == len(set(ids))  # unique ids


def test_explicit_model_header_is_a_weak_signal() -> None:
    def respond(probe) -> ProbeExchange:
        return ProbeExchange(
            probe_id=probe.id,
            response_text="Hello.",
            headers={"X-Model-Name": "claude-3-opus"},
        )

    result = run_fingerprint(DEFAULT_PROBES, respond)
    assert isinstance(result, FingerprintResult)
    assert any(e.kind == "header" for c in result.candidates for e in c.evidence)


def test_self_identification_is_a_weak_signal() -> None:
    bodies = {p.id: "I am Claude, an AI assistant made by Anthropic." for p in DEFAULT_PROBES}
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    assert result.top is not None
    assert any(
        e.kind == "self_id" for c in result.candidates for e in c.evidence
    )


def test_behavioral_markers_rank_a_family() -> None:
    # Craft responses that consistently trip claude-family behavioral markers.
    bodies = {
        p.id: "I aim to be helpful, harmless, and honest. Constitutional AI guides me."
        for p in DEFAULT_PROBES
    }
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    assert result.top is not None
    assert result.top.family == "claude"
    assert 0.0 <= result.top.score <= 1.0


def test_scores_are_normalized() -> None:
    bodies = {p.id: "I am Claude. helpful, harmless, and honest." for p in DEFAULT_PROBES}
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    total = sum(c.score for c in result.candidates)
    assert total <= 1.0 + 1e-9
    for c in result.candidates:
        assert 0.0 <= c.score <= 1.0


def test_candidates_are_ranked_descending() -> None:
    bodies = {
        p.id: "I am Claude, helpful harmless honest. Also GPT sometimes."
        for p in DEFAULT_PROBES
    }
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    scores = [c.score for c in result.candidates]
    assert scores == sorted(scores, reverse=True)


def test_unknown_when_no_signal() -> None:
    bodies = {p.id: "The weather is fine today." for p in DEFAULT_PROBES}
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    assert result.is_unknown is True
    assert result.top is None


def test_unknown_when_margin_too_small() -> None:
    # Equal evidence for two families → ambiguous → unknown by margin rule.
    text = "I am Claude helpful harmless honest. I am ChatGPT, a large language model by OpenAI."
    bodies = {p.id: text for p in DEFAULT_PROBES}
    result = run_fingerprint(
        DEFAULT_PROBES, _responder(bodies), min_score=0.4, min_margin=0.9
    )
    assert result.is_unknown is True


def test_result_labeled_heuristic() -> None:
    bodies = {p.id: "I am Claude." for p in DEFAULT_PROBES}
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    assert result.method == "heuristic"


def test_result_serializes_without_error() -> None:
    import json

    bodies = {p.id: "I am Claude, helpful harmless honest." for p in DEFAULT_PROBES}
    result = run_fingerprint(DEFAULT_PROBES, _responder(bodies))
    json.dumps(result.to_dict())


# --- Finding 6: transport outcome drives fingerprint classification ----------


def test_all_redirected_probes_yield_inconclusive() -> None:
    def respond(probe) -> ProbeExchange:
        return ProbeExchange(probe.id, "", {}, status=302, redirected=True)

    result = run_fingerprint(DEFAULT_PROBES, respond)
    assert result.inconclusive is True
    assert result.top is None


def test_all_transport_failures_yield_inconclusive() -> None:
    def respond(probe) -> ProbeExchange:
        return ProbeExchange(probe.id, "I am Claude", {}, status=0, transport_ok=False)

    result = run_fingerprint(DEFAULT_PROBES, respond)
    # Even though the (unusable) body mentions a family, nothing is scored.
    assert result.inconclusive is True
    assert result.candidates == []


def test_truncated_probes_are_not_scored() -> None:
    def respond(probe) -> ProbeExchange:
        return ProbeExchange(probe.id, "I am Claude", {}, status=200, truncated=True)

    result = run_fingerprint(DEFAULT_PROBES, respond)
    assert result.inconclusive is True


def test_request_count_sums_probe_attempts() -> None:
    def respond(probe) -> ProbeExchange:
        return ProbeExchange(probe.id, "hello", {}, attempts=2)

    result = run_fingerprint(DEFAULT_PROBES, respond)
    assert result.request_count == len(DEFAULT_PROBES) * 2
