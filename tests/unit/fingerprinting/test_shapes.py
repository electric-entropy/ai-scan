"""Provider-shape inference: structural, deterministic, fail-closed."""

from __future__ import annotations

import json

import pytest

from ai_scan.fingerprinting import infer_shape

_OPENAI = json.dumps({"choices": [{"message": {"content": "hi"}}]})
_ANTHROPIC = json.dumps({"role": "assistant", "content": [{"type": "text", "text": "hi"}],
                         "stop_reason": "end_turn"})
_GEMINI = json.dumps({"candidates": [{"content": {"parts": [{"text": "hi"}]}}]})
_OLLAMA = json.dumps({"model": "llama3", "message": {"role": "assistant", "content": "hi"}})


@pytest.mark.parametrize(
    "body,expected",
    [
        (_OPENAI, "openai_compatible"),
        (_ANTHROPIC, "anthropic"),
        (_GEMINI, "gemini"),
        (_OLLAMA, "ollama"),
    ],
)
def test_infers_known_provider_shapes(body, expected) -> None:
    assert infer_shape(body, {}) == expected


def test_sse_detected_by_header_or_body() -> None:
    assert infer_shape("{}", {"Content-Type": "text/event-stream"}) == "sse"
    assert infer_shape("data: {}\n\n", {}) == "sse"


def test_websocket_detected_by_upgrade_header() -> None:
    assert infer_shape("", {"Upgrade": "websocket"}) == "websocket"


def test_non_json_is_unknown() -> None:
    assert infer_shape("just prose", {}) == "unknown"


def test_mixed_shape_fails_closed_to_unknown() -> None:
    # A body that satisfies two shape predicates at once is ambiguous.
    mixed = json.dumps(
        {
            "choices": [{"message": {"content": "x"}}],
            "candidates": [{"content": {"parts": [{"text": "x"}]}}],
        }
    )
    assert infer_shape(mixed, {}) == "unknown"


def test_empty_object_is_unknown() -> None:
    assert infer_shape("{}", {}) == "unknown"
