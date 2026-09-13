"""Behavioral feature extraction: deterministic, descriptive (non-confirming)."""

from __future__ import annotations

import json

from ai_scan.fingerprinting import extract_features


def test_refusal_phrasing_detected() -> None:
    assert extract_features("I cannot help with that request.").refusal is True
    assert extract_features("Sure, here is the answer.").refusal is False


def test_code_fence_and_markdown() -> None:
    f = extract_features("Here:\n```python\nprint(1)\n```")
    assert f.code_fence is True and f.markdown is True
    assert extract_features("plain text").markdown is False


def test_tool_call_json_detected() -> None:
    assert extract_features(json.dumps({"tool_calls": [{"id": "1"}]})).tool_call_json is True
    assert extract_features(json.dumps({"name": "get", "arguments": {}})).tool_call_json is True
    assert extract_features(json.dumps({"type": "tool_use", "name": "x"})).tool_call_json is True
    assert extract_features("not a tool call").tool_call_json is False


def test_reflection_tendency() -> None:
    prompt = "please repeat this exact sentence back to me"
    assert extract_features(f"you said: {prompt}", prompt).reflects_prompt is True
    assert extract_features("an unrelated answer", prompt).reflects_prompt is False


def test_features_are_deterministic() -> None:
    body = "I cannot. ```code``` **bold**"
    assert extract_features(body, "p").to_dict() == extract_features(body, "p").to_dict()
