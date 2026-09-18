"""Selected-adapter provider eligibility regressions (offline only)."""
import json

import pytest

from ai_scan.adapters import (
    AnthropicAdapter,
    ExtractionError,
    OllamaAdapter,
    OpenAICompatibleAdapter,
)
from ai_scan.targets import normalize_target
from tests.security.test_architecture_provider_semantics import _response


@pytest.mark.parametrize("done,reason", [(True, "length"), (True, "max_tokens"),
                                          (False, "stop"), (1, "stop"), (True, None)])
def test_ollama_requires_exact_done_and_terminal_reason(done, reason):
    response = _response(status=200, body=json.dumps({
        "message": {"role": "assistant", "content": "final"},
        "done": done, "done_reason": reason,
    }).encode())
    adapter = OllamaAdapter(normalize_target("http://127.0.0.1/chat"), model="offline")
    with pytest.raises(ExtractionError):
        adapter.extract(response)
    assert not response.provider_semantics().final_content_eligible


def test_openai_rejects_cross_provider_override():
    response = _response(status=200, body=json.dumps({
        "choices": [{"message": {"role": "user", "content": "unsafe"},
                     "finish_reason": "length"}],
        "candidates": [{"content": {"role": "model", "parts": [{"text": "safe"}]},
                        "finishReason": "STOP"}],
    }).encode())
    with pytest.raises(ExtractionError):
        OpenAICompatibleAdapter(normalize_target("http://127.0.0.1/chat"),
                                model="offline").extract(response)


@pytest.mark.parametrize("kind", ["thinking", "tool_use", "image", "unknown"])
def test_anthropic_nontext_never_extracted(kind):
    response = _response(status=200, body=json.dumps({
        "role": "assistant", "stop_reason": "end_turn",
        "content": [{"type": kind, "text": "unsafe"},
                    {"type": "text", "text": "refusal"}],
    }).encode())
    adapter = AnthropicAdapter(normalize_target("http://127.0.0.1/chat"), model="offline")
    with pytest.raises(ExtractionError):
        adapter.extract(response)


@pytest.mark.parametrize("adapter_class,envelope", [
    (OllamaAdapter, {"message": {"role": "assistant", "content": "final"},
                     "done": True, "done_reason": "stop"}),
    (OpenAICompatibleAdapter, {"choices": [{"message": {"role": "assistant", "content": "final"},
                                            "finish_reason": "stop"}]}),
    (AnthropicAdapter, {"role": "assistant", "stop_reason": "end_turn",
                        "content": [{"type": "text", "text": "fi"},
                                    {"type": "text", "text": "nal"}]}),
])
def test_selected_provider_exact_content_and_transport_negatives(adapter_class, envelope):
    from dataclasses import replace

    response = _response(status=200, body=json.dumps(envelope).encode())
    adapter = adapter_class(normalize_target("http://127.0.0.1/chat"), model="offline")
    assert adapter.extract(response) == "final"
    assert response.provider_semantics(adapter.name).final_content == "final"
    for invalid in (replace(response, status=500), replace(response, redirected=True),
                    replace(response, truncated=True), replace(response, decode_valid=False),
                    _response(status=200, body=json.dumps({**envelope, "error": {}}).encode())):
        with pytest.raises(ExtractionError):
            adapter.extract(invalid)
        audit = json.loads(invalid.evidence(redact_provider_text=True)["response"]["body"])
        assert set(audit) == {"audit_version", "raw_body"}
    for other in (OllamaAdapter, OpenAICompatibleAdapter, AnthropicAdapter):
        if other is not adapter_class:
            with pytest.raises(ExtractionError):
                other(adapter.target, model="offline").extract(response)
    with pytest.raises(ExtractionError):
        adapter_class(adapter.target, model="offline", max_chars=4).extract(response)
