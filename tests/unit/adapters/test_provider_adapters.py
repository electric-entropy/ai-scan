"""Provider adapters: request shaping, extraction, config validation, offline."""

from __future__ import annotations

import json

import pytest

from ai_scan.adapters import (
    AdapterConfigError,
    AnthropicAdapter,
    ExtractionError,
    GeminiAdapter,
    OllamaAdapter,
    OpenAICompatibleAdapter,
    available_adapters,
    default_registry,
)
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse, RequestController, Transport, TransportConfig

TARGET = normalize_target("http://127.0.0.1:8080/v1/chat")

# (adapter class, response body producing "OK", extraction should yield "OK")
_PROVIDERS = [
    (OpenAICompatibleAdapter, {"choices": [{"message": {"content": "OK"}}]}),
    (AnthropicAdapter, {"content": [{"text": "OK"}]}),
    (
        GeminiAdapter,
        {"candidates": [{"content": {"role": "model", "parts": [{"text": "OK"}]},
                         "finishReason": "STOP"}]},
    ),
    (OllamaAdapter, {"message": {"content": "OK"}}),
]


def _response(body: str) -> HttpResponse:
    return HttpResponse(
        status=200, body=body, headers={}, redirected=False,
        redirect_location=None, truncated=False,
        request_line={"method": "POST", "url": TARGET.url},
    )


def test_all_provider_adapters_registered() -> None:
    names = available_adapters()
    assert {"openai_compatible", "anthropic", "gemini", "ollama", "sse", "websocket"} <= set(names)


@pytest.mark.parametrize("cls,response", _PROVIDERS)
def test_request_shaping_carries_prompt_as_json(cls, response) -> None:
    adapter = cls(target=TARGET, model="m-1")
    prepared = adapter.build_request("hello there")
    assert prepared.method == "POST"
    assert prepared.headers["Content-Type"] == "application/json"
    payload = json.loads(prepared.body.decode("utf-8"))
    # The prompt is embedded as JSON somewhere in the request body.
    assert "hello there" in json.dumps(payload)


@pytest.mark.parametrize("cls,response", _PROVIDERS)
def test_extraction_pulls_the_assistant_text(cls, response) -> None:
    adapter = cls(target=TARGET, model="m-1")
    assert adapter.extract(_response(json.dumps(response))) == "OK"


@pytest.mark.parametrize("cls,response", _PROVIDERS)
def test_extraction_fails_closed_on_wrong_shape(cls, response) -> None:
    adapter = cls(target=TARGET, model="m-1")
    with pytest.raises(ExtractionError):
        adapter.extract(_response(json.dumps({"unexpected": "shape"})))


@pytest.mark.parametrize("cls,response", _PROVIDERS)
def test_empty_model_fails_closed(cls, response) -> None:
    with pytest.raises(AdapterConfigError):
        cls(target=TARGET, model="")


@pytest.mark.parametrize("cls,response", _PROVIDERS)
def test_extra_headers_are_validated_and_frozen(cls, response) -> None:
    headers = {"X-Test": "one"}
    adapter = cls(target=TARGET, model="m-1", extra_headers=headers)
    headers["X-Test"] = "mutated"

    assert adapter.build_request("prompt").headers["X-Test"] == "one"
    with pytest.raises(AdapterConfigError):
        cls(target=TARGET, model="m-1", extra_headers={"X-Test": object()})


def test_registry_create_builds_provider_adapter() -> None:
    adapter = default_registry().create("openai_compatible", target=TARGET, model="gpt")
    assert adapter.capabilities().name == "openai_compatible"


def test_send_prepared_counts_one_physical_attempt(echo_server) -> None:
    # A provider request goes through the broker via send_prepared; exactly one
    # physical attempt is counted.
    target = normalize_target(f"{echo_server.base_url}/v1/chat")
    adapter = OpenAICompatibleAdapter(target=target, model="gpt")
    controller = RequestController(max_requests=4)
    transport = Transport(TransportConfig(), controller=controller)
    resp = transport.send_prepared(target, adapter.build_request("ping"))
    assert resp.status == 200
    assert controller.count == 1
