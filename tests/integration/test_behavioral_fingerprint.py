"""Integration: behavioral fingerprint over brokered, loopback-only probes."""

from __future__ import annotations

import json

import pytest

from ai_scan.adapters import AdapterConfigError, OpenAICompatibleAdapter
from ai_scan.fingerprint import DEFAULT_PROBES, ProbeExchange
from ai_scan.fingerprinting import build_fingerprint
from ai_scan.targets import normalize_target
from ai_scan.transport import RequestController, Transport, TransportConfig
from tests.conftest import MockRequest, MockResponse

_OPENAI_BODY = json.dumps({"choices": [{"message": {"content": "hello"}}]}).encode("utf-8")
_ANTHROPIC_BODY = json.dumps(
    {"role": "assistant", "content": [{"type": "text", "text": "hi"}], "stop_reason": "end"}
).encode("utf-8")


def _probe_via_broker(transport, target, adapter, probe) -> ProbeExchange:
    resp = transport.send_prepared(target, adapter.build_request(probe.prompt))
    return ProbeExchange(
        probe_id=probe.id,
        response_text=resp.body,
        headers=resp.headers,
        status=resp.status,
        redirected=resp.redirected,
        truncated=resp.truncated,
        transport_ok=True,
        attempts=resp.attempts,
    )


def test_fingerprint_over_broker_counts_attempts_and_identifies(mock_server) -> None:
    def behavior(_req: MockRequest) -> MockResponse:
        return MockResponse(status=200, body=_OPENAI_BODY,
                            headers={"Content-Type": "application/json"})

    server = mock_server(behavior)
    target = normalize_target(f"{server.base_url}/v1/chat")
    adapter = OpenAICompatibleAdapter(target=target, model="gpt")
    controller = RequestController(max_requests=16)
    transport = Transport(TransportConfig(), controller=controller)

    exchanges = [_probe_via_broker(transport, target, adapter, p) for p in DEFAULT_PROBES]
    fp = build_fingerprint(exchanges)

    assert fp.classification == "identified"
    assert fp.shapes[0][0] == "openai_compatible"
    # Every probe was a counted physical attempt through the broker.
    assert controller.count == len(DEFAULT_PROBES)


def test_router_target_reports_inconsistent(mock_server) -> None:
    calls = {"n": 0}

    def behavior(_req: MockRequest) -> MockResponse:
        # Alternate provider shapes, as a load-balancing router across models.
        calls["n"] += 1
        body = _OPENAI_BODY if calls["n"] % 2 else _ANTHROPIC_BODY
        return MockResponse(status=200, body=body, headers={"Content-Type": "application/json"})

    server = mock_server(behavior)
    target = normalize_target(f"{server.base_url}/v1/chat")
    adapter = OpenAICompatibleAdapter(target=target, model="gpt")
    transport = Transport(TransportConfig(), controller=RequestController(max_requests=16))

    exchanges = [_probe_via_broker(transport, target, adapter, p) for p in DEFAULT_PROBES]
    fp = build_fingerprint(exchanges)
    assert fp.classification == "inconsistent"


def test_malformed_adapter_config_fails_before_transport(monkeypatch) -> None:
    # A malformed provider config must fail at construction — before any
    # transport is built or any request is sent.
    import ai_scan.transport as transport_mod

    def boom(*_a, **_k):
        raise AssertionError("no transport may be constructed for a malformed config")

    monkeypatch.setattr(transport_mod, "Transport", boom)
    with pytest.raises(AdapterConfigError):
        OpenAICompatibleAdapter(target=normalize_target("http://127.0.0.1:8080/v1/chat"), model="")
