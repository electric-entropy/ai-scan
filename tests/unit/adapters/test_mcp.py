"""Milestone 14: tool/MCP adapters are offline shapers and fail closed."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ai_scan.adapters.base import AdapterConfigError, ExtractionError
from ai_scan.adapters.mcp import McpAdapter
from ai_scan.adapters.registry import available_adapters, default_registry
from ai_scan.targets import Target, normalize_target
from ai_scan.transport import HttpResponse
from tests.fixtures.mcp.synthetic_server import SyntheticMcpServer


def _target() -> Target:
    return normalize_target("http://127.0.0.1:8000/mcp")


def _response(body: str) -> HttpResponse:
    return HttpResponse(
        status=200,
        body=body,
        headers={},
        redirected=False,
        redirect_location=None,
        truncated=False,
        request_line={"method": "POST", "url": "http://127.0.0.1:8000/mcp"},
    )


def test_mcp_adapter_shapes_json_rpc_request_without_io() -> None:
    adapter = McpAdapter(_target(), tool_name="synthetic_tool", tool_arguments={"scope": "audit"})
    request = adapter.build_request("check approval boundary")
    assert request.method == "POST"
    assert request.url == "http://127.0.0.1:8000/mcp"
    assert request.headers["Content-Type"] == "application/json"
    payload = json.loads(request.body or b"{}")
    assert payload == {
        "jsonrpc": "2.0",
        "id": "ai-scan-synthetic-tool-call",
        "method": "tools/call",
        "params": {
            "name": "synthetic_tool",
            "arguments": {"scope": "audit", "prompt": "check approval boundary"},
        },
    }
    server = SyntheticMcpServer()
    result = server.handle(request.body or b"{}")
    assert result["result"]["content"][0]["text"] == "synthetic tool handled"
    assert server.trace == [{"tool": "synthetic_tool", "prompt": "check approval boundary"}]


def test_mcp_adapter_extracts_tool_text_result() -> None:
    adapter = McpAdapter(_target(), tool_name="synthetic_tool")
    response = _response(
        json.dumps({"result": {"content": [{"type": "text", "text": "TRACE_OK"}]}})
    )
    assert adapter.extract(response) == "TRACE_OK"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"tool_name": ""},
        {"tool_name": "bad\nname"},
        {"tool_name": "synthetic", "prompt_argument": "bad\rarg"},
        {"tool_name": "synthetic", "tool_arguments": {"bad\nkey": "value"}},
        {"tool_name": "synthetic", "tool_arguments": {"ok": object()}},
        {"tool_name": "synthetic", "extra_headers": {"X-Test": object()}},
        {"tool_name": "synthetic", "max_chars": True},
    ],
)
def test_malformed_mcp_config_fails_before_request(kwargs: dict[str, Any]) -> None:
    with pytest.raises(AdapterConfigError):
        McpAdapter(_target(), **kwargs)


def test_mcp_result_truncation_is_inconclusive_not_successful_extraction() -> None:
    adapter = McpAdapter(_target(), tool_name="synthetic", max_chars=3)
    response = _response(
        json.dumps({"result": {"content": [{"type": "text", "text": "TRACE_OK"}]}})
    )
    assert adapter.extract(response) == "TRA"


def test_mcp_missing_result_fails_closed() -> None:
    adapter = McpAdapter(_target(), tool_name="synthetic")
    with pytest.raises(ExtractionError):
        adapter.extract(_response("{}"))


def test_mcp_is_registered_for_offline_discovery() -> None:
    registry = default_registry()
    assert "mcp" in available_adapters()
    caps = registry.capabilities("mcp")
    assert caps.name == "mcp"
    assert caps.supports_sessions
    assert caps.prompt_encodings == frozenset({"json-rpc"})
