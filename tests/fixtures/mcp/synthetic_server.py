"""Synthetic in-process MCP server fixture.

This fixture is intentionally not a socket server. Tests feed JSON-RPC request
bytes directly into :meth:`SyntheticMcpServer.handle` so MCP behavior is covered
without opening network listeners.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SyntheticMcpServer:
    """Tiny JSON-RPC tool-call fixture with an auditable synthetic trace."""

    allowed_tools: frozenset[str] = frozenset({"synthetic_tool"})
    trace: list[dict[str, str]] = field(default_factory=list)

    def handle(self, request_body: bytes) -> dict[str, Any]:
        data = json.loads(request_body.decode("utf-8"))
        params = data.get("params", {})
        tool = params.get("name")
        arguments = params.get("arguments", {})
        if tool not in self.allowed_tools:
            return {"error": {"code": -32602, "message": "tool not allowed"}}
        if not isinstance(arguments, dict):
            return {"error": {"code": -32602, "message": "arguments must be an object"}}
        prompt = arguments.get("prompt", "")
        if not isinstance(prompt, str):
            return {"error": {"code": -32602, "message": "prompt must be a string"}}
        self.trace.append({"tool": tool, "prompt": prompt})
        return {"result": {"content": [{"type": "text", "text": "synthetic tool handled"}]}}
