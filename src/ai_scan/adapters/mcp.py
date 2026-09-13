"""Pure offline MCP-style adapter.

This module shapes JSON-RPC tool-call prompts for a target endpoint but performs
no I/O. Sending remains the request broker's job. Configuration is validated at
construction so malformed tool metadata cannot reach transport construction.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ai_scan.adapters.base import (
    AdapterCapabilities,
    AdapterConfigError,
    ExtractionSpec,
    PreparedRequest,
    extract_text,
    validate_extra_headers,
)
from ai_scan.targets import Target
from ai_scan.transport import HttpResponse, scrub_text

CAPABILITIES = AdapterCapabilities(
    name="mcp",
    methods=frozenset({"POST"}),
    prompt_encodings=frozenset({"json-rpc"}),
    extraction_modes=frozenset({"json_pointer", "text"}),
    supports_sessions=True,
)


def _freeze_tool_arguments(arguments: Mapping[str, str]) -> Mapping[str, str]:
    if not isinstance(arguments, Mapping):
        raise AdapterConfigError("tool_arguments must be a mapping")
    frozen: dict[str, str] = {}
    for key, value in arguments.items():
        if not isinstance(key, str) or not key:
            raise AdapterConfigError("tool argument names must be non-empty strings")
        if not isinstance(value, str):
            raise AdapterConfigError("tool argument values must be strings")
        if "\x00" in key or "\r" in key or "\n" in key:
            raise AdapterConfigError("tool argument names must not contain control separators")
        frozen[key] = value
    return MappingProxyType(frozen)


@dataclass
class McpAdapter:
    """Build bounded MCP JSON-RPC requests without constructing transport."""

    target: Target
    tool_name: str
    prompt_argument: str = "prompt"
    tool_arguments: Mapping[str, str] = field(default_factory=dict)
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    max_chars: int = 1_000_000

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not self.tool_name.strip():
            raise AdapterConfigError("MCP adapter requires a non-empty tool_name")
        if not isinstance(self.prompt_argument, str) or not self.prompt_argument:
            raise AdapterConfigError("MCP adapter requires a non-empty prompt_argument")
        if any(ch in self.tool_name for ch in "\r\n\x00"):
            raise AdapterConfigError("MCP tool_name must not contain control separators")
        if any(ch in self.prompt_argument for ch in "\r\n\x00"):
            raise AdapterConfigError("MCP prompt_argument must not contain control separators")
        if (
            not isinstance(self.max_chars, int)
            or isinstance(self.max_chars, bool)
            or self.max_chars <= 0
        ):
            raise AdapterConfigError("max_chars must be positive")
        self.tool_arguments = _freeze_tool_arguments(self.tool_arguments)
        self.extra_headers = validate_extra_headers(self.extra_headers)

    def capabilities(self) -> AdapterCapabilities:
        return CAPABILITIES

    def build_request(self, prompt: str) -> PreparedRequest:
        if not isinstance(prompt, str) or not prompt:
            raise AdapterConfigError("MCP prompt must be a non-empty string")
        arguments: dict[str, str] = dict(self.tool_arguments)
        arguments[self.prompt_argument] = prompt
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": "ai-scan-synthetic-tool-call",
            "method": "tools/call",
            "params": {"name": self.tool_name, "arguments": arguments},
        }
        headers = {"Content-Type": "application/json"}
        headers.update(self.extra_headers)
        try:
            body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            message = scrub_text(str(exc))
            raise AdapterConfigError(f"MCP payload could not be encoded: {message}") from exc
        return PreparedRequest(method="POST", url=self.target.url, headers=headers, body=body)

    def extract(self, response: HttpResponse) -> str:
        return extract_text(
            response,
            ExtractionSpec(
                mode="json_pointer",
                path="/result/content/0/text",
                max_chars=self.max_chars,
            ),
        )

    @contextmanager
    def session(self) -> Iterator[McpAdapter]:
        try:
            yield self
        finally:
            pass
