"""Offline adapter registry and capability discovery.

The registry maps an adapter name to a factory and a static capability
descriptor. Discovery (:meth:`names`, :meth:`capabilities`) is entirely offline:
it never instantiates an adapter or touches the network. :meth:`create` builds a
configured adapter and surfaces a malformed configuration as
:class:`AdapterConfigError` before any request exists.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ai_scan.adapters.anthropic import AnthropicAdapter
from ai_scan.adapters.base import Adapter, AdapterCapabilities, AdapterConfigError
from ai_scan.adapters.captured_http import CAPABILITIES as _CAPTURED_CAPS
from ai_scan.adapters.captured_http import CapturedHttpAdapter
from ai_scan.adapters.gemini import GeminiAdapter
from ai_scan.adapters.generic_http import CAPABILITIES as _GENERIC_CAPS
from ai_scan.adapters.generic_http import GenericHttpAdapter
from ai_scan.adapters.mcp import CAPABILITIES as _MCP_CAPS
from ai_scan.adapters.mcp import McpAdapter
from ai_scan.adapters.ollama import OllamaAdapter
from ai_scan.adapters.openai_compatible import OpenAICompatibleAdapter
from ai_scan.adapters.sse import SseAdapter
from ai_scan.adapters.websocket import WebSocketAdapter
from ai_scan.transport import scrub_text

Factory = Callable[..., Adapter]


def _json_caps(name: str) -> AdapterCapabilities:
    return AdapterCapabilities(
        name=name,
        methods=frozenset({"POST"}),
        prompt_encodings=frozenset({"json"}),
        extraction_modes=frozenset({"json_pointer", "text"}),
        supports_sessions=False,
    )


def _stream_caps(name: str, methods: frozenset[str], mode: str) -> AdapterCapabilities:
    return AdapterCapabilities(
        name=name,
        methods=methods,
        prompt_encodings=frozenset({"json"}),
        extraction_modes=frozenset({mode}),
        supports_sessions=True,
    )


@dataclass
class AdapterRegistry:
    """A name → (factory, capabilities) catalog of adapters."""

    _factories: dict[str, Factory] = field(default_factory=dict)
    _capabilities: dict[str, AdapterCapabilities] = field(default_factory=dict)

    def register(
        self, name: str, factory: Factory, capabilities: AdapterCapabilities
    ) -> None:
        if name in self._factories:
            raise AdapterConfigError(f"adapter {scrub_text(str(name))!r} is already registered")
        self._factories[name] = factory
        self._capabilities[name] = capabilities

    def names(self) -> list[str]:
        """All registered adapter names (sorted, offline)."""
        return sorted(self._factories)

    def capabilities(self, name: str) -> AdapterCapabilities:
        """The static capability descriptor for ``name`` (offline)."""
        if name not in self._capabilities:
            raise AdapterConfigError(f"unknown adapter {scrub_text(str(name))!r}")
        return self._capabilities[name]

    def create(self, name: str, **config: Any) -> Adapter:
        """Instantiate adapter ``name`` with ``config`` (fails closed on error)."""
        if name not in self._factories:
            raise AdapterConfigError(
                f"unknown adapter {scrub_text(str(name))!r}; available: {', '.join(self.names())}"
            )
        return self._factories[name](**config)


def default_registry() -> AdapterRegistry:
    """A registry preloaded with the built-in adapters."""
    registry = AdapterRegistry()
    registry.register("generic_http", GenericHttpAdapter, _GENERIC_CAPS)
    registry.register("captured_http", CapturedHttpAdapter, _CAPTURED_CAPS)
    registry.register("openai_compatible", OpenAICompatibleAdapter, _json_caps("openai_compatible"))
    registry.register("anthropic", AnthropicAdapter, _json_caps("anthropic"))
    registry.register("gemini", GeminiAdapter, _json_caps("gemini"))
    registry.register("ollama", OllamaAdapter, _json_caps("ollama"))
    registry.register("sse", SseAdapter, _stream_caps("sse", frozenset({"POST"}), "sse_delta"))
    registry.register(
        "websocket", WebSocketAdapter, _stream_caps("websocket", frozenset({"GET"}), "ws_delta")
    )
    registry.register("mcp", McpAdapter, _MCP_CAPS)
    return registry


def available_adapters() -> list[str]:
    """Names of the built-in adapters (offline discovery)."""
    return default_registry().names()
