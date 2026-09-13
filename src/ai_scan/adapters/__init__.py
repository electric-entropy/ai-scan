"""Adapters decouple application shape from transport and attack logic.

An :class:`~ai_scan.adapters.base.Adapter` knows how to *build* a request for a
target (marker insertion, encoding, captured-request replay) and how to
*extract* the relevant text from a response. It never performs I/O — the
transport broker remains the sole network mediator — so a malformed adapter
configuration fails closed with zero requests.
"""

from __future__ import annotations

from ai_scan.adapters.anthropic import AnthropicAdapter
from ai_scan.adapters.base import (
    Adapter,
    AdapterCapabilities,
    AdapterConfigError,
    AdapterError,
    ExtractionError,
    ExtractionSpec,
    HttpJsonAdapter,
    PreparedRequest,
    extract_text,
)
from ai_scan.adapters.captured_http import CapturedHttpAdapter, parse_captured_request
from ai_scan.adapters.gemini import GeminiAdapter
from ai_scan.adapters.generic_http import GenericHttpAdapter
from ai_scan.adapters.multimodal import MultimodalAdapter
from ai_scan.adapters.ollama import OllamaAdapter
from ai_scan.adapters.openai_compatible import OpenAICompatibleAdapter
from ai_scan.adapters.registry import (
    AdapterRegistry,
    available_adapters,
    default_registry,
)
from ai_scan.adapters.sse import SseAdapter
from ai_scan.adapters.websocket import WebSocketAdapter

__all__ = [
    "Adapter",
    "AdapterCapabilities",
    "AdapterConfigError",
    "AdapterError",
    "AdapterRegistry",
    "AnthropicAdapter",
    "CapturedHttpAdapter",
    "ExtractionError",
    "ExtractionSpec",
    "GeminiAdapter",
    "GenericHttpAdapter",
    "HttpJsonAdapter",
    "MultimodalAdapter",
    "OllamaAdapter",
    "OpenAICompatibleAdapter",
    "PreparedRequest",
    "SseAdapter",
    "WebSocketAdapter",
    "available_adapters",
    "default_registry",
    "extract_text",
    "parse_captured_request",
]
