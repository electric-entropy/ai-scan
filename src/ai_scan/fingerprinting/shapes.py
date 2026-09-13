"""Provider response-shape inference from local fixtures (deterministic).

Classifies a response as one of the known provider shapes by *structure* — not
by trusting any self-reported name. A body that matches no known shape, or
matches more than one, is ``unknown`` (fail closed). Streaming transports are
inferred from headers/body so a truncated or error stream can be marked unusable
rather than mistaken for a model identity.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

PROVIDER_SHAPES = frozenset(
    {"openai_compatible", "anthropic", "gemini", "ollama", "sse", "websocket", "unknown"}
)


def _header(headers: Mapping[str, str], name: str) -> str:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return ""


def _is_openai(obj: Any) -> bool:
    if not isinstance(obj, dict) or not isinstance(obj.get("choices"), list) or not obj["choices"]:
        return False
    first = obj["choices"][0]
    return isinstance(first, dict) and ("message" in first or "delta" in first or "text" in first)


def _is_anthropic(obj: Any) -> bool:
    if not isinstance(obj, dict) or not isinstance(obj.get("content"), list) or not obj["content"]:
        return False
    first = obj["content"][0]
    has_block = isinstance(first, dict) and ("text" in first or first.get("type") == "text")
    return has_block and ("role" in obj or "stop_reason" in obj or "model" in obj)


def _is_gemini(obj: Any) -> bool:
    candidates = obj.get("candidates") if isinstance(obj, dict) else None
    if not isinstance(candidates, list) or not candidates:
        return False
    first = candidates[0]
    content = first.get("content") if isinstance(first, dict) else None
    return isinstance(content, dict) and isinstance(content.get("parts"), list)


def _is_ollama(obj: Any) -> bool:
    if not isinstance(obj, dict) or "choices" in obj:
        return False
    message = obj.get("message")
    return isinstance(message, dict) and "content" in message and "model" in obj


def infer_shape(body: str, headers: Mapping[str, str] | None = None) -> str:
    """Infer the provider response shape; ``unknown`` on no/mixed match."""
    headers = headers or {}
    # Streaming transports first (header-driven, unambiguous).
    if "text/event-stream" in _header(headers, "content-type").lower():
        return "sse"
    if _header(headers, "upgrade").lower() == "websocket":
        return "websocket"
    # SSE body without a content-type header.
    if any(line.startswith("data:") for line in body.replace("\r\n", "\n").split("\n")):
        return "sse"

    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return "unknown"

    matches = [
        shape
        for shape, predicate in (
            ("openai_compatible", _is_openai),
            ("anthropic", _is_anthropic),
            ("gemini", _is_gemini),
            ("ollama", _is_ollama),
        )
        if predicate(obj)
    ]
    # Exactly one structural match identifies the shape; zero or several is
    # ambiguous and fails closed to ``unknown``.
    return matches[0] if len(matches) == 1 else "unknown"
