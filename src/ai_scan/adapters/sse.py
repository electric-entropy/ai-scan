"""Server-Sent Events (SSE) streaming adapter (offline shaper + bounded parser).

Shapes an OpenAI-style streaming request and aggregates the ``data:`` event
deltas from the (already-buffered, redacted) response body into one string,
bounded by ``max_chars``. A stream that is truncated, carries an error event, or
never terminates (``[DONE]`` missing) is *unusable* and raises
:class:`ExtractionError`, so such a stream can never be classified as confirmed;
a byte-truncated response likewise classifies inconclusive upstream.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from ai_scan.adapters.base import (
    AdapterCapabilities,
    AdapterConfigError,
    ExtractionError,
    PreparedRequest,
    _validate_max_chars,
    validate_extra_headers,
)
from ai_scan.targets import Target

_DONE = "[DONE]"


def _dig(obj: Any, pointer: str) -> Any:
    node = obj
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            return None
    return node


def _sse_events(body: str) -> list[tuple[str | None, str]]:
    """Return ``(event_type, data_payload)`` for each SSE block with a data line.

    The ``event:`` type line is captured alongside the concatenated ``data:``
    payload so an ``event: error`` block can be rejected regardless of the shape
    of its data.
    """
    events: list[tuple[str | None, str]] = []
    for block in body.replace("\r\n", "\n").split("\n\n"):
        event_type: str | None = None
        data: list[str] = []
        for line in block.split("\n"):
            if line.startswith("data:"):
                data.append(line[len("data:"):].lstrip())
            elif line.startswith("event:"):
                event_type = line[len("event:"):].strip()
        if data:
            events.append((event_type, "\n".join(data)))
    return events


@dataclass
class SseAdapter:
    """Streaming SSE chat adapter; aggregates `delta` content events."""

    target: Target
    model: str = ""
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    max_chars: int = 1_000_000
    delta_path: str = "/choices/0/delta/content"

    name = "sse"

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise AdapterConfigError("sse adapter requires a non-empty model")
        _validate_max_chars(self.max_chars)
        if not isinstance(self.delta_path, str) or not self.delta_path.startswith("/"):
            raise AdapterConfigError("delta_path must be a JSON pointer")
        self.extra_headers = validate_extra_headers(self.extra_headers)

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            name=self.name,
            methods=frozenset({"POST"}),
            prompt_encodings=frozenset({"json"}),
            extraction_modes=frozenset({"sse_delta"}),
            supports_sessions=True,
        )

    def build_request(self, prompt: str) -> PreparedRequest:
        body = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": True,
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
        headers.update(self.extra_headers)
        return PreparedRequest(method="POST", url=self.target.url, headers=headers, body=body)

    def extract(self, response: Any) -> str:
        if getattr(response, "truncated", False):
            raise ExtractionError("SSE stream was byte-truncated (inconclusive)")
        pieces: list[str] = []
        complete = False
        for event_type, payload in _sse_events(response.body):
            if event_type == "error":
                raise ExtractionError("SSE stream delivered an error event")
            if payload.strip() == _DONE:
                complete = True
                break
            try:
                event = json.loads(payload)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ExtractionError("malformed SSE event") from exc
            if isinstance(event, dict) and event.get("error") is not None:
                raise ExtractionError("SSE stream delivered an error event")
            delta = _dig(event, self.delta_path)
            if not isinstance(delta, str):
                raise ExtractionError("SSE event does not contain the configured delta")
            pieces.append(delta)
            if sum(len(p) for p in pieces) >= self.max_chars:
                # Hit the bound before the terminator → the stream is truncated,
                # not complete. Never allow a confirming body from it.
                raise ExtractionError(
                    "SSE stream exceeded max_chars before [DONE] (truncated; inconclusive)"
                )
        if not complete:
            raise ExtractionError("SSE stream did not terminate ([DONE] missing)")
        return "".join(pieces)[: self.max_chars]

    @contextmanager
    def session(self) -> Iterator[SseAdapter]:
        try:
            yield self
        finally:
            pass
