"""WebSocket streaming adapter (offline shaper + bounded frame parser).

The adapter shapes the WebSocket *upgrade* request (the broker only does HTTP;
no live socket is opened here) and aggregates newline-delimited JSON message
frames from the buffered, redacted response transcript. A transcript that is
truncated, carries an error frame, or never sends a terminal ``done`` frame is
unusable and raises :class:`ExtractionError`, so it can never be confirmed.
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
from ai_scan.adapters.sse import _dig
from ai_scan.targets import Target


@dataclass
class WebSocketAdapter:
    """Streaming WebSocket chat adapter; aggregates `delta` message frames."""

    target: Target
    model: str = ""
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    max_chars: int = 1_000_000
    delta_path: str = "/delta"

    name = "websocket"

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise AdapterConfigError("websocket adapter requires a non-empty model")
        _validate_max_chars(self.max_chars)
        if not isinstance(self.delta_path, str) or not self.delta_path.startswith("/"):
            raise AdapterConfigError("delta_path must be a JSON pointer")
        self.extra_headers = validate_extra_headers(self.extra_headers)

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            name=self.name,
            methods=frozenset({"GET"}),
            prompt_encodings=frozenset({"json"}),
            extraction_modes=frozenset({"ws_delta"}),
            supports_sessions=True,
        )

    def build_request(self, prompt: str) -> PreparedRequest:
        # Shape the WebSocket upgrade handshake (origin-form http(s) URL). The
        # prompt is carried as the first message frame in the body.
        headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Content-Type": "application/json",
        }
        headers.update(self.extra_headers)
        body = json.dumps({"model": self.model, "message": prompt}).encode("utf-8")
        return PreparedRequest(method="GET", url=self.target.url, headers=headers, body=body)

    def extract(self, response: Any) -> str:
        if getattr(response, "truncated", False):
            raise ExtractionError("WebSocket transcript was byte-truncated (inconclusive)")
        pieces: list[str] = []
        complete = False
        for line in response.body.replace("\r\n", "\n").split("\n"):
            if not line.strip():
                continue
            try:
                frame = json.loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ExtractionError("malformed WebSocket frame") from exc
            if not isinstance(frame, dict):
                raise ExtractionError("WebSocket frame must be a JSON object")
            if frame.get("error") is not None:
                raise ExtractionError("WebSocket stream delivered an error frame")
            if frame.get("type") == "done" or frame.get("done") is True:
                complete = True
                break
            delta = _dig(frame, self.delta_path)
            if not isinstance(delta, str):
                raise ExtractionError("WebSocket frame does not contain the configured delta")
            pieces.append(delta)
            if sum(len(p) for p in pieces) >= self.max_chars:
                # Hit the bound before the done frame → truncated, not complete.
                raise ExtractionError(
                    "WebSocket stream exceeded max_chars before done (truncated; inconclusive)"
                )
        if not complete:
            raise ExtractionError("WebSocket stream did not terminate (no done frame)")
        return "".join(pieces)[: self.max_chars]

    @contextmanager
    def session(self) -> Iterator[WebSocketAdapter]:
        try:
            yield self
        finally:
            pass
