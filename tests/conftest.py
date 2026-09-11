"""Shared pytest fixtures: local in-process mock HTTP targets.

All network tests hit loopback servers only. Each server is deterministic and
represents a specific behavior the tool must handle safely (echo, redirect,
oversized response, canary-following vulnerable app, resistant app).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

Handler = Callable[["MockRequest"], "MockResponse"]


@dataclass
class MockRequest:
    """A parsed inbound request handed to a mock behavior callable."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass
class MockResponse:
    """The response a mock behavior returns."""

    status: int = 200
    body: bytes = b""
    headers: dict[str, str] | None = None


@dataclass
class MockServer:
    """A running loopback server plus the base URL to reach it."""

    base_url: str
    host: str
    port: int


def _make_server(behavior: Handler) -> tuple[ThreadingHTTPServer, threading.Thread]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:  # silence test noise
            pass

        def _dispatch(self) -> None:
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            req = MockRequest(
                method=self.command,
                path=self.path,
                headers={k: v for k, v in self.headers.items()},
                body=body,
            )
            resp = behavior(req)
            self.send_response(resp.status)
            for key, value in (resp.headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

        def do_GET(self) -> None:
            self._dispatch()

        def do_POST(self) -> None:
            self._dispatch()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture
def mock_server() -> Iterator[Callable[[Handler], MockServer]]:
    """Factory fixture: start a loopback server for a given behavior callable."""
    started: list[ThreadingHTTPServer] = []

    def factory(behavior: Handler) -> MockServer:
        server, _thread = _make_server(behavior)
        started.append(server)
        host, port = server.server_address[0], server.server_address[1]
        return MockServer(base_url=f"http://{host}:{port}", host=str(host), port=int(port))

    yield factory

    for server in started:
        server.shutdown()
        server.server_close()


@pytest.fixture
def echo_server(mock_server) -> MockServer:
    """Server that echoes request method, path, headers, and body as JSON."""

    def behavior(req: MockRequest) -> MockResponse:
        payload = {
            "method": req.method,
            "path": req.path,
            "headers": req.headers,
            "body": req.text,
        }
        return MockResponse(
            status=200,
            body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    return mock_server(behavior)
