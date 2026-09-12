"""Deterministic broker test doubles (no real sockets).

Shared by the broker unit tests and the egress/budget security tests so the
physical-attempt invariants can be exercised precisely and fast.
"""

from __future__ import annotations

import urllib.error
from typing import Any


class FakeResponse:
    """Minimal stand-in for a urllib response object."""

    def __init__(self, status: int = 200, headers: dict[str, str] | None = None,
                 body: bytes = b"{}") -> None:
        self.status = status
        self._headers = headers or {}
        self._body = body
        self.closed = False

    @property
    def headers(self) -> Any:
        return _Headers(self._headers)

    def read(self, amount: int) -> bytes:
        return self._body[:amount]

    def close(self) -> None:
        self.closed = True


class _Headers:
    def __init__(self, data: dict[str, str]) -> None:
        self._data = data

    def items(self) -> Any:
        return self._data.items()


class RecordingOpener:
    """Records every ``open`` so tests can assert whether I/O happened."""

    def __init__(self, response: FakeResponse | None = None,
                 error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._response = response or FakeResponse()
        self._error = error

    def open(self, request: Any, timeout: float | None = None) -> Any:
        self.calls.append(
            {
                "url": request.full_url,
                "method": request.get_method(),
                "headers": dict(request.header_items()),
                "timeout": timeout,
            }
        )
        if self._error is not None:
            raise self._error
        return self._response


def http_error(status: int, headers: dict[str, str], body: bytes) -> urllib.error.HTTPError:
    """Build an HTTPError the broker will capture as a non-2xx/redirect."""
    import email.message

    msg = email.message.Message()
    for key, value in headers.items():
        msg[key] = value
    return urllib.error.HTTPError("http://mock.local/", status, "x", msg, _BytesIO(body))


class _BytesIO:
    """A tiny readable/closeable shim for HTTPError bodies."""

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, amount: int) -> bytes:
        return self._body[:amount]

    def close(self) -> None:
        return None
