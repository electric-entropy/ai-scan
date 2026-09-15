"""Captured-HTTP adapter — replay a Burp-style raw request, safely.

Parses a raw HTTP/1.1 request (request line + headers + body) and replays its
*shape* (method, path, headers, body, explicit ``*`` marker location) against
the **in-scope** target. The captured authority is never trusted for routing,
so a capture cannot smuggle traffic to another destination. Parsing fails closed
(raising :class:`AdapterConfigError`, zero requests) on:

* absolute-form / authority-form request targets (arbitrary destination),
* a ``Host`` header that conflicts with the in-scope target,
* bare CR, NUL, obs-fold continuation lines, or control chars (header injection),
* duplicate header names (ambiguous),
* ``Transfer-Encoding`` (unsupported; classic smuggling vector),
* a ``Content-Length`` that disagrees with the captured body length,
* a missing ``*`` marker (the prompt would have nowhere to land).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

from ai_scan.adapters.base import (
    MARKER,
    AdapterCapabilities,
    AdapterConfigError,
    ExtractionSpec,
    PreparedRequest,
    extract_text,
)
from ai_scan.targets import Target
from ai_scan.transport import ACTIVE_METHODS, HttpResponse, scrub_text
from ai_scan.transport.http import _apply_marker, _encode_prompt

_DEFAULT_PORTS = {"http": 80, "https": 443}
_VALID_ENCODINGS = frozenset({"json", "url", "raw"})
# RFC 7230 token characters for a header field-name.
_TOKEN_CHARS = frozenset(
    "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)
_MANAGED_HEADERS = frozenset({"host", "content-length"})

# Static, offline capability descriptor (discoverable without a target/config).
CAPABILITIES = AdapterCapabilities(
    name="captured_http",
    methods=frozenset(ACTIVE_METHODS),
    prompt_encodings=frozenset(_VALID_ENCODINGS),
    extraction_modes=frozenset({"text", "json_pointer", "header"}),
    supports_sessions=False,
)


@dataclass(frozen=True)
class CapturedTemplate:
    """A parsed, validated captured request (shape only; bound to a target)."""

    method: str
    request_target: str
    headers: Mapping[str, str]
    body: str
    marker_in_path: bool
    marker_in_body: bool


def _authority(target: Target) -> str:
    host = f"[{target.host}]" if ":" in target.host else target.host
    if target.port == _DEFAULT_PORTS[target.scheme]:
        return host
    return f"{host}:{target.port}"


def parse_captured_request(raw: str, target: Target) -> CapturedTemplate:
    """Parse and validate ``raw`` against ``target``; fail closed on any ambiguity."""
    if not isinstance(raw, str) or not raw.strip():
        raise AdapterConfigError("captured request is empty")

    normalized = raw.replace("\r\n", "\n")
    if "\r" in normalized:
        raise AdapterConfigError("captured request contains a bare CR (possible header injection)")
    if "\x00" in normalized:
        raise AdapterConfigError("captured request contains a NUL byte")

    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    method, request_target = _parse_request_line(lines[0])
    headers = _parse_headers(lines[1:])

    _check_authority(headers, target)
    if any(k.lower() == "transfer-encoding" for k in headers):
        raise AdapterConfigError("Transfer-Encoding is not supported (smuggling vector)")
    _check_content_length(headers, body)

    marker_in_path = MARKER in request_target
    marker_in_body = MARKER in body
    if not (marker_in_path or marker_in_body):
        raise AdapterConfigError("captured request must contain the '*' prompt marker")

    return CapturedTemplate(
        method=method,
        request_target=request_target,
        headers=headers,
        body=body,
        marker_in_path=marker_in_path,
        marker_in_body=marker_in_body,
    )


def _parse_request_line(line: str) -> tuple[str, str]:
    parts = line.split(" ")
    if len(parts) != 3:
        raise AdapterConfigError("malformed request line (expected 'METHOD TARGET VERSION')")
    given_method, request_target, version = parts
    method = given_method.upper()
    if method not in ACTIVE_METHODS:
        raise AdapterConfigError(
            f"captured method {scrub_text(given_method)!r} is not permitted; allowed: "
            f"{', '.join(sorted(ACTIVE_METHODS))}"
        )
    if not version.startswith("HTTP/"):
        raise AdapterConfigError("malformed HTTP version in request line")
    if "://" in request_target or not request_target.startswith("/"):
        raise AdapterConfigError(
            "request target must be origin-form ('/path'); absolute/authority form "
            "would allow an arbitrary destination"
        )
    return method, request_target


def _parse_headers(header_lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for line in header_lines:
        if not line:
            continue
        if line[0] in (" ", "\t"):
            raise AdapterConfigError("obsolete header line folding is not allowed")
        name, sep, value = line.partition(":")
        if not sep:
            raise AdapterConfigError("malformed header line (missing ':')")
        name = name.strip()
        value = value.strip()
        if not name or any(c not in _TOKEN_CHARS for c in name):
            raise AdapterConfigError("invalid header name")
        if any((ord(c) < 32 and c != "\t") or ord(c) == 127 for c in value):
            raise AdapterConfigError("invalid control character in header value")
        low = name.lower()
        if low in seen:
            raise AdapterConfigError(
                f"duplicate header {scrub_text(name)!r} is not allowed (ambiguous)"
            )
        seen.add(low)
        headers[name] = value
    return headers


def _check_authority(headers: dict[str, str], target: Target) -> None:
    host_values = [v for k, v in headers.items() if k.lower() == "host"]
    if not host_values:
        return
    expected = _authority(target)
    if host_values[0].strip().lower() != expected.lower():
        raise AdapterConfigError("captured Host header conflicts with the in-scope target")


def _check_content_length(headers: dict[str, str], body: str) -> None:
    cl_values = [v for k, v in headers.items() if k.lower() == "content-length"]
    if not cl_values:
        return
    raw = cl_values[0].strip()
    if not raw.isdigit():
        raise AdapterConfigError("Content-Length is not a non-negative integer")
    if int(raw) != len(body.encode("utf-8")):
        raise AdapterConfigError("Content-Length disagrees with the captured body length")


@dataclass
class CapturedHttpAdapter:
    """Replays a parsed captured request against the in-scope target."""

    target: Target
    raw_request: str
    prompt_encoding: str | None = None
    extraction: ExtractionSpec = field(default_factory=ExtractionSpec)
    _template: CapturedTemplate = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if self.prompt_encoding is not None and self.prompt_encoding not in _VALID_ENCODINGS:
            raise AdapterConfigError(
                f"unknown prompt encoding {scrub_text(str(self.prompt_encoding))!r}; "
                f"allowed: {', '.join(sorted(_VALID_ENCODINGS))}"
            )
        self._template = parse_captured_request(self.raw_request, self.target)

    def capabilities(self) -> AdapterCapabilities:
        return CAPABILITIES

    def build_request(self, prompt: str) -> PreparedRequest:
        tmpl = self._template
        path = tmpl.request_target
        body = tmpl.body
        if tmpl.marker_in_path:
            path = _apply_marker(path, _encode_prompt(prompt, self.prompt_encoding or "url"))
        if tmpl.marker_in_body:
            body = _apply_marker(body, _encode_prompt(prompt, self.prompt_encoding or "json"))

        url = f"{self.target.scheme}://{_authority(self.target)}{path}"
        # Drop transport-managed headers; urllib sets Host (from the URL) and
        # Content-Length (from the body) for the actual, post-substitution bytes.
        headers = {
            name: value
            for name, value in tmpl.headers.items()
            if name.lower() not in _MANAGED_HEADERS
        }
        body_bytes = None if tmpl.method == "GET" else body.encode("utf-8")
        return PreparedRequest(method=tmpl.method, url=url, headers=headers, body=body_bytes)

    def extract(self, response: HttpResponse) -> str:
        return extract_text(response, self.extraction)

    @contextmanager
    def session(self) -> Iterator[CapturedHttpAdapter]:
        try:
            yield self
        finally:
            pass
