"""Captured-HTTP adapter: safe replay and fail-closed parsing.

Covers the boundary/malformed cases from the M5 acceptance matrix — conflicting
authority, Content-Length mismatch, header injection (bare CR/NUL/obs-fold),
duplicate headers, Transfer-Encoding, absolute-form targets, CRLF vs LF, and the
explicit marker requirement — plus positive GET/POST replay bound to the
in-scope target.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from ai_scan.adapters import AdapterConfigError, CapturedHttpAdapter, parse_captured_request
from ai_scan.targets import normalize_target
from ai_scan.transport import RequestController, Transport, TransportConfig

TARGET = normalize_target("http://127.0.0.1:8080/chat")


def _raw(lines: list[str], body: str = "", *, eol: str = "\r\n") -> str:
    head = eol.join(lines)
    return f"{head}{eol}{eol}{body}"


# --- positive replay ------------------------------------------------------------

def test_post_capture_replays_shape_bound_to_in_scope_target() -> None:
    raw = _raw(
        ["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", "Content-Type: application/json"],
        '{"input": "*"}',
    )
    adapter = CapturedHttpAdapter(target=TARGET, raw_request=raw)
    prepared = adapter.build_request("PING")
    assert prepared.method == "POST"
    assert prepared.url == "http://127.0.0.1:8080/chat"
    assert prepared.body == b'{"input": "PING"}'
    # Transport-managed headers are dropped; Content-Type is preserved.
    assert prepared.headers["Content-Type"] == "application/json"
    assert "Host" not in prepared.headers
    assert "Content-Length" not in prepared.headers


def test_get_capture_marker_in_path_is_url_encoded() -> None:
    target = normalize_target("http://127.0.0.1:8080/s")
    raw = _raw(["GET /s?q=* HTTP/1.1", "Host: 127.0.0.1:8080"])
    prepared = CapturedHttpAdapter(target=target, raw_request=raw).build_request("a b&c")
    assert prepared.method == "GET"
    assert prepared.body is None
    assert prepared.url == "http://127.0.0.1:8080/s?q=a%20b%26c"


def test_lf_only_line_endings_are_accepted() -> None:
    raw = _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080"], '{"in":"*"}', eol="\n")
    prepared = CapturedHttpAdapter(target=TARGET, raw_request=raw).build_request("x")
    assert prepared.body == b'{"in":"x"}'


def test_raw_marker_mode_is_verbatim() -> None:
    raw = _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080"], "prefix:*")
    prepared = CapturedHttpAdapter(
        target=TARGET, raw_request=raw, prompt_encoding="raw"
    ).build_request('x"y')
    assert prepared.body == b'prefix:x"y'


def test_matching_content_length_is_accepted() -> None:
    body = '{"in":"*"}'
    raw = _raw(
        ["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", f"Content-Length: {len(body)}"], body
    )
    tmpl = parse_captured_request(raw, TARGET)
    assert tmpl.marker_in_body is True


# --- fail-closed parsing --------------------------------------------------------

@pytest.mark.parametrize(
    "raw",
    [
        # absolute-form request target → arbitrary destination
        _raw(["POST http://evil.example/chat HTTP/1.1", "Host: 127.0.0.1:8080"], "*"),
        # authority-form / non-origin target
        _raw(["POST chat HTTP/1.1", "Host: 127.0.0.1:8080"], "*"),
        # conflicting Host
        _raw(["POST /chat HTTP/1.1", "Host: evil.example:8080"], "*"),
        # duplicate header
        _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", "X-A: 1", "X-A: 2"], "*"),
        # transfer-encoding smuggling
        _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", "Transfer-Encoding: chunked"], "*"),
        # content-length mismatch
        _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", "Content-Length: 999"], "*"),
        # obs-fold continuation line
        _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", "X-A: 1", " folded"], "*"),
        # missing colon in header
        _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080", "BadHeaderLine"], "*"),
        # disallowed method
        _raw(["DELETE /chat HTTP/1.1", "Host: 127.0.0.1:8080"], "*"),
        # malformed request line
        _raw(["POST /chat", "Host: 127.0.0.1:8080"], "*"),
        # no marker anywhere
        _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080"], '{"in":"x"}'),
    ],
)
def test_malformed_capture_fails_closed(raw: str) -> None:
    with pytest.raises(AdapterConfigError):
        CapturedHttpAdapter(target=TARGET, raw_request=raw)


def test_bare_cr_is_rejected() -> None:
    raw = "POST /chat HTTP/1.1\nHost: 127.0.0.1:8080\rX-Injected: 1\n\n*"
    with pytest.raises(AdapterConfigError):
        CapturedHttpAdapter(target=TARGET, raw_request=raw)


def test_nul_byte_is_rejected() -> None:
    raw = "POST /chat HTTP/1.1\nHost: 127.0.0.1:8080\n\n{\"in\":\"*\x00\"}"
    with pytest.raises(AdapterConfigError):
        CapturedHttpAdapter(target=TARGET, raw_request=raw)


def test_empty_capture_is_rejected() -> None:
    with pytest.raises(AdapterConfigError):
        CapturedHttpAdapter(target=TARGET, raw_request="   ")


# --- session + end-to-end -------------------------------------------------------

def test_session_is_always_finalized_even_on_error() -> None:
    raw = _raw(["POST /chat HTTP/1.1", "Host: 127.0.0.1:8080"], '{"in":"*"}')
    adapter = CapturedHttpAdapter(target=TARGET, raw_request=raw)
    with pytest.raises(RuntimeError):
        with adapter.session() as active:
            assert active is adapter
            raise RuntimeError("boom")
    # A second session still opens cleanly (no leaked state).
    with adapter.session() as active:
        assert active is adapter


def test_captured_adapter_round_trips_through_real_transport(echo_server: Any) -> None:
    target = normalize_target(f"{echo_server.base_url}/chat")
    host = f"{echo_server.host}:{echo_server.port}"
    raw = _raw(["POST /chat HTTP/1.1", f"Host: {host}", "Content-Type: application/json"],
               '{"input": "*"}')
    adapter = CapturedHttpAdapter(target=target, raw_request=raw)
    transport = Transport(TransportConfig(), controller=RequestController(max_requests=4))
    resp = transport.send_prepared(target, adapter.build_request("PING"))
    echoed = json.loads(resp.body)
    assert echoed["method"] == "POST"
    assert json.loads(echoed["body"])["input"] == "PING"
