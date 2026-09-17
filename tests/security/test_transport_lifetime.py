"""Phase 1A transport-lifetime regressions (Astra H1, M1, M2).

Real-runtime coverage against loopback servers, converted from the reviewer's
``/tmp/ai_scan_transport_review.py`` reproductions:

* **H1** — an ambient ``*_proxy`` environment variable must not divert a request
  away from the vetted, scope-pinned destination or forward its credential.
* **M1** — one target-bound DNS/rebinding pin survives the whole transport
  lifetime: a changed resolver answer fails *before* a second connection.
* **M2** — one monotonic absolute deadline bounds resolution and response-body
  consumption; expired/partial work is unusable (never a clean 2xx).

Negative controls (ordinary loopback, IPv6 loopback, stable DNS) prove the
guards do not break normal local access.
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.error
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import pytest

from ai_scan.adapters.base import PreparedRequest
from ai_scan.targets import normalize_target
from ai_scan.transport._errors import BudgetExceededError, ScopeError
from ai_scan.transport.broker import RequestBroker
from ai_scan.transport.budgets import BudgetLedger
from ai_scan.transport.http import Transport, TransportConfig
from ai_scan.transport.scope_guard import ResolvedEndpoint, ScopeGuard


def _make_handler(hits: list[dict[str, object]]) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:  # silence
            pass

        def do_GET(self) -> None:  # noqa: N802
            hits.append(
                {
                    "addr": self.server.server_address,
                    "path": self.path,
                    "auth": self.headers.get("Authorization"),
                }
            )
            if self.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "10")
                self.end_headers()
                for _ in range(10):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.08)
                return
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    return _Handler


def _serve(
    hits: list[dict[str, object]], host: str = "127.0.0.1", family: int = socket.AF_INET
) -> ThreadingHTTPServer:
    class _Server(ThreadingHTTPServer):
        address_family = family

    srv = _Server((host, 0), _make_handler(hits))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def target_server() -> Iterator[tuple[ThreadingHTTPServer, list[dict[str, object]]]]:
    hits: list[dict[str, object]] = []
    srv = _serve(hits)
    try:
        yield srv, hits
    finally:
        srv.shutdown()
        srv.server_close()


# --- H1: ambient proxies must not divert the vetted destination ---------------


@pytest.mark.parametrize("proxy_var", ["http_proxy", "HTTP_PROXY"])
def test_ambient_proxy_cannot_divert_target_or_forward_credential(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
    proxy_var: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target_srv, target_hits = target_server
    proxy_hits: list[dict[str, object]] = []
    proxy_srv = _serve(proxy_hits)
    try:
        monkeypatch.setenv(proxy_var, f"http://127.0.0.1:{proxy_srv.server_port}")
        monkeypatch.setenv("no_proxy", "")
        target = normalize_target(f"http://127.0.0.1:{target_srv.server_port}/")
        transport = Transport(TransportConfig(max_retries=0))
        resp = transport.send(
            target,
            method="GET",
            prompt="",
            headers={"Authorization": "Bearer local-review-dummy"},
        )
        assert resp.status == 200
        # The vetted target received exactly one request; the proxy received none.
        assert len(target_hits) == 1
        assert proxy_hits == []
        # And the credential was never forwarded to the proxy.
        assert all("local-review-dummy" not in str(h.get("auth")) for h in proxy_hits)
    finally:
        proxy_srv.shutdown()
        proxy_srv.server_close()


def test_no_proxy_ordinary_loopback_still_works(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    target_srv, target_hits = target_server
    target = normalize_target(f"http://127.0.0.1:{target_srv.server_port}/")
    resp = Transport(TransportConfig(max_retries=0)).send(target, method="GET", prompt="")
    assert resp.status == 200 and resp.ok
    assert len(target_hits) == 1


def test_ipv6_loopback_positive_control(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("http_proxy", raising=False)
    monkeypatch.delenv("HTTP_PROXY", raising=False)
    hits: list[dict[str, object]] = []
    try:
        srv = _serve(hits, host="::1", family=socket.AF_INET6)
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    try:
        target = normalize_target(f"http://[0:0:0:0:0:0:0:1]:{srv.server_port}/")
        resp = Transport(TransportConfig(max_retries=0)).send(target, method="GET", prompt="")
        assert resp.status == 200
    finally:
        srv.shutdown()
        srv.server_close()


# --- M1: one target-bound DNS pin survives the transport lifetime -------------


def test_dns_rebinding_rejected_across_sends_on_one_transport(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
) -> None:
    target_srv, hits = target_server
    port = target_srv.server_port
    answers = iter([["127.0.0.1"], ["127.0.0.2"]])
    transport = Transport(
        TransportConfig(max_retries=0),
        resolver=lambda _host: next(answers),
        allow_private=True,
    )
    named = normalize_target(f"http://review.invalid:{port}/")
    prepared = PreparedRequest("GET", named.url)
    # First send pins 127.0.0.1.
    assert transport.send_prepared(named, prepared).status == 200
    before = len(hits)
    # Second send resolves a *different* answer — rebinding must be rejected
    # before any second connection is attempted.
    with pytest.raises(ScopeError):
        transport.send_prepared(named, prepared)
    assert len(hits) == before


def test_stable_dns_allows_repeated_sends(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
) -> None:
    target_srv, hits = target_server
    port = target_srv.server_port
    transport = Transport(
        TransportConfig(max_retries=0),
        resolver=lambda _host: ["127.0.0.1"],
        allow_private=True,
    )
    named = normalize_target(f"http://review.invalid:{port}/")
    prepared = PreparedRequest("GET", named.url)
    assert transport.send_prepared(named, prepared).status == 200
    assert transport.send_prepared(named, prepared).status == 200
    assert len(hits) == 2


# --- M2: one monotonic absolute deadline bounds resolution + body reads --------


def test_slow_drip_body_over_duration_is_unusable(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
) -> None:
    target_srv, _hits = target_server
    slow = normalize_target(f"http://127.0.0.1:{target_srv.server_port}/slow")
    transport = Transport(
        TransportConfig(max_retries=0, timeout=0.15, max_duration_seconds=0.1)
    )
    started = time.monotonic()
    with pytest.raises(BudgetExceededError):
        transport.send(slow, method="GET", prompt="")
    # The drip (0.8s worth) must not be allowed to run to completion.
    assert time.monotonic() - started < 0.6


def test_slow_resolver_prevents_connection_after_deadline() -> None:
    hits: list[dict[str, object]] = []
    srv = _serve(hits)
    try:

        def _slow_resolver(_host: str) -> list[str]:
            time.sleep(0.2)
            return ["127.0.0.1"]

        transport = Transport(
            TransportConfig(max_retries=0, max_duration_seconds=0.05),
            resolver=_slow_resolver,
            allow_private=True,
        )
        named = normalize_target(f"http://review.invalid:{srv.server_port}/")
        with pytest.raises(BudgetExceededError):
            transport.send(named, method="GET", prompt="")
        # Resolution already blew the deadline: no socket I/O may occur.
        assert hits == []
    finally:
        srv.shutdown()
        srv.server_close()


def test_ordinary_request_within_generous_deadline_succeeds(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
) -> None:
    target_srv, _hits = target_server
    target = normalize_target(f"http://127.0.0.1:{target_srv.server_port}/")
    transport = Transport(TransportConfig(max_retries=0, max_duration_seconds=30.0))
    resp = transport.send(target, method="GET", prompt="")
    assert resp.status == 200 and resp.ok and resp.body == "OK"


class _InjectedClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _DeadlineCrossingBody:
    """A body whose terminal read crosses the absolute deadline."""

    status = 200
    headers: dict[str, str] = {}

    def __init__(self, clock: _InjectedClock) -> None:
        self._clock = clock

    def read(self, _size: int = -1) -> bytes:
        self._clock.now = 2.0
        return b""

    read1 = read

    def close(self) -> None:
        pass


class _SuccessOpener:
    def __init__(self, body: _DeadlineCrossingBody) -> None:
        self._body = body

    def open(self, *_args: object, **_kwargs: object) -> _DeadlineCrossingBody:
        return self._body


class _ErrorOpener(_SuccessOpener):
    def open(self, *_args: object, **_kwargs: object) -> _DeadlineCrossingBody:
        raise urllib.error.HTTPError(
            "http://127.0.0.1/", 500, "synthetic", {}, self._body
        )  # type: ignore[arg-type]


@pytest.mark.parametrize("error_body", [False, True])
def test_terminal_eof_crossing_deadline_is_unusable(error_body: bool) -> None:
    """Success and HTTP-error EOF reads are checked after the blocking read."""
    clock = _InjectedClock()
    ledger = BudgetLedger(max_requests=1, max_duration_seconds=1.0, clock=clock)
    # The perform-level regression isolates post-read enforcement; production
    # fetch establishes the same start time when it acquires the attempt.
    ledger._start = 0.0  # noqa: SLF001
    body = _DeadlineCrossingBody(clock)
    opener: object = _ErrorOpener(body) if error_body else _SuccessOpener(body)
    broker = RequestBroker(
        ledger=ledger,
        guard=cast(ScopeGuard, object()),
        timeout=5.0,
        max_response_bytes=1024,
        opener=cast(object, opener),  # type: ignore[arg-type]
    )
    target = normalize_target("http://127.0.0.1/")
    endpoint = ResolvedEndpoint(target, "127.0.0.1", 4, True)

    with pytest.raises(BudgetExceededError):
        broker._perform(endpoint, target.url, "GET", None, {})  # noqa: SLF001


# --- M1 (concurrency): the guard cache get-or-create must be atomic -----------


def _install_counting_guard(monkeypatch: pytest.MonkeyPatch, delay: float) -> list[int]:
    """Patch the guard used by ``_guard_for`` to count constructions.

    A short delay inside ``__init__`` widens the race window so a *missing* cache
    lock would deterministically mint more than one guard for a single target.
    """
    import ai_scan.transport.http as http_mod

    constructed: list[int] = []
    real_guard = http_mod.ScopeGuard

    class _CountingGuard(real_guard):  # type: ignore[valid-type, misc]
        def __init__(self, *args: object, **kwargs: object) -> None:
            time.sleep(delay)
            constructed.append(1)
            super().__init__(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(http_mod, "ScopeGuard", _CountingGuard)
    return constructed


def test_guard_cache_get_or_create_is_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    constructed = _install_counting_guard(monkeypatch, delay=0.02)
    transport = Transport(
        TransportConfig(max_retries=0),
        resolver=lambda _host: ["127.0.0.1"],
        allow_private=True,
    )
    target = normalize_target("http://review.invalid:8080/")

    n = 16
    barrier = threading.Barrier(n)
    results: list[object] = []
    results_lock = threading.Lock()

    def _worker() -> None:
        barrier.wait()
        guard = transport._guard_for(target)  # noqa: SLF001 - exercising the cache
        with results_lock:
            results.append(guard)

    threads = [threading.Thread(target=_worker) for _ in range(n)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    # Exactly one guard is constructed and every caller receives that same object.
    assert len(constructed) == 1
    assert len({id(guard) for guard in results}) == 1


def test_concurrent_sends_use_a_single_shared_guard(
    target_server: tuple[ThreadingHTTPServer, list[dict[str, object]]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    constructed = _install_counting_guard(monkeypatch, delay=0.01)
    target_srv, _hits = target_server
    port = target_srv.server_port
    transport = Transport(
        TransportConfig(max_retries=0, max_concurrency=8),
        resolver=lambda _host: ["127.0.0.1"],
        allow_private=True,
    )
    named = normalize_target(f"http://review.invalid:{port}/")
    errors: list[Exception] = []
    errors_lock = threading.Lock()
    barrier = threading.Barrier(6)

    def _worker() -> None:
        barrier.wait()
        try:
            resp = transport.send_prepared(named, PreparedRequest("GET", named.url))
            assert resp.status == 200
        except Exception as exc:  # noqa: BLE001 - recorded for the assertion below
            with errors_lock:
                errors.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    # All six concurrent sends shared exactly one guard for the target.
    assert len(constructed) == 1
