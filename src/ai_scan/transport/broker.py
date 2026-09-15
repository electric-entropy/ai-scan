"""The sole request broker: every physical attempt flows through here.

No adapter or plugin is ever handed a raw network client. They call
:meth:`RequestBroker.fetch`, which — once per physical attempt and *before any
socket I/O* —

1. acquires request, rate, time, and concurrency budget (via the ledger), then
2. re-checks the target scope against the host's freshly resolved IPs (via
   the scope guard), then
3. connects to the *vetted* IP (pinning the connection to the address the guard
   validated, so a rebinding between check and connect cannot escape scope).

Budget exhaustion and scope denial surface as structured
:class:`BudgetExceededError` / :class:`ScopeError` carrying the accurate
per-kind physical totals. The urllib opener is name-mangled and never exposed.
"""

from __future__ import annotations

import contextlib
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from ai_scan.transport._errors import ScopeError, TransportError
from ai_scan.transport.budgets import AttemptKind, BudgetLedger
from ai_scan.transport.scope_guard import ResolvedEndpoint, ScopeGuard

_DEFAULT_PORTS = {"http": 80, "https": 443}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow any redirect (fail-closed scope)."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


@dataclass
class RawExchange:
    """The unshaped result of one physical attempt (redaction happens above)."""

    status: int
    headers: dict[str, str]
    payload: bytes


class RequestBroker:
    """Mediates, budgets, and scope-checks every physical network attempt."""

    def __init__(
        self,
        *,
        ledger: BudgetLedger,
        guard: ScopeGuard,
        timeout: float,
        max_response_bytes: int,
        opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        self._ledger = ledger
        self._guard = guard
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        # Name-mangled: adapters/plugins holding a broker cannot reach the opener.
        self.__opener = opener or urllib.request.build_opener(_NoRedirect)

    @property
    def totals(self) -> dict[str, int]:
        """Per-kind physical-attempt totals (the parts sum to ``total``)."""
        return self._ledger.totals()

    def fetch(
        self,
        *,
        url: str,
        method: str,
        data: bytes | None,
        headers: dict[str, str],
        kind: AttemptKind,
    ) -> RawExchange:
        """Perform one budgeted, scope-checked physical attempt of ``kind``.

        Raises:
            BudgetExceededError: If any budget (count/rate/time/concurrency) is
                exhausted — no socket I/O occurs.
            ScopeError: If the URL or its resolved IPs leave the target
                scope — no socket I/O occurs.
            TransportError: On a connection/timeout failure.

        Budget/scope denials carry accurate per-kind ``totals``.
        """
        try:
            with self._ledger.attempt(kind):
                # Budget is now held; scope is re-checked before any connection.
                endpoint = self._guard.check(url)
                return self._perform(endpoint, url, method, data, headers)
        except TransportError as exc:
            if exc.totals is None:
                exc.totals = self._ledger.totals()
            raise

    def _perform(
        self,
        endpoint: ResolvedEndpoint,
        url: str,
        method: str,
        data: bytes | None,
        headers: dict[str, str],
    ) -> RawExchange:
        connect_url, req_headers = _pin_connection(endpoint, url, headers)
        request = urllib.request.Request(connect_url, data=data, method=method)
        for key, value in req_headers.items():
            request.add_header(key, value)

        try:
            raw = self.__opener.open(request, timeout=self._timeout)
            with contextlib.closing(raw):
                status = raw.status
                resp_headers = {k: v for k, v in raw.headers.items()}
                payload = raw.read(self._max_response_bytes + 1)
        except urllib.error.HTTPError as http_err:
            # Non-2xx (including our captured redirects) arrive here.
            with contextlib.closing(http_err):
                status = http_err.code
                resp_headers = (
                    {k: v for k, v in http_err.headers.items()} if http_err.headers else {}
                )
                payload = http_err.read(self._max_response_bytes + 1)
        return RawExchange(status=status, headers=resp_headers, payload=payload)


def _target_authority(endpoint: ResolvedEndpoint) -> str:
    """The ``Host`` authority of the in-scope target (host[:non-default-port])."""
    target = endpoint.target
    host = f"[{target.host}]" if ":" in target.host else target.host
    if target.port != _DEFAULT_PORTS[target.scheme]:
        return f"{host}:{target.port}"
    return host


def _pin_connection(
    endpoint: ResolvedEndpoint, url: str, headers: dict[str, str]
) -> tuple[str, dict[str, str]]:
    """Rewrite the connection to the vetted IP and pin ``Host`` from the target.

    The ``Host`` header is transport-managed authority: a caller/adapter may not
    supply it (a forged ``Host`` could reach an unintended virtual host behind
    the target origin), so any supplied ``Host`` is rejected and the broker
    sets ``Host`` from the *in-scope target* itself.

    For an IP-literal target the URL already *is* the vetted address, so it is
    returned unchanged (an IP-literal HTTPS target is likewise safe — no name to
    re-resolve). For a named host over http, the authority is rewritten to the
    guard-validated IP, so the socket cannot connect anywhere the guard did not
    vet (closing the resolve→connect rebinding window).

    A named host over **https** is rejected: urllib would re-resolve the
    hostname during the TLS connect, reopening the rebinding window, and
    rewriting the authority to the IP would break SNI and certificate hostname
    validation. We fail closed until SNI/cert-preserving IP pinning is
    implemented, rather than connect to an unvetted address.
    """
    req_headers = {k: v for k, v in headers.items() if k.lower() != "host"}
    if len(req_headers) != len(headers):
        raise ScopeError(
            "a caller-supplied Host header is not permitted; Host is pinned from "
            "the in-scope target at the broker boundary"
        )
    authority = _target_authority(endpoint)
    if endpoint.host_is_literal:
        req_headers["Host"] = authority
        return url, req_headers
    if endpoint.target.scheme != "http":
        raise ScopeError(
            "named-host HTTPS is not supported: the TLS connection cannot be "
            "pinned to the scope-validated IP without breaking SNI/certificate "
            "validation; use an IP-literal target"
        )

    parts = urlsplit(url)
    ip_authority = f"[{endpoint.ip}]" if endpoint.family == 6 else endpoint.ip
    if endpoint.target.port != _DEFAULT_PORTS[endpoint.target.scheme]:
        ip_authority = f"{ip_authority}:{endpoint.target.port}"
    pinned_url = urlunsplit(
        (parts.scheme, ip_authority, parts.path, parts.query, parts.fragment)
    )
    req_headers["Host"] = authority
    return pinned_url, req_headers
