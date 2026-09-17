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

from ai_scan.transport._errors import BudgetExceededError, ScopeError, TransportError
from ai_scan.transport.budgets import AttemptKind, BudgetLedger
from ai_scan.transport.scope_guard import ResolvedEndpoint, ScopeGuard

_DEFAULT_PORTS = {"http": 80, "https": 443}
# Response-body read chunk (bytes); small enough that a slow-drip body is caught
# by the wall-clock deadline check between chunks.
_READ_CHUNK = 8192


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow any redirect (fail-closed scope)."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def build_scoped_opener() -> urllib.request.OpenerDirector:
    """Build the only opener the transport/broker may use.

    Two safety properties are baked in and never left to ambient state:

    * ``ProxyHandler({})`` — an **empty** proxy map disables urllib's default
      environment-aware proxying, so an ambient ``http_proxy`` / ``HTTPS_PROXY``
      (any case) can never divert a request away from the scope-vetted, pinned
      destination or forward the target credential to a third party. Proxy
      support, if ever wanted, must be an explicit transport feature with a
      documented destination/trust contract, never inherited silently.
    * :class:`_NoRedirect` — no 3xx is ever followed (scope fails closed).
    """
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


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
        self.__opener = opener or build_scoped_opener()

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
                # Resolution consumed real time; a slow resolver must not permit
                # a connection to be opened after the run deadline has passed.
                self._ledger.check_deadline()
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

        timeout = self._connect_timeout()
        try:
            raw = self.__opener.open(request, timeout=timeout)
            with contextlib.closing(raw):
                status = raw.status
                resp_headers = {k: v for k, v in raw.headers.items()}
                payload = self._read_within_deadline(raw)
        except urllib.error.HTTPError as http_err:
            # Non-2xx (including our captured redirects) arrive here.
            with contextlib.closing(http_err):
                status = http_err.code
                resp_headers = (
                    {k: v for k, v in http_err.headers.items()} if http_err.headers else {}
                )
                payload = self._read_within_deadline(http_err)
        # Keep the final state transition fail-closed even if a response object
        # has unusual read semantics: expired bytes never become RawExchange.
        self._ledger.check_deadline()
        return RawExchange(status=status, headers=resp_headers, payload=payload)

    def _connect_timeout(self) -> float:
        """Socket timeout for this attempt, clamped to the remaining deadline."""
        remaining = self._ledger.remaining()
        if remaining is None:
            return self._timeout
        if remaining <= 0:
            raise BudgetExceededError("time budget exceeded before connect")
        return min(self._timeout, remaining)

    def _read_within_deadline(self, response: object) -> bytes:
        """Read the body in chunks, bounded by both the byte and time budgets.

        A slow-drip body can stay under both the per-read socket timeout and the
        byte cap while overrunning the run's wall-clock deadline. Reading in
        chunks and re-checking the deadline between them makes expired work fail
        closed (``BudgetExceededError``) rather than complete as a usable 2xx.
        """
        limit = self._max_response_bytes + 1
        if self._ledger.remaining() is None:
            whole: bytes = response.read(limit)  # type: ignore[attr-defined]
            return whole
        # ``read1`` returns data from a single underlying recv, so a slow-drip
        # body yields control between chunks (a plain ``read(n)`` would block for
        # the full content-length). Fall back to bounded ``read`` when a response
        # object (e.g. some error bodies) does not expose ``read1``.
        read1 = getattr(response, "read1", None)
        read = read1 if read1 is not None else response.read  # type: ignore[attr-defined]
        chunks: list[bytes] = []
        total = 0
        while total < limit:
            self._ledger.check_deadline()
            chunk = read(min(_READ_CHUNK, limit - total))
            # A blocking read can cross the absolute deadline.  Check after
            # every read, including terminal EOF, before using its result.
            self._ledger.check_deadline()
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)


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
