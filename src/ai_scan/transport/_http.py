"""Bounded, scope-safe HTTP transport built on the standard library.

Design constraints (all enforced here, not left to callers):

* Active requests use a non-destructive method allowlist (``GET``/``POST``).
* A required, positive timeout; a bounded maximum response size; a bounded
  retry count; an explicit user-agent; an enforced request-rate limit; and a
  single physical-request budget that counts every attempt, retries included.
* Redirects are **never followed** — any 3xx is captured as evidence so scope
  escape (e.g. a redirect to an unauthorized host) fails closed.
* Secrets are redacted from all stored evidence: sensitive request/response
  headers (matched by an explicit set *and* by token-bearing name patterns),
  secret-like query parameters in request URLs and redirect ``Location``
  values, and any known secret values reflected in a response body. Secrets
  never appear in exception strings.
* urllib response objects are always closed.

Prompt insertion uses a literal ``*`` marker so templates stay explicit about
where operator-controlled text lands.
"""

from __future__ import annotations

import contextlib
import json
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

from ai_scan.targets import Target
from ai_scan.transport.records import ExchangeRecord, build_exchange_record
from ai_scan.transport.redaction import (
    redact_headers,
    redact_url,
    scrub_text,
    sensitive_header_values,
    url_secret_values,
)

MARKER = "*"

# Non-destructive method allowlist for the MVP.
ACTIVE_METHODS = frozenset({"GET", "POST"})


class TransportError(Exception):
    """Raised on a transport-level failure. Never contains secret material."""


class BudgetExceededError(TransportError):
    """Raised when the physical-request budget is exhausted."""


@dataclass
class RequestController:
    """Enforces a physical-request budget and a minimum inter-request interval.

    ``acquire`` is called once per physical request attempt (including retries),
    so the same counter both enforces the budget and is reported. Time is taken
    from injected ``clock``/``sleeper`` callables so rate limiting is testable
    without real wall-clock delays.

    Attributes:
        max_requests: Hard cap on physical request attempts.
        min_interval: Minimum seconds between consecutive attempts.
        clock: Returns a monotonic timestamp in seconds.
        sleeper: Sleeps for the given number of seconds.
        count: Number of attempts acquired so far.
    """

    max_requests: int
    min_interval: float = 0.0
    clock: Callable[[], float] = time.monotonic
    sleeper: Callable[[float], None] = time.sleep
    count: int = 0
    _last: float | None = field(default=None, repr=False)

    def acquire(self) -> None:
        """Reserve one physical request, enforcing budget then rate.

        Raises:
            BudgetExceededError: If the budget is already exhausted.
        """
        if self.count >= self.max_requests:
            raise BudgetExceededError(
                f"request budget of {self.max_requests} exhausted"
            )
        if self.min_interval > 0 and self._last is not None:
            wait = self.min_interval - (self.clock() - self._last)
            if wait > 0:
                self.sleeper(wait)
        self._last = self.clock()
        self.count += 1


@dataclass(frozen=True)
class TransportConfig:
    """Bounds and identity for the transport.

    Attributes:
        timeout: Per-request timeout in seconds (must be > 0).
        max_response_bytes: Response body is truncated to this many bytes.
        user_agent: ``User-Agent`` header sent on every request.
        max_retries: Extra attempts on transient connection errors.
        max_requests: Physical-request budget when no controller is supplied.
        min_interval_seconds: Minimum seconds between physical requests.
    """

    timeout: float = 15.0
    max_response_bytes: int = 262_144
    user_agent: str = "ai-scan/0.1 (authorized-assessment)"
    max_retries: int = 2
    max_requests: int = 64
    min_interval_seconds: float = 0.0

    def __post_init__(self) -> None:
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if self.max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be positive")
        if self.min_interval_seconds < 0:
            raise ValueError("min_interval_seconds must be non-negative")


@dataclass
class HttpResponse:
    """A captured HTTP response plus redacted request evidence.

    Attributes:
        status: HTTP status code.
        body: Response body decoded as text, truncated to the byte bound.
        headers: Response headers (sensitive values redacted).
        redirected: Whether the response was a redirect (3xx).
        redirect_location: The ``Location`` header, secret-redacted, if any
            (captured, never followed).
        truncated: Whether the body was truncated at the size bound.
        request_line: ``{method, url}`` of the request (URL secret-redacted).
        request_headers: Request headers with sensitive values redacted.
        attempts: Physical attempts made for this request (>= 1).
        ok: Whether a usable 2xx response was obtained (not redirect/error/
            truncated).
    """

    status: int
    body: str
    headers: dict[str, str]
    redirected: bool
    redirect_location: str | None
    truncated: bool
    request_line: dict[str, str]
    request_headers: dict[str, str] = field(default_factory=dict)
    attempts: int = 1
    known_secrets: frozenset[str] = field(default_factory=frozenset)

    @property
    def ok(self) -> bool:
        """True only for a clean, usable 2xx response."""
        return 200 <= self.status < 300 and not self.redirected and not self.truncated

    def evidence(self) -> dict[str, Any]:
        """Return a JSON-serializable, secret-free evidence record."""
        return {
            "request": {
                "method": self.request_line.get("method", ""),
                "url": self.request_line.get("url", ""),
                "headers": dict(self.request_headers),
            },
            "response": {
                "status": self.status,
                "redirected": self.redirected,
                "redirect_location": self.redirect_location,
                "truncated": self.truncated,
                "headers": dict(self.headers),
                "body": self.body,
            },
        }

    def to_record(self) -> ExchangeRecord:
        """Build an immutable, redaction-complete canonical exchange record.

        Fields are already redacted on this object; :func:`build_exchange_record`
        re-applies central redaction (idempotent) so the record is guaranteed
        secret-free and marked ``redaction_complete``.
        """
        return build_exchange_record(
            method=self.request_line.get("method", ""),
            url=self.request_line.get("url", ""),
            request_headers=self.request_headers,
            status=self.status,
            response_headers=self.headers,
            body=self.body,
            redirected=self.redirected,
            redirect_location=self.redirect_location,
            truncated=self.truncated,
            attempts=self.attempts,
            known_secrets=self.known_secrets,
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow any redirect."""

    def redirect_request(self, *_args: object, **_kwargs: object) -> None:
        return None


def _apply_marker(text: str, prompt: str) -> str:
    return text.replace(MARKER, prompt)


def json_escape_prompt(prompt: str) -> str:
    """Escape ``prompt`` for safe insertion inside a JSON string literal.

    Returns the JSON-encoded form with the surrounding quotes stripped, so it
    can replace a ``*`` marker that sits inside quotes in a JSON body template
    (e.g. ``{"input": "*"}``). This escapes quotes, backslashes, and control
    characters such as newlines that would otherwise produce invalid JSON.
    """
    return json.dumps(prompt)[1:-1]


def _encode_prompt(prompt: str, encoding: str) -> str:
    if encoding == "json":
        return json_escape_prompt(prompt)
    if encoding == "url":
        return quote(prompt, safe="")
    return prompt


class Transport:
    """Sends templated requests within fixed safety bounds."""

    def __init__(
        self,
        config: TransportConfig | None = None,
        controller: RequestController | None = None,
    ) -> None:
        self.config = config or TransportConfig()
        self.controller = controller or RequestController(
            max_requests=self.config.max_requests,
            min_interval=self.config.min_interval_seconds,
        )
        self._opener = urllib.request.build_opener(_NoRedirect)

    def send(
        self,
        target: Target,
        *,
        method: str,
        prompt: str,
        body_template: str | None = None,
        headers: dict[str, str] | None = None,
        prompt_encoding: str | None = None,
    ) -> HttpResponse:
        """Send a single request, inserting ``prompt`` at the ``*`` marker.

        The prompt is encoded for the marker's context before substitution so
        the resulting request is always well-formed: ``GET`` percent-encodes
        into the URL/query; other methods JSON-string-escape into a JSON body
        template (pass ``prompt_encoding="raw"`` for a non-JSON template).

        Only methods in :data:`ACTIVE_METHODS` are permitted. Never follows
        redirects. Every physical attempt is rate-limited and counted against
        the shared request budget.

        Raises:
            TransportError: On a disallowed method or a connection/timeout
                failure. The message is sanitized and never contains request
                headers or the prompt.
            BudgetExceededError: When the request budget is exhausted.
        """
        raw_method = method
        method = method.upper()
        if method not in ACTIVE_METHODS:
            # The method value is untrusted; scrub it before it enters the
            # exception message so a secret-like method cannot leak.
            raise TransportError(
                f"method {scrub_text(raw_method)!r} is not permitted; allowed: "
                f"{', '.join(sorted(ACTIVE_METHODS))}"
            )

        req_headers = dict(headers or {})
        req_headers.setdefault("User-Agent", self.config.user_agent)

        encoding = prompt_encoding or ("url" if method == "GET" else "json")

        if method == "GET":
            url = _apply_marker(target.url, _encode_prompt(prompt, encoding))
            data: bytes | None = None
        else:
            url = target.url
            template = body_template if body_template is not None else f'"{MARKER}"'
            body = _apply_marker(template, _encode_prompt(prompt, encoding))
            data = body.encode("utf-8")
            req_headers.setdefault("Content-Type", "application/json")

        redacted = redact_headers(req_headers)
        secret_values = sensitive_header_values(req_headers) | url_secret_values(target.url)
        request_line = {
            "method": method,
            "url": redact_url(_apply_marker(target.url, "<PROMPT>")),
        }

        last_error: Exception | None = None
        attempts = 0
        for _attempt in range(self.config.max_retries + 1):
            self.controller.acquire()  # rate limit + budget (raises when exhausted)
            attempts += 1
            try:
                return self._perform(
                    url, method, data, req_headers, redacted,
                    request_line, secret_values, attempts,
                )
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = exc
                continue

        raise TransportError(
            f"Request to {target.origin} failed after "
            f"{attempts} attempt(s): {_safe_reason(last_error)}"
        )

    def _perform(
        self,
        url: str,
        method: str,
        data: bytes | None,
        req_headers: dict[str, str],
        redacted: dict[str, str],
        request_line: dict[str, str],
        secret_values: frozenset[str],
        attempts: int,
    ) -> HttpResponse:
        request = urllib.request.Request(url, data=data, method=method)
        for key, value in req_headers.items():
            request.add_header(key, value)

        try:
            raw = self._opener.open(request, timeout=self.config.timeout)
            with contextlib.closing(raw):
                status = raw.status
                resp_headers = {k: v for k, v in raw.headers.items()}
                payload = raw.read(self.config.max_response_bytes + 1)
        except urllib.error.HTTPError as http_err:
            # Non-2xx (including our captured redirects) arrive here.
            with contextlib.closing(http_err):
                status = http_err.code
                resp_headers = (
                    {k: v for k, v in http_err.headers.items()}
                    if http_err.headers
                    else {}
                )
                payload = http_err.read(self.config.max_response_bytes + 1)

        truncated = len(payload) > self.config.max_response_bytes
        payload = payload[: self.config.max_response_bytes]

        redirected = 300 <= status < 400
        location = resp_headers.get("Location") if redirected else None
        if location is not None:
            location = redact_url(location)

        body_text = scrub_text(payload.decode("utf-8", errors="replace"), secret_values)
        # Redact response headers by name, then scrub *every* header value for
        # reflected known secrets (an opaque credential echoed in an ordinary
        # header must not survive).
        safe_resp_headers = {
            key: scrub_text(value, secret_values)
            for key, value in redact_headers(resp_headers).items()
        }
        # A Location value carries secret-like query params even though the
        # header name itself is not sensitive; redact its URL in place.
        for key in list(safe_resp_headers):
            if key.lower() == "location":
                safe_resp_headers[key] = redact_url(safe_resp_headers[key])

        return HttpResponse(
            status=status,
            body=body_text,
            headers=safe_resp_headers,
            redirected=redirected,
            redirect_location=location,
            truncated=truncated,
            request_line=request_line,
            request_headers=redacted,
            attempts=attempts,
            known_secrets=secret_values,
        )


def _safe_reason(error: Exception | None) -> str:
    """Produce a short, secret-free description of a transport error."""
    if error is None:
        return "unknown error"
    if isinstance(error, urllib.error.URLError) and not isinstance(error, urllib.error.HTTPError):
        return f"{type(error).__name__}: connection failed"
    return type(error).__name__
