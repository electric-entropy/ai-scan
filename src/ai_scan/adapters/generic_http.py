"""Generic HTTP adapter — parity with the current transport request shaping.

Reproduces exactly what :meth:`ai_scan.transport.Transport.send` builds today:
``GET`` percent-encodes the prompt into the URL/query at the ``*`` marker; other
methods JSON-string-escape it into a JSON body template (``raw`` leaves it
verbatim). Header defaults (``User-Agent``, and ``Content-Type`` for non-GET)
match the transport, so existing integration fixtures pass through unchanged.
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
from ai_scan.transport import ACTIVE_METHODS, HttpResponse, TransportConfig, scrub_text
from ai_scan.transport.http import _apply_marker, _encode_prompt

_VALID_ENCODINGS = frozenset({"json", "url", "raw"})
_DEFAULT_USER_AGENT = TransportConfig().user_agent
_DEFAULT_BODY_TEMPLATE = f'"{MARKER}"'

# Static, offline capability descriptor (discoverable without a target/config).
CAPABILITIES = AdapterCapabilities(
    name="generic_http",
    methods=frozenset(ACTIVE_METHODS),
    prompt_encodings=frozenset(_VALID_ENCODINGS),
    extraction_modes=frozenset({"text", "json_pointer", "header"}),
    supports_sessions=False,
)


@dataclass
class GenericHttpAdapter:
    """Builds requests for a plain HTTP JSON/text endpoint.

    Attributes:
        target: The authorized target (defines scheme/host/port/path/url).
        method: HTTP method (must be in :data:`ACTIVE_METHODS`).
        body_template: Non-GET body template containing the ``*`` marker.
        prompt_encoding: ``json`` | ``url`` | ``raw`` (defaults by method).
        user_agent: ``User-Agent`` header value.
        extra_headers: Additional request headers.
        extraction: How to extract the text-of-interest from a response.
    """

    target: Target
    method: str = "POST"
    body_template: str | None = None
    prompt_encoding: str | None = None
    user_agent: str = _DEFAULT_USER_AGENT
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    extraction: ExtractionSpec = field(default_factory=ExtractionSpec)

    def __post_init__(self) -> None:
        # Preserve the value as given so the (untrusted) original is what gets
        # scrubbed into any error message, not the uppercased form.
        given_method = self.method
        self.method = self.method.upper()
        if self.method not in ACTIVE_METHODS:
            raise AdapterConfigError(
                f"method {scrub_text(str(given_method))!r} is not permitted; allowed: "
                f"{', '.join(sorted(ACTIVE_METHODS))}"
            )
        if self.prompt_encoding is not None and self.prompt_encoding not in _VALID_ENCODINGS:
            raise AdapterConfigError(
                f"unknown prompt encoding {scrub_text(str(self.prompt_encoding))!r}; "
                f"allowed: {', '.join(sorted(_VALID_ENCODINGS))}"
            )
        # The prompt must have somewhere to land: the marker must appear in the
        # GET URL or the non-GET body template. Otherwise fail closed.
        if self.method == "GET":
            if MARKER not in self.target.url:
                raise AdapterConfigError("GET target URL must contain the '*' prompt marker")
        else:
            template = (
                self.body_template if self.body_template is not None else _DEFAULT_BODY_TEMPLATE
            )
            if MARKER not in template:
                raise AdapterConfigError("body template must contain the '*' prompt marker")

    def capabilities(self) -> AdapterCapabilities:
        return CAPABILITIES

    def build_request(self, prompt: str) -> PreparedRequest:
        encoding = self.prompt_encoding or ("url" if self.method == "GET" else "json")
        headers: dict[str, str] = dict(self.extra_headers)
        headers.setdefault("User-Agent", self.user_agent)

        if self.method == "GET":
            url = _apply_marker(self.target.url, _encode_prompt(prompt, encoding))
            body: bytes | None = None
        else:
            url = self.target.url
            template = (
                self.body_template if self.body_template is not None else _DEFAULT_BODY_TEMPLATE
            )
            body = _apply_marker(template, _encode_prompt(prompt, encoding)).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")

        return PreparedRequest(method=self.method, url=url, headers=headers, body=body)

    def extract(self, response: HttpResponse) -> str:
        return extract_text(response, self.extraction)

    @contextmanager
    def session(self) -> Iterator[GenericHttpAdapter]:
        # Stateless HTTP: open/close is a deterministic no-op, always finalized.
        try:
            yield self
        finally:
            pass
