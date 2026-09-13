"""Adapter protocol, prepared request, and response extraction.

An adapter is a pure request *shaper* and response *extractor*:

* :meth:`Adapter.build_request` turns a prompt into a :class:`PreparedRequest`
  (method/url/headers/body) — no I/O; the transport broker sends it.
* :meth:`Adapter.extract` pulls the relevant text from an
  :class:`~ai_scan.transport.HttpResponse` per an :class:`ExtractionSpec`.
* :meth:`Adapter.capabilities` is an offline, static description.
* :meth:`Adapter.session` is a deterministic open/close scope that is *always*
  finalized, even when the body raises.

Configuration errors raise :class:`AdapterConfigError` at construction / build
time, before any request exists, so a malformed adapter sends zero traffic.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, ClassVar, Protocol, runtime_checkable

from ai_scan.targets import Target
from ai_scan.transport import HttpResponse, scrub_text

MARKER = "*"

_VALID_EXTRACTION_MODES = frozenset({"text", "json_pointer", "header"})


class AdapterError(Exception):
    """Base class for adapter failures. Messages are secret-free."""


class AdapterConfigError(AdapterError):
    """Raised for a malformed adapter configuration (fails closed, zero I/O)."""


class ExtractionError(AdapterError):
    """Raised when a response field cannot be extracted as configured."""


@dataclass(frozen=True)
class PreparedRequest:
    """An immutable, ready-to-send request produced by an adapter.

    The adapter has already performed marker insertion and encoding; the
    transport layer only sends it. ``headers`` is frozen to a read-only mapping.
    """

    method: str
    url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or not self.method.strip():
            raise AdapterConfigError("prepared request requires a non-empty method")
        if not self.method.isascii() or not self.method.isalpha():
            raise AdapterConfigError("prepared request method must be alphabetic ASCII")
        if not isinstance(self.url, str) or not self.url:
            raise AdapterConfigError("prepared request requires a URL")
        if not isinstance(self.headers, Mapping):
            raise AdapterConfigError("prepared request headers must be a mapping")
        frozen_headers: dict[str, str] = {}
        for name, value in self.headers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise AdapterConfigError("prepared request header names and values must be strings")
            frozen_headers[name] = value
        if self.body is not None and not isinstance(self.body, bytes):
            raise AdapterConfigError("prepared request body must be bytes or None")
        object.__setattr__(self, "method", self.method.upper())
        object.__setattr__(self, "headers", MappingProxyType(frozen_headers))

    def header_dict(self) -> dict[str, str]:
        """A fresh mutable copy of the headers (for the transport layer)."""
        return dict(self.headers)


@dataclass(frozen=True)
class AdapterCapabilities:
    """Offline, static description of what an adapter supports."""

    name: str
    methods: frozenset[str]
    prompt_encodings: frozenset[str]
    extraction_modes: frozenset[str]
    supports_sessions: bool = False


@dataclass(frozen=True)
class ExtractionSpec:
    """How to extract the text-of-interest from a response.

    ``mode``:
        * ``text`` — the whole response body.
        * ``json_pointer`` — navigate the JSON body by ``path`` (RFC 6901-like,
          e.g. ``/choices/0/message/content``); the target must be a scalar.
        * ``header`` — the response header named ``path`` (case-insensitive).

    ``max_chars`` caps the returned length (a streaming-aggregation bound).
    """

    mode: str = "text"
    path: str = ""
    max_chars: int = 1_000_000

    def __post_init__(self) -> None:
        if self.mode not in _VALID_EXTRACTION_MODES:
            # The mode is untrusted config; scrub before it enters the message.
            raise AdapterConfigError(
                f"unknown extraction mode {scrub_text(str(self.mode))!r}; "
                f"allowed: {', '.join(sorted(_VALID_EXTRACTION_MODES))}"
            )
        if self.mode in {"json_pointer", "header"} and not self.path:
            raise AdapterConfigError(
                f"extraction mode {scrub_text(str(self.mode))!r} requires a path"
            )
        if self.mode == "text" and self.path:
            raise AdapterConfigError("extraction mode 'text' does not take a path")
        if (
            not isinstance(self.max_chars, int)
            or isinstance(self.max_chars, bool)
            or self.max_chars <= 0
        ):
            raise AdapterConfigError("max_chars must be positive")


@runtime_checkable
class Adapter(Protocol):
    """The protocol every adapter implements (request shaping + extraction)."""

    def capabilities(self) -> AdapterCapabilities: ...

    def build_request(self, prompt: str) -> PreparedRequest: ...

    def extract(self, response: HttpResponse) -> str: ...

    @contextmanager
    def session(self) -> Iterator[Adapter]: ...


def _validate_max_chars(value: object) -> int:
    """Validate a positive-integer character bound (shared by the adapters)."""
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise AdapterConfigError("max_chars must be positive")
    return int(value)


def validate_extra_headers(headers: Mapping[str, str]) -> Mapping[str, str]:
    """Validate and freeze adapter-controlled headers at construction time."""
    if not isinstance(headers, Mapping):
        raise AdapterConfigError("extra_headers must be a mapping")
    frozen_headers: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise AdapterConfigError("extra header names and values must be strings")
        frozen_headers[key] = value
    return MappingProxyType(frozen_headers)


def extract_text(response: HttpResponse, spec: ExtractionSpec) -> str:
    """Extract and bound the text-of-interest from ``response`` per ``spec``.

    Raises:
        ExtractionError: If the configured field is absent or incompatible
            (e.g. a JSON pointer into a non-JSON body or at a non-scalar node).
    """
    if spec.mode == "text":
        value = response.body
    elif spec.mode == "header":
        value = _extract_header(response, spec.path)
    else:
        value = _extract_json_pointer(response.body, spec.path)
    return value[: spec.max_chars]


def _extract_header(response: HttpResponse, name: str) -> str:
    wanted = name.lower()
    for key, value in response.headers.items():
        if key.lower() == wanted:
            return value
    raise ExtractionError("response does not carry the configured header")


def _extract_json_pointer(body: str, pointer: str) -> str:
    try:
        data: Any = json.loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ExtractionError("response body is not valid JSON for pointer extraction") from exc

    if not pointer.startswith("/"):
        raise ExtractionError("JSON pointer must start with '/'")

    node = data
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict):
            if token not in node:
                raise ExtractionError("JSON pointer does not resolve in the response")
            node = node[token]
        elif isinstance(node, list):
            if not token.lstrip("-").isdigit():
                raise ExtractionError("JSON pointer index into a list is not an integer")
            index = int(token)
            if index < 0 or index >= len(node):
                raise ExtractionError("JSON pointer index is out of range")
            node = node[index]
        else:
            raise ExtractionError("JSON pointer descends into a scalar value")

    # Reject incompatible (non-scalar) leaves rather than stringifying a blob.
    if isinstance(node, bool) or isinstance(node, (int, float)):
        return str(node)
    if isinstance(node, str):
        return node
    raise ExtractionError("JSON pointer target is not a scalar field")


@dataclass
class HttpJsonAdapter:
    """Shared base for JSON provider adapters (OpenAI/Anthropic/Gemini/Ollama).

    Subclasses set the class attributes ``name``, ``extraction_path`` (a JSON
    pointer into the provider's response), and implement :meth:`_payload`
    (the request JSON for a prompt). The base handles config validation (no
    transport), request encoding, extraction via the central
    :func:`extract_text`, capabilities, and a no-op session. It never performs
    I/O — it only *shapes* a :class:`PreparedRequest`.
    """

    name: ClassVar[str] = "http_json"
    extraction_path: ClassVar[str] = "/"

    target: Target
    model: str = ""
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    max_chars: int = 1_000_000

    def __post_init__(self) -> None:
        if not isinstance(self.model, str) or not self.model.strip():
            raise AdapterConfigError(f"{self.name} adapter requires a non-empty model")
        _validate_max_chars(self.max_chars)
        self.extra_headers = validate_extra_headers(self.extra_headers)

    def _payload(self, prompt: str) -> dict[str, Any]:
        raise NotImplementedError

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        headers.update(self.extra_headers)
        return headers

    def build_request(self, prompt: str) -> PreparedRequest:
        body = json.dumps(self._payload(prompt)).encode("utf-8")
        return PreparedRequest(
            method="POST", url=self.target.url, headers=self._headers(), body=body
        )

    def extract(self, response: HttpResponse) -> str:
        spec = ExtractionSpec(
            mode="json_pointer", path=self.extraction_path, max_chars=self.max_chars
        )
        return extract_text(response, spec)

    def capabilities(self) -> AdapterCapabilities:
        return AdapterCapabilities(
            name=self.name,
            methods=frozenset({"POST"}),
            prompt_encodings=frozenset({"json"}),
            extraction_modes=frozenset({"json_pointer", "text"}),
            supports_sessions=False,
        )

    @contextmanager
    def session(self) -> Iterator[HttpJsonAdapter]:
        try:
            yield self
        finally:
            pass
