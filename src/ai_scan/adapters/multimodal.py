"""Offline multimodal adapter groundwork.

This adapter only shapes requests for synthetic media fixtures. It rejects binary
or remote media sources and requires an explicit ``file_upload`` capability when
used by planning code. No image parsing, browser execution, or network access is
performed here; the broker remains the only sender of the prepared request.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field

from ai_scan.adapters.base import (
    AdapterCapabilities,
    AdapterConfigError,
    ExtractionSpec,
    PreparedRequest,
    extract_text,
    validate_extra_headers,
)
from ai_scan.targets import Target
from ai_scan.transport import HttpResponse, scrub_text

CAPABILITIES = AdapterCapabilities(
    name="multimodal",
    methods=frozenset({"POST"}),
    prompt_encodings=frozenset({"json"}),
    extraction_modes=frozenset({"json_pointer", "text"}),
    supports_sessions=False,
)

_ALLOWED_MEDIA_TYPES = frozenset({"text/plain", "text/markdown", "image/svg+xml"})


@dataclass
class MultimodalAdapter:
    """Pure offline request shaper for synthetic multimodal test fixtures."""

    target: Target
    media_type: str
    media_text: str
    prompt_field: str = "prompt"
    media_field: str = "media"
    extra_headers: Mapping[str, str] = field(default_factory=dict)
    max_chars: int = 1_000_000

    def __post_init__(self) -> None:
        if self.media_type not in _ALLOWED_MEDIA_TYPES:
            raise AdapterConfigError(
                f"unsupported synthetic media type {scrub_text(str(self.media_type))!r}"
            )
        if not isinstance(self.media_text, str) or not self.media_text:
            raise AdapterConfigError("media_text must be a non-empty string")
        if self.media_text.startswith(("http://", "https://")):
            raise AdapterConfigError("remote media references are not allowed")
        for field_name in (self.prompt_field, self.media_field):
            if not isinstance(field_name, str) or not field_name.isidentifier():
                raise AdapterConfigError("multimodal field names must be simple identifiers")
        if (
            not isinstance(self.max_chars, int)
            or isinstance(self.max_chars, bool)
            or self.max_chars <= 0
        ):
            raise AdapterConfigError("max_chars must be positive")
        self.extra_headers = validate_extra_headers(self.extra_headers)

    def capabilities(self) -> AdapterCapabilities:
        return CAPABILITIES

    def build_request(self, prompt: str) -> PreparedRequest:
        body = json.dumps(
            {
                self.prompt_field: prompt,
                self.media_field: {"type": self.media_type, "text": self.media_text},
            },
            ensure_ascii=False,
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        headers.update(self.extra_headers)
        return PreparedRequest("POST", self.target.url, headers, body)

    def extract(self, response: HttpResponse) -> str:
        return extract_text(
            response,
            ExtractionSpec(mode="json_pointer", path="/output", max_chars=self.max_chars),
        )

    @contextmanager
    def session(self) -> Iterator[MultimodalAdapter]:
        try:
            yield self
        finally:
            pass
