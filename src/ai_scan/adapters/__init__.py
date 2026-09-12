"""Adapters decouple application shape from transport and attack logic.

An :class:`~ai_scan.adapters.base.Adapter` knows how to *build* a request for a
target (marker insertion, encoding, captured-request replay) and how to
*extract* the relevant text from a response. It never performs I/O — the
transport broker remains the sole network mediator — so a malformed adapter
configuration fails closed with zero requests.
"""

from __future__ import annotations

from ai_scan.adapters.base import (
    Adapter,
    AdapterCapabilities,
    AdapterConfigError,
    AdapterError,
    ExtractionError,
    ExtractionSpec,
    PreparedRequest,
    extract_text,
)
from ai_scan.adapters.captured_http import CapturedHttpAdapter, parse_captured_request
from ai_scan.adapters.generic_http import GenericHttpAdapter
from ai_scan.adapters.registry import (
    AdapterRegistry,
    available_adapters,
    default_registry,
)

__all__ = [
    "Adapter",
    "AdapterCapabilities",
    "AdapterConfigError",
    "AdapterError",
    "AdapterRegistry",
    "CapturedHttpAdapter",
    "ExtractionError",
    "ExtractionSpec",
    "GenericHttpAdapter",
    "PreparedRequest",
    "available_adapters",
    "default_registry",
    "extract_text",
    "parse_captured_request",
]
