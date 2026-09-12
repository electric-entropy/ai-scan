"""Bounded, scope-safe HTTP transport (compatibility facade).

Milestone 3 split the transport into a package: the HTTP engine lives in
``_http``, central recursive redaction in ``redaction``, and immutable canonical
exchange records in ``records``. This package re-exports the historical public
API so ``from ai_scan.transport import ...`` keeps working unchanged for the
Milestone 0–2 contracts and callers.
"""

from __future__ import annotations

from ai_scan.transport._http import (
    ACTIVE_METHODS,
    MARKER,
    BudgetExceededError,
    HttpResponse,
    RequestController,
    Transport,
    TransportConfig,
    TransportError,
    json_escape_prompt,
)
from ai_scan.transport.records import (
    ExchangeRecord,
    RecordStore,
    RecordValidationError,
    RequestRecord,
    ResponseRecord,
    UnredactedRecordError,
    build_exchange_record,
)
from ai_scan.transport.redaction import (
    REDACTED,
    RedactionError,
    redact_headers,
    redact_url,
    redact_value,
    scrub_structure,
    scrub_text,
)

__all__ = [
    "ACTIVE_METHODS",
    "MARKER",
    "REDACTED",
    "BudgetExceededError",
    "ExchangeRecord",
    "HttpResponse",
    "RecordStore",
    "RecordValidationError",
    "RedactionError",
    "RequestController",
    "RequestRecord",
    "ResponseRecord",
    "Transport",
    "TransportConfig",
    "TransportError",
    "UnredactedRecordError",
    "build_exchange_record",
    "json_escape_prompt",
    "redact_headers",
    "redact_url",
    "redact_value",
    "scrub_structure",
    "scrub_text",
]
