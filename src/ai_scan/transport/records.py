"""Immutable, canonical request/response/exchange records.

Records are **deeply immutable** and **runtime-validated** at construction:
header maps are copied and exposed as read-only ``MappingProxyType`` views,
value types are checked, and invalid inputs are rejected. They are built only
through :func:`build_exchange_record`, which runs the content through central
recursive redaction and stamps a module-private *trusted provenance* token.

A :class:`RecordStore` is the persistence boundary: it accepts only an
:class:`ExchangeRecord` that carries the trusted provenance token **and** passes
a canonical, secret-free re-validation. Forged or directly-constructed records
(e.g. one that merely sets ``redaction_complete=True``) are rejected.
"""

from __future__ import annotations

import hmac
import json
import math
import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from types import MappingProxyType
from typing import Any

from ai_scan.core.ids import content_id
from ai_scan.transport.redaction import (
    _matches_secret_pattern,
    redact_url,
    redact_value,
)

SCHEMA_VERSION = "exchange-v1"

# Per-process secret key for the content-bound provenance seal. An unforgeable
# HMAC over the canonical redacted content proves a record was produced by
# build_exchange_record and has not been altered (e.g. via dataclasses.replace).
_SEAL_KEY = secrets.token_bytes(32)


def _canonical_content(
    request: RequestRecord, response: ResponseRecord, attempts: int, schema_version: str
) -> str:
    return json.dumps(
        {
            "schema_version": schema_version,
            "attempts": attempts,
            "request": request.to_dict(),
            "response": response.to_dict(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _compute_seal(
    request: RequestRecord, response: ResponseRecord, attempts: int, schema_version: str
) -> str:
    payload = _canonical_content(request, response, attempts, schema_version).encode("utf-8")
    return hmac.new(_SEAL_KEY, payload, sha256).hexdigest()


class UnredactedRecordError(Exception):
    """Raised when a record fails the store's provenance/redaction gate."""


class RecordValidationError(ValueError):
    """Raised when a record constructor receives invalid input."""


def _frozen_headers(headers: Any, where: str) -> MappingProxyType[str, str]:
    if not isinstance(headers, Mapping):
        raise RecordValidationError(f"{where}: headers must be a mapping")
    copied: dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise RecordValidationError(f"{where}: header names and values must be strings")
        copied[key] = value
    return MappingProxyType(copied)


def _require_str(value: Any, where: str, *, allow_empty: bool = True) -> None:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise RecordValidationError(f"{where}: expected a non-empty string")


def _require_bool(value: Any, where: str) -> None:
    if value is not True and value is not False:
        raise RecordValidationError(f"{where}: expected a bool")


@dataclass(frozen=True)
class RequestRecord:
    method: str
    url: str
    headers: MappingProxyType[str, str]

    def __post_init__(self) -> None:
        _require_str(self.method, "RequestRecord.method", allow_empty=False)
        _require_str(self.url, "RequestRecord.url")
        object.__setattr__(self, "headers", _frozen_headers(self.headers, "RequestRecord"))

    def to_dict(self) -> dict[str, Any]:
        return {"method": self.method, "url": self.url, "headers": dict(self.headers)}


@dataclass(frozen=True)
class ResponseRecord:
    status: int
    headers: MappingProxyType[str, str]
    body: str
    redirected: bool
    redirect_location: str | None
    truncated: bool

    def __post_init__(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise RecordValidationError("ResponseRecord.status must be an int")
        if not (0 <= self.status <= 599):
            raise RecordValidationError("ResponseRecord.status out of range")
        _require_str(self.body, "ResponseRecord.body")
        _require_bool(self.redirected, "ResponseRecord.redirected")
        _require_bool(self.truncated, "ResponseRecord.truncated")
        if self.redirect_location is not None and not isinstance(self.redirect_location, str):
            raise RecordValidationError("ResponseRecord.redirect_location must be str or None")
        object.__setattr__(self, "headers", _frozen_headers(self.headers, "ResponseRecord"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "headers": dict(self.headers),
            "body": self.body,
            "redirected": self.redirected,
            "redirect_location": self.redirect_location,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class ExchangeRecord:
    """An immutable, validated, redacted request/response pair."""

    request: RequestRecord
    response: ResponseRecord
    attempts: int
    redaction_complete: bool
    schema_version: str = SCHEMA_VERSION
    # Content-bound HMAC seal (set by build_exchange_record); verified by the
    # store against freshly-recomputed content. compare=False so equality/digest
    # reflect content, not the seal.
    provenance: str = field(default="", compare=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.request, RequestRecord):
            raise RecordValidationError("ExchangeRecord.request must be a RequestRecord")
        if not isinstance(self.response, ResponseRecord):
            raise RecordValidationError("ExchangeRecord.response must be a ResponseRecord")
        if isinstance(self.attempts, bool) or not isinstance(self.attempts, int):
            raise RecordValidationError("ExchangeRecord.attempts must be an int")
        if self.attempts < 1:
            raise RecordValidationError("ExchangeRecord.attempts must be >= 1")
        _require_bool(self.redaction_complete, "ExchangeRecord.redaction_complete")
        if self.schema_version != SCHEMA_VERSION:
            raise RecordValidationError(f"unsupported schema_version {self.schema_version!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "redaction_complete": self.redaction_complete,
            "attempts": self.attempts,
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
        }

    def digest(self) -> str:
        body = self.to_dict()
        body.pop("redaction_complete", None)
        return content_id(body, prefix="exch")


def build_exchange_record(
    *,
    method: str,
    url: str,
    request_headers: Mapping[str, str],
    status: int,
    response_headers: Mapping[str, str],
    body: str,
    redirected: bool,
    redirect_location: str | None,
    truncated: bool,
    attempts: int,
    known_secrets: frozenset[str] = frozenset(),
) -> ExchangeRecord:
    """Build a redacted, immutable, trusted exchange record.

    The whole request/response structure is run through central recursive
    redaction (its result is *used*, not discarded): every field — method,
    full URL, headers, body, redirect location, and any nested data — is
    scrubbed for known secrets and credential patterns, and sensitive keys are
    redacted. A non-finite numeric argument fails closed.
    """
    for name, num in (("status", status), ("attempts", attempts)):
        if isinstance(num, float) and not math.isfinite(num):
            raise RecordValidationError(f"{name} must be finite")

    raw_request = {"method": method, "url": redact_url(url), "headers": dict(request_headers)}
    raw_response = {
        "status": status,
        "headers": dict(response_headers),
        "body": body,
        "redirected": redirected,
        "redirect_location": redact_url(redirect_location) if redirect_location else None,
        "truncated": truncated,
    }
    red_req = redact_value(raw_request, known_secrets)
    red_resp = redact_value(raw_response, known_secrets)

    request = RequestRecord(
        method=red_req["method"], url=red_req["url"], headers=red_req["headers"]
    )
    response = ResponseRecord(
        status=red_resp["status"],
        headers=red_resp["headers"],
        body=red_resp["body"],
        redirected=red_resp["redirected"],
        redirect_location=red_resp["redirect_location"],
        truncated=red_resp["truncated"],
    )
    seal = _compute_seal(request, response, attempts, SCHEMA_VERSION)
    return ExchangeRecord(
        request=request,
        response=response,
        attempts=attempts,
        redaction_complete=True,
        provenance=seal,
    )


def _is_canonically_redacted(record: ExchangeRecord) -> bool:
    """Re-validate that the record serializes cleanly with no secret literals."""
    try:
        serialized = json.dumps(record.to_dict(), sort_keys=True)
    except (TypeError, ValueError):
        return False
    if _matches_secret_pattern(serialized):
        return False
    # Header maps must still be the read-only views (deep immutability intact).
    return isinstance(record.request.headers, MappingProxyType) and isinstance(
        record.response.headers, MappingProxyType
    )


class RecordStore:
    """A persistence boundary that accepts only trusted, redacted records."""

    def __init__(self) -> None:
        self._records: list[ExchangeRecord] = []

    def add(self, record: ExchangeRecord) -> None:
        if not isinstance(record, ExchangeRecord):
            raise UnredactedRecordError(
                f"only ExchangeRecord instances may be persisted, got {type(record).__name__}"
            )
        if record.redaction_complete is not True:
            raise UnredactedRecordError("record is not marked redaction_complete=True")
        # Recompute the content-bound seal from the record's *current* content.
        # Any mutation (dataclasses.replace, swapped child, copied seal onto
        # different content) invalidates it.
        expected = _compute_seal(
            record.request, record.response, record.attempts, record.schema_version
        )
        if not record.provenance or not hmac.compare_digest(expected, record.provenance):
            raise UnredactedRecordError(
                "record provenance seal does not match its content (forged or mutated)"
            )
        if not _is_canonically_redacted(record):
            raise UnredactedRecordError("record failed canonical secret-free re-validation")
        self._records.append(record)

    def __len__(self) -> int:
        return len(self._records)

    def records(self) -> tuple[ExchangeRecord, ...]:
        return tuple(self._records)
