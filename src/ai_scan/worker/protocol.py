"""Strict local-worker protocol for optional isolated execution.

The worker boundary is deliberately narrow in this milestone: callers can send a
small JSON request to a disposable local container and receive a bounded JSON
result. Active network semantics do not change, and the default local worker
runs with Docker networking disabled until target-scoped egress enforcement is
implemented outside the Python process.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import IO, Any

MAX_PAYLOAD_BYTES = 64 * 1024
MAX_MESSAGE_BYTES = 128 * 1024
SUPPORTED_PROTOCOL_VERSION = "worker-v1"
SUPPORTED_OPERATIONS = frozenset({"ping", "echo"})


class WorkerProtocolError(ValueError):
    """Raised when a worker message is malformed or unsupported."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise WorkerProtocolError("worker message has duplicate JSON keys")
        out[key] = value
    return out


def _reject_non_finite(_constant: str) -> float:
    raise WorkerProtocolError("worker message contains a non-finite number")


def read_bounded(stream: IO[bytes]) -> bytes:
    """Read at most one message from ``stream``, bounding the allocation.

    Reads only ``MAX_MESSAGE_BYTES + 1`` bytes so an unbounded/huge stdin cannot
    force a large allocation before the size is checked; anything larger than the
    limit fails closed without consuming the rest of the stream.
    """
    raw = stream.read(MAX_MESSAGE_BYTES + 1)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise WorkerProtocolError("worker message exceeds the maximum size")
    return raw


def _require_string(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and value == ""):
        raise WorkerProtocolError(f"{field} must be a non-empty string")
    return value


def _reject_unknown_fields(data: dict[str, object], allowed: frozenset[str], where: str) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise WorkerProtocolError(f"{where} has unknown fields")


def _loads_object(raw: bytes | str, where: str) -> dict[str, object]:
    if isinstance(raw, str):
        encoded = raw.encode("utf-8")
    else:
        encoded = raw
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise WorkerProtocolError(f"{where} exceeds the maximum message size")
    try:
        parsed = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerProtocolError(f"{where} must be valid UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise WorkerProtocolError(f"{where} must be a JSON object")
    return parsed


@dataclass(frozen=True)
class WorkerRequest:
    """A bounded request accepted by the isolated local worker."""

    protocol_version: str
    operation: str
    payload: str

    def __post_init__(self) -> None:
        _require_string(self.protocol_version, "protocol_version")
        _require_string(self.operation, "operation")
        if self.protocol_version != SUPPORTED_PROTOCOL_VERSION:
            raise WorkerProtocolError("unsupported worker protocol version")
        if self.operation not in SUPPORTED_OPERATIONS:
            raise WorkerProtocolError("unsupported worker operation")
        if not isinstance(self.payload, str):
            raise WorkerProtocolError("payload must be a string")
        if len(self.payload.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise WorkerProtocolError("payload exceeds the maximum size")

    def to_dict(self) -> dict[str, str]:
        return {
            "protocol_version": self.protocol_version,
            "operation": self.operation,
            "payload": self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)

    @classmethod
    def from_json(cls, raw: bytes | str) -> WorkerRequest:
        data = _loads_object(raw, "worker request")
        _reject_unknown_fields(
            data, frozenset({"protocol_version", "operation", "payload"}), "request"
        )
        return cls(
            protocol_version=_require_string(data.get("protocol_version"), "protocol_version"),
            operation=_require_string(data.get("operation"), "operation"),
            payload=_require_string(data.get("payload"), "payload", allow_empty=True),
        )


@dataclass(frozen=True)
class WorkerResult:
    """A bounded response returned by the isolated local worker."""

    protocol_version: str
    status: str
    output: str

    def __post_init__(self) -> None:
        _require_string(self.protocol_version, "protocol_version")
        if self.protocol_version != SUPPORTED_PROTOCOL_VERSION:
            raise WorkerProtocolError("unsupported worker result protocol version")
        if self.status not in {"ok", "error"}:
            raise WorkerProtocolError("worker status must be ok or error")
        if not isinstance(self.output, str):
            raise WorkerProtocolError("worker output must be a string")
        if len(self.output.encode("utf-8")) > MAX_PAYLOAD_BYTES:
            raise WorkerProtocolError("worker output exceeds the maximum size")

    def to_dict(self) -> dict[str, str]:
        return {
            "protocol_version": self.protocol_version,
            "status": self.status,
            "output": self.output,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"), allow_nan=False)

    @classmethod
    def from_json(cls, raw: bytes | str) -> WorkerResult:
        data = _loads_object(raw, "worker result")
        _reject_unknown_fields(data, frozenset({"protocol_version", "status", "output"}), "result")
        return cls(
            protocol_version=_require_string(data.get("protocol_version"), "protocol_version"),
            status=_require_string(data.get("status"), "status"),
            output=_require_string(data.get("output"), "output", allow_empty=True),
        )


def handle_request(request: WorkerRequest) -> WorkerResult:
    """Execute the built-in safe worker operation.

    This intentionally supports only non-network operations. Future adapter/plugin
    execution must enter through this typed boundary and the same broker/scope
    contracts, not through ad hoc container commands.
    """

    if request.operation == "ping":
        return WorkerResult(SUPPORTED_PROTOCOL_VERSION, "ok", "pong")
    if request.operation == "echo":
        return WorkerResult(SUPPORTED_PROTOCOL_VERSION, "ok", request.payload)
    raise WorkerProtocolError("unsupported worker operation")


def error_result(message: str) -> WorkerResult:
    """Build a protocol error result without reflecting untrusted raw input."""

    return WorkerResult(SUPPORTED_PROTOCOL_VERSION, "error", message)
