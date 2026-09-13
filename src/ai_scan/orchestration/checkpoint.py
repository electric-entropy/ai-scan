"""Atomic, tamper-rejecting, secret-free run checkpoints.

A checkpoint records which cases have completed (and their finding status), the
per-family control outcomes, the physical request count, and the run state — so
a killed run resumes without repeating a completed physical attempt. It is bound
to its plan's digest and carries a content digest of its own; :func:`load_checkpoint`
fails closed if either the plan digest or the content digest does not match
(rejecting a tampered or mismatched checkpoint). Writes are atomic (temp file +
``os.replace``). No secret material is ever stored.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any

from ai_scan.packs.signatures import compute_digest, verify_digest

CHECKPOINT_VERSION = 1
_VALID_STATES = frozenset(
    {
        "planned",
        "authorized",
        "running",
        "confirming",
        "cleaning_up",
        "completed",
        "completed_with_gaps",
        "cancelled",
        "failed",
    }
)
_VALID_STATUSES = frozenset({"confirmed", "potential", "not_observed", "inconclusive"})


class CheckpointError(Exception):
    """Raised when a checkpoint is malformed, tampered, or plan-mismatched."""


@dataclass
class Checkpoint:
    """Resumable run state for one plan (secret-free)."""

    plan_digest: str
    state: str
    request_count: int = 0
    completed: dict[str, dict[str, Any]] = field(default_factory=dict)
    control_results: dict[str, bool] = field(default_factory=dict)

    def to_body(self) -> dict[str, Any]:
        return {
            "checkpoint_version": CHECKPOINT_VERSION,
            "plan_digest": self.plan_digest,
            "state": self.state,
            "request_count": self.request_count,
            # Sort for a stable, digestable, diff-friendly representation.
            "completed": {k: self.completed[k] for k in sorted(self.completed)},
            "control_results": {k: self.control_results[k] for k in sorted(self.control_results)},
        }


def _sealed(checkpoint: Checkpoint) -> dict[str, Any]:
    body = checkpoint.to_body()
    body["digest"] = compute_digest(body)
    return body


def write_checkpoint_atomic(path: str, checkpoint: Checkpoint) -> None:
    """Write ``checkpoint`` to ``path`` atomically (temp file + replace)."""
    payload = json.dumps(_sealed(checkpoint), indent=2, sort_keys=True)
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, prefix=".ckpt-", suffix=".tmp", delete=False
    )
    try:
        with handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(handle.name)
        raise


def load_checkpoint(path: str, *, expected_plan_digest: str) -> Checkpoint:
    """Load and verify a checkpoint, failing closed on tamper / plan mismatch."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        # A missing checkpoint is "no prior run"; the caller starts fresh.
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise CheckpointError("checkpoint could not be read") from exc
    if not isinstance(data, dict):
        raise CheckpointError("checkpoint must be a JSON object")
    if data.get("checkpoint_version") != CHECKPOINT_VERSION:
        raise CheckpointError("unsupported or missing checkpoint_version")
    if not verify_digest(data):
        raise CheckpointError("checkpoint digest does not match its content (tampered)")
    if data.get("plan_digest") != expected_plan_digest:
        raise CheckpointError("checkpoint belongs to a different plan")
    try:
        state = _require_str(data["state"], "state")
        if state not in _VALID_STATES:
            raise CheckpointError("invalid checkpoint state")
        request_count = _require_int(data["request_count"], "request_count", positive=False)
        completed = _completed(data["completed"])
        control_results = _control_results(data["control_results"])
        return Checkpoint(
            plan_digest=_require_str(data["plan_digest"], "plan_digest"),
            state=state,
            request_count=request_count,
            completed=completed,
            control_results=control_results,
        )
    except (KeyError, TypeError, ValueError, CheckpointError) as exc:
        raise CheckpointError("malformed checkpoint") from exc


def _require_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise CheckpointError(f"{name} must be a non-empty string")
    return value


def _require_int(value: object, name: str, *, positive: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CheckpointError(f"{name} must be an integer")
    if positive and value <= 0:
        raise CheckpointError(f"{name} must be positive")
    if not positive and value < 0:
        raise CheckpointError(f"{name} must be non-negative")
    return value


def _completed(value: object) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise CheckpointError("completed must be an object")
    out: dict[str, dict[str, Any]] = {}
    for key, raw_record in value.items():
        case_id = _require_str(key, "case_id")
        if not isinstance(raw_record, dict):
            raise CheckpointError("completed records must be objects")
        family = _require_str(raw_record.get("family"), "family")
        status = _require_str(raw_record.get("status"), "status")
        if status not in _VALID_STATUSES:
            raise CheckpointError("invalid completed status")
        prompt = _require_str(raw_record.get("prompt"), "prompt")
        kind = _require_str(raw_record.get("kind"), "kind")
        if kind not in {"attack", "control"}:
            raise CheckpointError("invalid completed kind")
        proof = raw_record.get("proof")
        if proof is not None and not isinstance(proof, str):
            raise CheckpointError("proof must be a string or null")
        out[case_id] = {
            "family": family,
            "status": status,
            "prompt": prompt,
            "proof": proof,
            "kind": kind,
        }
    return out


def _control_results(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise CheckpointError("control_results must be an object")
    out: dict[str, bool] = {}
    for key, raw in value.items():
        family = _require_str(key, "family")
        if not isinstance(raw, bool):
            raise CheckpointError("control result values must be boolean")
        out[family] = raw
    return out
