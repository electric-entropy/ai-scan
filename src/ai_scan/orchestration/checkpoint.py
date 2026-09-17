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
import re
import tempfile
from dataclasses import dataclass, field
from typing import Any

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.packs.signatures import compute_digest, verify_digest
from ai_scan.transport.redaction import scrub_structure

CHECKPOINT_VERSION = 1
_ALLOWED_FIELDS = frozenset(
    {
        "checkpoint_version",
        "plan_digest",
        "state",
        "request_count",
        "canary",
        "completed",
        "control_results",
        "digest",
    }
)
_VALID_STATES = frozenset(
    {
        "planned",
        "validated",
        "running",
        "confirming",
        "cleaning_up",
        "completed",
        "completed_with_gaps",
        "cancelled",
        "failed",
    }
)
# The full seven-state confidence vocabulary is preserved where runner state is
# persisted (no collapse of likely/suspected into legacy potential).
_VALID_STATUSES = frozenset(
    {"confirmed", "likely", "suspected", "potential", "not_observed", "inconclusive",
     "blocked", "not_tested"}
)
# Per-family control coverage: a usable clean control ran, a control emitted the
# canary (false-positive baseline), or control coverage is a gap.
_VALID_CONTROL_RESULTS = frozenset({"clean", "emitted", "gap"})
# Each completed record is closed-schema: the evidence shape (with persisted
# per-trial ``trials``), or a legacy shape without trials — the pre-evidence
# 7-field record or the baseline 5-field record. Legacy records carry no
# re-derivable evidence, so they can never be ``confirmed`` and a legacy
# control never counts as control coverage. Anything else is rejected.
_COUNTED_RECORD_FIELDS = frozenset(
    {"family", "status", "prompt", "proof", "kind", "attack_trials", "successes"}
)
_EVIDENCE_RECORD_FIELDS = _COUNTED_RECORD_FIELDS | {"trials"}
_LEGACY_RECORD_FIELDS = frozenset({"family", "status", "prompt", "proof", "kind"})


class CheckpointError(Exception):
    """Raised when a checkpoint is malformed, tampered, or plan-mismatched."""


@dataclass
class Checkpoint:
    """Resumable run state for one plan (secret-free)."""

    plan_digest: str
    state: str
    request_count: int = 0
    completed: dict[str, dict[str, Any]] = field(default_factory=dict)
    control_results: dict[str, str] = field(default_factory=dict)
    # The run's synthetic canary (not a secret), stored so a resumed run and a
    # plan-binding load can re-derive each case's rendered prompt.
    canary: str = ""

    def to_body(self) -> dict[str, Any]:
        return {
            "checkpoint_version": CHECKPOINT_VERSION,
            "plan_digest": self.plan_digest,
            "state": self.state,
            "request_count": self.request_count,
            "canary": self.canary,
            # Sort for a stable, digestable, diff-friendly representation.
            "completed": {k: self.completed[k] for k in sorted(self.completed)},
            "control_results": {k: self.control_results[k] for k in sorted(self.control_results)},
        }


def _sealed(checkpoint: Checkpoint, known_secrets: frozenset[str]) -> dict[str, Any]:
    # Recursively scrub the body (credential literals, reflected known secrets,
    # URL-field secrets) *before* sealing, so the digest is computed over — and
    # matches — the redacted content that is actually persisted.
    body: dict[str, Any] = scrub_structure(checkpoint.to_body(), known_secrets)
    body["digest"] = compute_digest(body)
    return body


def write_checkpoint_atomic(
    path: str, checkpoint: Checkpoint, *, known_secrets: frozenset[str] = frozenset()
) -> None:
    """Write ``checkpoint`` to ``path`` atomically (temp file + replace), 0600.

    The checkpoint body is recursively redacted before the write, and the file
    is created and left mode ``0600`` so no secret material is ever readable on
    disk.
    """
    payload = json.dumps(_sealed(checkpoint, known_secrets), indent=2, sort_keys=True)
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
        os.chmod(handle.name, 0o600)
        os.replace(handle.name, path)
        os.chmod(path, 0o600)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(handle.name)
        raise


def load_checkpoint(
    path: str, *, expected_plan_digest: str, plan: object | None = None
) -> Checkpoint:
    """Load and verify a checkpoint, failing closed on tamper / plan mismatch.

    Strict-parsed: duplicate JSON keys and non-finite numbers are rejected, and a
    closed top-level field set rejects unknown fields (even when re-digested).
    When ``plan`` is supplied, every completed record is **bound to the verified
    plan**: its case must exist in the plan with a matching family/kind/rendered
    prompt, and its status must re-derive from its persisted trials under the
    shared evidence contract — so a re-digested forged record is rejected rather
    than trusted or skipped.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        # A missing checkpoint is "no prior run"; the caller starts fresh.
        raise
    except OSError as exc:
        raise CheckpointError("checkpoint could not be read") from exc
    try:
        data = load_json_strict(text)
    except ConfigError as exc:
        raise CheckpointError("checkpoint is not valid strict JSON") from exc
    if not isinstance(data, dict):
        raise CheckpointError("checkpoint must be a JSON object")
    unknown = set(data) - _ALLOWED_FIELDS
    if unknown:
        raise CheckpointError(f"checkpoint has unknown field(s) not permitted ({len(unknown)})")
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
        canary = data.get("canary", "")
        if not isinstance(canary, str):
            raise CheckpointError("canary must be a string")
        completed = _completed(data["completed"])
        control_results = _control_results(data["control_results"])
        checkpoint = Checkpoint(
            plan_digest=_require_str(data["plan_digest"], "plan_digest"),
            state=state,
            request_count=request_count,
            completed=completed,
            control_results=control_results,
            canary=canary,
        )
    except (KeyError, TypeError, ValueError, CheckpointError) as exc:
        raise CheckpointError("malformed checkpoint") from exc
    if plan is not None:
        _bind_completed_to_plan(checkpoint, plan)
    return checkpoint


def _bind_completed_to_plan(checkpoint: Checkpoint, plan: object) -> None:
    """Reject any completed record not derivable from the verified plan.

    Each record's case must exist in the plan with a matching family/kind and the
    exact rendered prompt (template rendered with the checkpoint's canary for an
    attack, the bare template for a control). Every evidence-bearing record is
    then re-derived from its persisted trials through the shared evidence
    contract (:func:`~ai_scan.orchestration.evidence.verify_records`): status,
    proof, trial and success counts, and per-family control coverage must all
    match, and the physical request count must cover the persisted attempts. A
    legacy record without trials can never be ``confirmed``.
    """
    from ai_scan.orchestration.evidence import (
        CaseEvidence,
        EvidenceError,
        resolve_plan_packs,
        verify_records,
    )

    plan_cases = {c.case_id: c for c in plan.cases}  # type: ignore[attr-defined]
    # Prefer the stored canary; fall back to deriving it from the completed
    # records themselves so a legacy checkpoint (written before the canary field)
    # still binds and resumes rather than being rejected as non-plan-derived.
    canary = checkpoint.canary or _derive_canary(checkpoint.completed, plan_cases)
    if checkpoint.request_count > plan.limits.max_physical_requests:  # type: ignore[attr-defined]
        raise CheckpointError("request_count exceeds the plan's physical request budget")
    evidence: list[CaseEvidence] = []
    for case_id, record in checkpoint.completed.items():
        case = plan_cases.get(case_id)
        if case is None:
            raise CheckpointError("completed record references a case not in the plan")
        if record.get("family") != case.family or record.get("kind") != case.kind:
            raise CheckpointError("completed record does not match its plan case")
        expected = case.template if case.kind == "control" else case.template.replace(
            "{canary}", canary
        )
        if record.get("prompt") != expected:
            raise CheckpointError("completed record prompt is not plan-derived")
        if "trials" not in record:
            if record.get("status") == "confirmed":
                raise CheckpointError(
                    "confirmed record carries no persisted trial evidence"
                )
            continue
        evidence.append(
            CaseEvidence(
                case_id=case_id,
                kind=str(record["kind"]),
                status=str(record["status"]),
                proof=record.get("proof"),
                attack_trials=int(record["attack_trials"]),
                successes=int(record["successes"]),
                trials=record["trials"],
            )
        )
    if not evidence:
        return
    try:
        verified = verify_records(plan, resolve_plan_packs(plan), canary, evidence)  # type: ignore[arg-type]
    except EvidenceError as exc:
        raise CheckpointError(f"completed record evidence is invalid: {exc}") from exc
    for family, result in verified.control_results.items():
        if checkpoint.control_results.get(family) != result:
            raise CheckpointError("control results do not match the persisted control evidence")
    if checkpoint.request_count < verified.physical_request_count:
        raise CheckpointError("request_count is below the persisted physical trial attempts")


def _derive_canary(completed: dict[str, dict[str, Any]], plan_cases: dict[str, Any]) -> str:
    """Recover the run's canary from a completed attack record's rendered prompt.

    Used only when the checkpoint predates the stored ``canary`` field. The
    candidate is verified by re-rendering the plan template, so it cannot be
    spoofed into matching an inconsistent prompt.
    """
    for case_id, record in completed.items():
        if record.get("kind") != "attack":
            continue
        case = plan_cases.get(case_id)
        if case is None or "{canary}" not in case.template:
            continue
        prompt = str(record.get("prompt", ""))
        prefix = case.template[: case.template.find("{canary}")]
        if not prompt.startswith(prefix):
            continue
        match = re.match(r"AISCAN-[A-Za-z0-9_-]+", prompt[len(prefix):])
        if match and case.template.replace("{canary}", match.group(0)) == prompt:
            return match.group(0)
    return ""


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
        record_fields = set(raw_record)
        if record_fields == _LEGACY_RECORD_FIELDS:
            # Legacy baseline record: no trial counts. Safe to trust as completed
            # for non-confirmed statuses; a legacy 'confirmed' has zero trial
            # evidence and is therefore rejected by plan binding.
            legacy = True
        elif record_fields in (_COUNTED_RECORD_FIELDS, _EVIDENCE_RECORD_FIELDS):
            legacy = False
        else:
            raise CheckpointError("completed record has unknown or missing field(s)")
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
        if legacy:
            attack_trials, successes = 0, 0
        else:
            attack_trials = _require_int(raw_record["attack_trials"], "attack_trials",
                                         positive=False)
            successes = _require_int(raw_record["successes"], "successes", positive=False)
            if successes > attack_trials:
                raise CheckpointError("completed record successes cannot exceed attack_trials")
        normalized: dict[str, Any] = {
            "family": family,
            "status": status,
            "prompt": prompt,
            "proof": proof,
            "kind": kind,
            "attack_trials": attack_trials,
            "successes": successes,
        }
        if "trials" in raw_record:
            normalized["trials"] = _trials(raw_record["trials"])
        out[case_id] = normalized
    return out


def _trials(value: object) -> list[dict[str, Any]]:
    """Structurally validate persisted trial evidence (plan binding re-derives it)."""
    from ai_scan.orchestration.evidence import EvidenceError, trial_from_dict, trial_to_dict

    if not isinstance(value, list) or not value:
        raise CheckpointError("completed record trials must be a non-empty list")
    try:
        return [trial_to_dict(trial_from_dict(item)) for item in value]
    except EvidenceError as exc:
        raise CheckpointError("completed record trial evidence is malformed") from exc


def _control_results(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise CheckpointError("control_results must be an object")
    out: dict[str, str] = {}
    for key, raw in value.items():
        family = _require_str(key, "family")
        if isinstance(raw, bool):
            # Legacy boolean control result: True == the control emitted the
            # canary, False == a clean (non-emitting) control.
            out[family] = "emitted" if raw else "clean"
        elif isinstance(raw, str) and raw in _VALID_CONTROL_RESULTS:
            out[family] = raw
        else:
            raise CheckpointError("invalid control result")
    return out
