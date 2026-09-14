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
# The full seven-state confidence vocabulary is preserved where runner state is
# persisted (no collapse of likely/suspected into legacy potential).
_VALID_STATUSES = frozenset(
    {"confirmed", "likely", "suspected", "potential", "not_observed", "inconclusive",
     "blocked", "not_tested"}
)
# Per-family control coverage: a usable clean control ran, a control emitted the
# canary (false-positive baseline), or control coverage is a gap.
_VALID_CONTROL_RESULTS = frozenset({"clean", "emitted", "gap"})
# Each completed record is closed-schema: exactly the new 7-field shape, or the
# legacy baseline 5-field shape (migrated on load). Anything else is rejected.
_ALLOWED_RECORD_FIELDS = frozenset(
    {"family", "status", "prompt", "proof", "kind", "attack_trials", "successes"}
)
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
    prompt, and a ``confirmed`` record must carry canary-bearing proof — so a
    re-digested forged record is rejected rather than trusted or skipped.
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
    attack, the bare template for a control). A ``confirmed`` record must carry
    proof that contains that canary. This rejects re-digested forged records
    (unknown case, altered family/kind/prompt, or a fabricated confirmation)
    rather than trusting or skipping them.
    """
    plan_cases = {c.case_id: c for c in plan.cases}  # type: ignore[attr-defined]
    # Prefer the stored canary; fall back to deriving it from the completed
    # records themselves so a legacy checkpoint (written before the canary field)
    # still binds and resumes rather than being rejected as non-plan-derived.
    canary = checkpoint.canary or _derive_canary(checkpoint.completed, plan_cases)
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
        if record.get("status") == "confirmed":
            _reject_unsupported_confirmation(record, case, checkpoint, canary, plan)


def _reject_unsupported_confirmation(
    record: dict[str, Any], case: Any, checkpoint: Checkpoint, canary: str, plan: Any
) -> None:
    """Reject a ``confirmed`` record whose own evidence cannot support confirmation.

    A confirmed status is re-derived from the record's trial counts against the
    plan's resolved thresholds, the family's control coverage, and canary-bearing
    proof. A re-digested status flip (e.g. a not-observed record relabeled
    ``confirmed``) is rejected because its counts/control/proof do not justify it.
    Note: the digest is tamper-evidence, not a signature (rule #12); a forgery
    that fabricates fully self-consistent trial evidence is out of scope here and
    is caught by the signed evidence bundle (C1).
    """
    from ai_scan.validation import Evidence, ExactCanaryValidator

    min_attack, min_successes = int(plan.trial_policy[0]), int(plan.trial_policy[1])
    family_key = f"{case.pack_id}:{case.family}"
    proof = record.get("proof")
    if (
        int(record.get("attack_trials", 0)) < min_attack
        or int(record.get("successes", 0)) < min_successes
        or checkpoint.control_results.get(family_key) != "clean"
        or not isinstance(proof, str)
        or not canary
        or canary not in proof
    ):
        raise CheckpointError("confirmed record is not supported by its trial/control evidence")
    # The canary is public (it is in the rendered prompt/checkpoint), so a proof
    # that is *only* the canary — or the canary with no surrounding response
    # context — is not response-derived evidence of execution; it is trivially
    # forgeable. Require the proof to carry genuine response context beyond the
    # public canary string.
    if not proof.replace(canary, "").strip():
        raise CheckpointError("confirmed record proof is a bare/public canary, not execution")
    # The proof must also show genuine, non-reflected canary execution: a proof
    # that is the (public) rendered prompt echoed back is reflection/self-echo,
    # which B1 classifies as 'suspected' — never a confirmation.
    rendered = case.template.replace("{canary}", canary)
    signal = ExactCanaryValidator().validate(
        Evidence(response=proof, canary=canary, prompt=rendered, evaluable=True)
    )
    if not signal.fired or signal.reflection:
        raise CheckpointError("confirmed record proof is reflection/self-echo, not execution")


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
            # evidence and is therefore rejected by the confirmation re-derivation.
            legacy = True
        elif record_fields == _ALLOWED_RECORD_FIELDS:
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
        out[case_id] = {
            "family": family,
            "status": status,
            "prompt": prompt,
            "proof": proof,
            "kind": kind,
            "attack_trials": attack_trials,
            "successes": successes,
        }
    return out


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
