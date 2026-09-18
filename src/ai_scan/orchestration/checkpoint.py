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
from typing import Any, cast

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.core.run_identity import (
    RunIdentity,
    canary_commitment,
    disclosure_marker_commitment,
    evidence_canary,
    evidence_marker,
)
from ai_scan.packs.signatures import compute_digest, verify_digest
from ai_scan.transport.redaction import scrub_structure

# v3 binds the persisted pseudonymous canary and disclosure-marker state to one
# shared run identity and requires case-bound trial commitments.
CHECKPOINT_VERSION = 3
# Import compatibility only.  This public literal is no longer used as the
# persisted identity and is never globally rewritten.
PERSISTED_CANARY = "AISCAN-PERSISTED-CANARY"
_ALLOWED_FIELDS = frozenset(
    {
        "checkpoint_version",
        "plan_digest",
        "state",
        "request_count",
        "canary",
        "canary_commitment",
        "marker_commitment",
        "completed",
        "control_results",
        "progress",
        "in_flight",
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
# Every current completed record has one exact evidence-bearing schema. Older
# shapes have no distinct supported version and fail closed.
_COUNTED_RECORD_FIELDS = frozenset(
    {"family", "status", "prompt", "proof", "kind", "attack_trials", "successes"}
)
_EVIDENCE_RECORD_FIELDS = _COUNTED_RECORD_FIELDS | {"trials"}


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
    canary_commitment: str = ""
    # Opaque, domain-separated binding of the run's disclosure-marker *state*
    # (present-and-which, or explicitly absent). Resume requires the supplied
    # marker to reproduce this exact commitment before any completed/progress/
    # in-flight evidence may be used, so old→new / marker→missing / missing→marker
    # substitution fails closed instead of inheriting a prior LLM02 confirmation.
    marker_commitment: str = ""
    # M3: per-case in-progress trials (so resume never repeats a completed trial)
    # and the single write-ahead attempt intent whose outcome was not yet recorded
    # (an issued-but-interrupted attempt — already counted, never reissued).
    progress: dict[str, dict[str, Any]] = field(default_factory=dict)
    in_flight: dict[str, Any] | None = None

    def to_body(self) -> dict[str, Any]:
        return {
            "checkpoint_version": CHECKPOINT_VERSION,
            "plan_digest": self.plan_digest,
            "state": self.state,
            "request_count": self.request_count,
            "canary": self.canary,
            "canary_commitment": self.canary_commitment,
            "marker_commitment": self.marker_commitment,
            # Sort for a stable, digestable, diff-friendly representation.
            "completed": {k: self.completed[k] for k in sorted(self.completed)},
            "control_results": {k: self.control_results[k] for k in sorted(self.control_results)},
            "progress": {k: self.progress[k] for k in sorted(self.progress)},
            "in_flight": self.in_flight,
        }


def marker_commitment(plan_digest: str, marker: str | None) -> str:
    """Compatibility name for the shared run-identity marker commitment."""
    return disclosure_marker_commitment(plan_digest, marker)


def _canonicalize_canary(value: Any, canary: str, persisted: str) -> Any:
    """Replace only this run's bound canary; never rewrite public marker text."""
    if isinstance(value, str):
        return value.replace(canary, persisted) if canary and persisted else value
    if isinstance(value, dict):
        return {key: _canonicalize_canary(item, canary, persisted) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize_canary(item, canary, persisted) for item in value]
    return value


def _sealed(checkpoint: Checkpoint, known_secrets: frozenset[str]) -> dict[str, Any]:
    # Canonicalize the synthetic canary before general redaction. Using the same
    # REDACTED token for both the canary and unrelated credentials is ambiguous:
    # offline proof derivation can select the wrong placeholder occurrence.
    canary = checkpoint.canary
    commitment = checkpoint.canary_commitment
    persisted = evidence_canary(commitment) if commitment else ""
    canonical = _canonicalize_canary(checkpoint.to_body(), canary, persisted)
    if commitment:
        canonical["canary"] = persisted
    remaining_secrets = frozenset(secret for secret in known_secrets if secret != canary)
    # Recursively scrub the body (credential literals, reflected known secrets,
    # URL-field secrets) *before* sealing, so the digest is computed over — and
    # matches — the redacted content that is actually persisted.
    body: dict[str, Any] = scrub_structure(canonical, remaining_secrets)
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
    path: str,
    *,
    expected_plan_digest: str,
    plan: object | None = None,
    disclosure_marker: str | None = None,
    expected_canary: str | None = None,
    expected_marker_commitment: str | None = None,
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
    if set(data) != _ALLOWED_FIELDS:
        raise CheckpointError("checkpoint has unknown or missing top-level fields")
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
        commitment = data["canary_commitment"]
        if not isinstance(commitment, str) or (
            commitment
            and (
                len(commitment) != 64
                or any(ch not in "0123456789abcdef" for ch in commitment)
            )
        ):
            raise CheckpointError("canary commitment is malformed")
        if commitment and canary != evidence_canary(commitment):
            raise CheckpointError("checkpoint evidence identity is malformed")
        if expected_canary is not None and commitment != canary_commitment(
            expected_plan_digest, expected_canary
        ):
            raise CheckpointError("checkpoint run identity does not match the supplied canary")
        marker_binding = data["marker_commitment"]
        if not isinstance(marker_binding, str) or (
            marker_binding
            and (
                len(marker_binding) != 64
                or any(ch not in "0123456789abcdef" for ch in marker_binding)
            )
        ):
            raise CheckpointError("marker commitment is malformed")
        # Fail closed on any disclosure-marker identity change (old→new,
        # marker→missing, missing→marker). Enforced only when the caller supplies
        # the expected commitment (a resuming run); a structural/diagnostic load
        # passes none. An evidence-bearing checkpoint must carry the binding, so a
        # re-digested document that strips it (to escape the check) is rejected.
        if expected_marker_commitment is not None:
            has_evidence = bool(
                data.get("completed") or data.get("progress") or data.get("in_flight") is not None
            )
            if not marker_binding and has_evidence:
                raise CheckpointError(
                    "checkpoint run identity lacks a disclosure-marker commitment"
                )
            if marker_binding and marker_binding != expected_marker_commitment:
                raise CheckpointError(
                    "checkpoint run identity does not match the supplied disclosure marker"
                )
        completed = _completed(data["completed"])
        control_results = _control_results(data["control_results"])
        progress = _progress(data.get("progress", {}))
        in_flight = _in_flight(data.get("in_flight"))
        checkpoint = Checkpoint(
            plan_digest=_require_str(data["plan_digest"], "plan_digest"),
            state=state,
            request_count=request_count,
            completed=completed,
            control_results=control_results,
            canary=canary,
            canary_commitment=commitment,
            marker_commitment=marker_binding,
            progress=progress,
            in_flight=in_flight,
        )
    except CheckpointError as exc:
        if "run identity" in str(exc):
            raise
        raise CheckpointError("malformed checkpoint") from exc
    except (KeyError, TypeError, ValueError) as exc:
        raise CheckpointError("malformed checkpoint") from exc
    if plan is not None:
        _bind_completed_to_plan(checkpoint, plan, disclosure_marker=disclosure_marker)
    return checkpoint


def _bind_completed_to_plan(
    checkpoint: Checkpoint, plan: object, *, disclosure_marker: str | None = None
) -> None:
    """Reject any completed record not derivable from the verified plan.

    Each record's case must exist in the plan with a matching family/kind and the
    exact rendered prompt (template rendered with the checkpoint's canary for an
    attack, the bare template for a control). Every evidence-bearing record is
    then re-derived from its persisted trials through the shared evidence
    contract (:func:`~ai_scan.orchestration.evidence.verify_records`): status,
    proof, trial and success counts, and per-family control coverage must all
    match, and the physical request count must cover the persisted attempts.
    Records without complete trial evidence are rejected.
    """
    from ai_scan.orchestration.evidence import (
        CaseEvidence,
        EvidenceError,
        is_marker_dependent_case,
        resolve_plan_packs,
        verify_records,
    )

    plan_cases = {c.case_id: c for c in plan.cases}  # type: ignore[attr-defined]
    from ai_scan.orchestration.planner import Plan

    typed_plan = cast(Plan, plan)
    if (
        checkpoint.completed or checkpoint.progress or checkpoint.in_flight is not None
    ) and not checkpoint.canary_commitment:
        raise CheckpointError("legacy checkpoint evidence lacks a run identity commitment")
    canary = checkpoint.canary
    try:
        expected_marker = disclosure_marker_commitment(typed_plan.digest, disclosure_marker)
        if checkpoint.marker_commitment != expected_marker:
            raise CheckpointError("checkpoint run identity does not match the disclosure marker")
        identity = RunIdentity.verify_persisted(
            typed_plan.digest,
            checkpoint.canary_commitment,
            checkpoint.marker_commitment,
            canary,
            evidence_marker(
                checkpoint.marker_commitment, present=disclosure_marker is not None
            ),
        )
    except (ValueError, CheckpointError) as exc:
        raise CheckpointError("checkpoint run identity is malformed") from exc
    packs = resolve_plan_packs(typed_plan)
    if checkpoint.request_count > plan.limits.max_physical_requests:  # type: ignore[attr-defined]
        raise CheckpointError("request_count exceeds the plan's physical request budget")
    evidence: list[CaseEvidence] = []
    for case_id, record in checkpoint.completed.items():
        case = plan_cases.get(case_id)
        if case is None:
            raise CheckpointError("completed record references a case not in the plan")
        if is_marker_dependent_case(packs[case.pack_id], case):
            raise CheckpointError("marker-dependent evidence is live-only and not resumable")
        if record.get("family") != case.family or record.get("kind") != case.kind:
            raise CheckpointError("completed record does not match its plan case")
        expected = case.template if case.kind == "control" else case.template.replace(
            "{canary}", canary
        )
        if record.get("prompt") != expected:
            raise CheckpointError("completed record prompt is not plan-derived")
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
    completed_physical = 0
    if evidence:
        try:
            verified = verify_records(
                typed_plan,
                packs,
                canary,
                evidence,
                disclosure_marker,
                identity,
            )
        except EvidenceError as exc:
            raise CheckpointError(f"completed record evidence is invalid: {exc}") from exc
        for family, result in verified.control_results.items():
            if checkpoint.control_results.get(family) != result:
                raise CheckpointError(
                    "control results do not match the persisted control evidence"
                )
        completed_physical = verified.physical_request_count

    # M3: bind per-case progress + the in-flight attempt to the plan, and require
    # the cumulative physical count to cover every persisted attempt (no reset /
    # undercount). progress trials are budget-bounded exactly like completed ones.
    from ai_scan.orchestration.evidence import rendered_prompt, trial_ceiling, trials_from_list
    budget = typed_plan.limits.max_physical_requests
    progress_physical = 0
    for case_id, record in checkpoint.progress.items():
        case = plan_cases.get(case_id)
        if case is None:
            raise CheckpointError("progress record references a case not in the plan")
        if is_marker_dependent_case(packs[case.pack_id], case):
            raise CheckpointError("marker-dependent progress evidence is live-only")
        if record.get("kind") != case.kind or record.get("family") != case.family:
            raise CheckpointError("progress record does not match its plan case")
        if record.get("prompt") != rendered_prompt(case, canary):
            raise CheckpointError("progress record prompt is not plan-derived")
        try:
            trials = trials_from_list(
                record.get("trials"),
                trial_ceiling(typed_plan, case),
                budget,
                plan=typed_plan,
                case=case,
                canary=canary,
                identity=identity,
            )
        except EvidenceError as exc:
            raise CheckpointError(f"progress trial evidence is invalid: {exc}") from exc
        progress_physical += sum(t.attempts for t in trials)
    in_flight_physical = 0
    if checkpoint.in_flight is not None:
        inf = checkpoint.in_flight
        case = plan_cases.get(inf["case_id"])
        if case is None:
            raise CheckpointError("in-flight attempt references a case not in the plan")
        if is_marker_dependent_case(packs[case.pack_id], case):
            raise CheckpointError("marker-dependent in-flight evidence is live-only")
        if (
            inf.get("kind") != case.kind
            or inf.get("family") != case.family
            or inf.get("prompt") != rendered_prompt(case, canary)
        ):
            raise CheckpointError("in-flight attempt does not match its plan case")
        in_flight_physical = int(inf["attempts"])
    total_physical = completed_physical + progress_physical + in_flight_physical
    if checkpoint.request_count != total_physical:
        raise CheckpointError(
            "request_count does not equal the persisted physical trial attempts"
        )
    if checkpoint.request_count > budget:
        raise CheckpointError("request_count exceeds the plan's physical request budget")


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
        if set(raw_record) != _EVIDENCE_RECORD_FIELDS:
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
        attack_trials = _require_int(raw_record["attack_trials"], "attack_trials", positive=False)
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
        normalized["trials"] = _trials(raw_record["trials"])
        out[case_id] = normalized
    return out


def _trials(value: object) -> list[dict[str, Any]]:
    """Structurally validate persisted trial evidence (plan binding re-derives it)."""
    from ai_scan.orchestration.evidence import EvidenceError, trial_from_dict

    if not isinstance(value, list) or not value:
        raise CheckpointError("completed record trials must be a non-empty list")
    try:
        normalized: list[dict[str, Any]] = []
        for item in value:
            trial_from_dict(item)
            normalized.append(dict(item))
        return normalized
    except EvidenceError as exc:
        raise CheckpointError("completed record trial evidence is malformed") from exc


def _progress(value: object) -> dict[str, dict[str, Any]]:
    """Structurally validate per-case in-progress trials (plan binding re-derives)."""
    from ai_scan.orchestration.evidence import EvidenceError, trial_from_dict

    if not isinstance(value, dict):
        raise CheckpointError("progress must be an object")
    out: dict[str, dict[str, Any]] = {}
    for case_id, record in value.items():
        _require_str(case_id, "progress case_id")
        if not isinstance(record, dict) or set(record) != {"kind", "family", "prompt", "trials"}:
            raise CheckpointError("progress record has unknown or missing field(s)")
        kind = _require_str(record["kind"], "kind")
        if kind not in {"attack", "control"}:
            raise CheckpointError("invalid progress kind")
        family = _require_str(record["family"], "family")
        prompt = _require_str(record["prompt"], "prompt")
        raw_trials = record["trials"]
        if not isinstance(raw_trials, list) or not raw_trials:
            raise CheckpointError("progress record trials must be a non-empty list")
        try:
            trials = []
            for item in raw_trials:
                trial_from_dict(item)
                trials.append(dict(item))
        except EvidenceError as exc:
            raise CheckpointError("progress record trial evidence is malformed") from exc
        out[case_id] = {"kind": kind, "family": family, "prompt": prompt, "trials": trials}
    return out


def _in_flight(value: object) -> dict[str, Any] | None:
    """Validate the single write-ahead attempt intent (an issued, uncounted-outcome)."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) not in (
        {"case_id", "kind", "family", "prompt"},
        {"case_id", "kind", "family", "prompt", "attempts"},
    ):
        raise CheckpointError("in_flight has unknown or missing field(s)")
    kind = _require_str(value["kind"], "kind")
    if kind not in {"attack", "control"}:
        raise CheckpointError("invalid in_flight kind")
    return {
        "case_id": _require_str(value["case_id"], "case_id"),
        "kind": kind,
        "family": _require_str(value["family"], "family"),
        "prompt": _require_str(value["prompt"], "prompt"),
        "attempts": _require_int(value.get("attempts", 0), "attempts", positive=False),
    }


def _control_results(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise CheckpointError("control_results must be an object")
    out: dict[str, str] = {}
    for key, raw in value.items():
        family = _require_str(key, "family")
        if isinstance(raw, str) and raw in _VALID_CONTROL_RESULTS:
            out[family] = raw
        else:
            raise CheckpointError("invalid control result")
    return out
