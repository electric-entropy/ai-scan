"""The single evidence contract shared by live runs, checkpoints, bundles, replay.

A persisted case record is evidence only if its status can be re-derived from
its own persisted physical trials under the canonical plan. The same functions
classify a live run (:mod:`~ai_scan.orchestration.runner`), bind a resumed
checkpoint (:mod:`~ai_scan.orchestration.checkpoint`), and verify an exported
bundle and its replay (:mod:`ai_scan.evidence_graph`), so no path can hold a
weaker notion of ``confirmed`` than another.

For every record:

* the case exists in the verified plan, with matching kind;
* it carries 1..N persisted trials (N = the plan's per-kind trial count), each a
  closed-schema outcome with a positive integer physical ``attempts``;
* a control's result (``clean``/``emitted``/``gap``) and status are re-derived
  from its trials; per-family control coverage is the merge of those results;
* an attack's status, proof, usable-trial count and success count are
  re-derived from its trials against its family's *derived* control coverage at
  the plan's thresholds.

The physical request count is the sum of persisted trial attempts. An exact
final-token response (the bare canary) is therefore confirmable only when the
repeatability, matched clean controls, and physical counts are all present as
persisted evidence — a single forged body or a claimed count never suffices.
The digest over this evidence is tamper-evidence, not a signature: a forger who
fabricates a fully self-consistent run is out of scope for offline replay.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ai_scan.core.modes import resolve_policy
from ai_scan.injection import (
    CONTROL_CLEAN,
    CONTROL_EMITTED,
    CONTROL_GAP,
    ExchangeOutcome,
    InjectionStatus,
    _select_validators,
    control_result,
    evaluate_trials,
    merge_control_results,
    physical_attempts,
)
from ai_scan.orchestration.planner import Plan, PlannedCase
from ai_scan.packs import Pack, resolve_packs

TRIAL_FIELDS = frozenset({
    "body", "status", "redirected", "truncated", "transport_ok", "attempts", "semantic"
})
SEMANTIC_VERSION = 1
SEMANTIC_NORMALIZATION = "strip-v1"
SEMANTIC_FIELDS = frozenset({
    "version",
    "normalization",
    "plan_digest",
    "case_id",
    "pack_id",
    "family",
    "kind",
    "marker_digest",
    "body_digest",
    "exact_match",
})
_DISCLOSURE_SENTINEL = "AISCAN-SEMANTIC-DISCLOSURE-MATCH"
_REDACTION_PLACEHOLDERS = frozenset({"REDACTED", "[REDACTED]"})

# The persisted status of a control case, derived from its coverage result.
CONTROL_STATUS = {
    CONTROL_EMITTED: InjectionStatus.SUSPECTED,
    CONTROL_CLEAN: InjectionStatus.NOT_OBSERVED,
    CONTROL_GAP: InjectionStatus.INCONCLUSIVE,
}


class EvidenceError(ValueError):
    """Raised when persisted evidence does not satisfy the evidence contract."""


@dataclass(frozen=True)
class DerivedCase:
    """A case's classification re-derived from its persisted trials."""

    status: InjectionStatus
    proof: str | None
    attack_trials: int
    successes: int


@dataclass(frozen=True)
class VerifiedEvidence:
    """The outcome of verifying a set of records against the contract."""

    control_results: Mapping[str, str]
    findings: Mapping[str, DerivedCase]
    physical_request_count: int


def resolve_plan_packs(plan: Plan) -> dict[str, Pack]:
    """Resolve the plan's packs offline under its mode policy (fail closed)."""
    try:
        policy = resolve_policy(plan.mode)
        resolved = {p.id: p for p in resolve_packs(plan.mode, trust=policy.pack_trust)}
    except Exception as exc:  # PolicyError / PackResolutionError
        raise EvidenceError("cannot resolve packs for the plan mode") from exc
    if {c.pack_id for c in plan.cases} - set(resolved):
        raise EvidenceError("plan references packs that no longer resolve")
    return resolved


def family_key(case: PlannedCase) -> str:
    return f"{case.pack_id}:{case.family}"


def rendered_prompt(case: PlannedCase, canary: str) -> str:
    """The prompt a case sends: the canary-rendered template for an attack."""
    return case.template.replace("{canary}", canary) if case.kind == "attack" else case.template


def trial_to_dict(outcome: ExchangeOutcome) -> dict[str, Any]:
    """Serialize one physical trial outcome (known secrets are never persisted)."""
    return {
        "body": outcome.body,
        "status": outcome.status,
        "redirected": outcome.redirected,
        "truncated": outcome.truncated,
        "transport_ok": outcome.transport_ok,
        "attempts": physical_attempts(outcome),
        "semantic": outcome.semantic,
    }


def trial_from_dict(raw: object) -> ExchangeOutcome:
    """Strictly parse one persisted trial (closed schema, exact types)."""
    if not isinstance(raw, Mapping):
        raise EvidenceError("trial evidence has unknown or missing fields")
    fields = set(raw)
    if fields == TRIAL_FIELDS - {"semantic"}:
        raw = dict(raw)
        raw["semantic"] = None
    elif fields != TRIAL_FIELDS:
        raise EvidenceError("trial evidence has unknown or missing fields")
    body, status, attempts = raw["body"], raw["status"], raw["attempts"]
    flags = (raw["redirected"], raw["truncated"], raw["transport_ok"])
    if not isinstance(body, str) or not all(isinstance(flag, bool) for flag in flags):
        raise EvidenceError("trial evidence has invalid field types")
    for number in (status, attempts):
        if isinstance(number, bool) or not isinstance(number, int):
            raise EvidenceError("trial evidence has invalid field types")
    if not 0 <= status <= 999:
        raise EvidenceError("trial evidence has an invalid HTTP status")
    if attempts < 1:
        raise EvidenceError("trial evidence must record at least one physical attempt")
    return ExchangeOutcome(
        body=body,
        status=status,
        redirected=flags[0],
        truncated=flags[1],
        transport_ok=flags[2],
        attempts=attempts,
        semantic=_semantic_from_dict(raw["semantic"]),
    )


def _semantic_from_dict(raw: object) -> dict[str, Any] | None:
    if raw is None:
        return None
    if not isinstance(raw, Mapping) or set(raw) != SEMANTIC_FIELDS:
        raise EvidenceError("trial semantic evidence is malformed")
    out = dict(raw)
    if out["version"] != SEMANTIC_VERSION or out["normalization"] != SEMANTIC_NORMALIZATION:
        raise EvidenceError("trial semantic evidence has unsupported version")
    string_fields = (
        "plan_digest", "case_id", "pack_id", "family", "kind", "marker_digest", "body_digest"
    )
    if not all(isinstance(out[field], str) and out[field] for field in string_fields):
        raise EvidenceError("trial semantic evidence has invalid field types")
    if out["kind"] not in {"attack", "control"} or not isinstance(out["exact_match"], bool):
        raise EvidenceError("trial semantic evidence has invalid field types")
    for digest_field in ("marker_digest", "body_digest"):
        value = out[digest_field]
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise EvidenceError("trial semantic evidence has invalid digest")
    if out["exact_match"] != (out["marker_digest"] == out["body_digest"]):
        raise EvidenceError("trial semantic match flag contradicts its digests")
    return out


def _semantic_digest(plan: Plan, case: PlannedCase, value: str) -> str:
    payload = {
        "version": SEMANTIC_VERSION,
        "normalization": SEMANTIC_NORMALIZATION,
        "plan_digest": plan.digest,
        "case_id": case.case_id,
        "pack_id": case.pack_id,
        "family": case.family,
        "kind": case.kind,
        "normalized": value.strip(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def disclosure_semantic(plan: Plan, case: PlannedCase, marker: str, body: str) -> dict[str, Any]:
    """Return non-secret exact-match metadata for LLM02 final-body disclosure."""
    marker_digest = _semantic_digest(plan, case, marker)
    body_digest = _semantic_digest(plan, case, body)
    return {
        "version": SEMANTIC_VERSION,
        "normalization": SEMANTIC_NORMALIZATION,
        "plan_digest": plan.digest,
        "case_id": case.case_id,
        "pack_id": case.pack_id,
        "family": case.family,
        "kind": case.kind,
        "marker_digest": marker_digest,
        "body_digest": body_digest,
        "exact_match": marker_digest == body_digest,
    }


def trials_from_list(
    raw: object, ceiling: int, budget: int | None = None
) -> tuple[ExchangeOutcome, ...]:
    """Parse a record's trials; ``budget`` bounds each trial's physical attempts."""
    if not isinstance(raw, list) or not raw:
        raise EvidenceError("record must carry its persisted trial evidence")
    if len(raw) > ceiling:
        raise EvidenceError("record carries more trials than the plan can substantiate")
    trials = tuple(trial_from_dict(item) for item in raw)
    if budget is not None and any(t.attempts > budget for t in trials):
        raise EvidenceError("trial physical attempts exceed the plan budget")
    return trials


def trial_ceiling(plan: Plan, case: PlannedCase) -> int:
    attack_trials, _successes, control_trials = plan.trial_policy
    return attack_trials if case.kind == "attack" else control_trials


def _is_disclosure_pack(pack: Pack) -> bool:
    categories = frozenset(pack.mappings.get("owasp-llm", ()))
    return "LLM02" in categories and "LLM01" not in categories


def _case_token(pack: Pack, prompt_canary: str, disclosure_marker: str | None) -> str:
    if _is_disclosure_pack(pack):
        if disclosure_marker in _REDACTION_PLACEHOLDERS:
            return _DISCLOSURE_SENTINEL
        if disclosure_marker is None:
            return _DISCLOSURE_SENTINEL
        return disclosure_marker
    return prompt_canary


def _bind_semantic(plan: Plan, case: PlannedCase, trial: ExchangeOutcome) -> dict[str, Any] | None:
    semantic = trial.semantic
    if semantic is None:
        return None
    expected = {
        "plan_digest": plan.digest,
        "case_id": case.case_id,
        "pack_id": case.pack_id,
        "family": case.family,
        "kind": case.kind,
    }
    for key, value in expected.items():
        if semantic.get(key) != value:
            raise EvidenceError("trial semantic evidence does not match the plan case")
    return semantic


def _disclosure_final_only_trials(
    plan: Plan,
    case: PlannedCase,
    pack: Pack,
    trials: Sequence[ExchangeOutcome],
    canary: str,
    disclosure_marker: str | None,
) -> Sequence[ExchangeOutcome]:
    """For LLM02, only whole final assistant content may disclose the marker.

    Redacted persisted bodies are never semantic evidence. A disclosure trial must
    carry pre-redaction semantic metadata bound to this plan/case; legacy LLM02
    persisted evidence without it cannot confirm. Live in-memory trials may also
    be evaluated directly when the real disclosure marker is supplied.
    """
    categories = frozenset(pack.mappings.get("owasp-llm", ()))
    if "LLM02" not in categories or "LLM01" in categories:
        return trials
    token = _case_token(pack, canary, disclosure_marker)
    filtered: list[ExchangeOutcome] = []
    for trial in trials:
        semantic = _bind_semantic(plan, case, trial)
        if semantic is not None and disclosure_marker is None:
            raise EvidenceError("LLM02 semantic evidence requires an explicit disclosure marker")
        if semantic is not None:
            matched = bool(semantic["exact_match"])
        elif disclosure_marker is not None and disclosure_marker not in _REDACTION_PLACEHOLDERS:
            matched = trial.body.strip() == disclosure_marker
        else:
            matched = False
        filtered.append(
            ExchangeOutcome(
                body=token if matched else "",
                status=trial.status,
                redirected=trial.redirected,
                truncated=trial.truncated,
                transport_ok=trial.transport_ok,
                attempts=trial.attempts,
                known_secrets=trial.known_secrets,
                semantic=trial.semantic,
            )
        )
    return tuple(filtered)


def derive_control(
    plan: Plan,
    case: PlannedCase,
    pack: Pack,
    trials: Sequence[ExchangeOutcome],
    canary: str,
    disclosure_marker: str | None = None,
) -> str:
    trials = _disclosure_final_only_trials(plan, case, pack, trials, canary, disclosure_marker)
    return control_result(
        trials, _case_token(pack, canary, disclosure_marker), plan.trial_policy[2]
    )


def derive_attack(
    plan: Plan,
    case: PlannedCase,
    pack: Pack,
    trials: Sequence[ExchangeOutcome],
    canary: str,
    disclosure_marker: str | None,
    control: str | None,
) -> tuple[DerivedCase, ExchangeOutcome | None]:
    """Classify an attack case's trials at the plan thresholds (live and offline)."""
    success_token = _case_token(pack, canary, disclosure_marker)
    trials = _disclosure_final_only_trials(plan, case, pack, trials, canary, disclosure_marker)
    status, proof, usable, successes, representative = evaluate_trials(
        trials,
        success_token,
        rendered_prompt(case, canary),
        _select_validators(pack.validators),
        control_succeeded=control == CONTROL_EMITTED,
        matched_clean_control=control == CONTROL_CLEAN,
        min_attack_trials=plan.trial_policy[0],
        min_successes=plan.trial_policy[1],
        requires_state_change=pack.side_effects,
    )
    if _is_disclosure_pack(pack) and status.value == "confirmed":
        proof = "REDACTED"
    return DerivedCase(status, proof, usable, successes), representative


@dataclass(frozen=True)
class CaseEvidence:
    """One persisted record, normalized for verification.

    ``pack_id``/``family``/``prompt`` are bound to the plan case when the
    persisted format carries them (``None`` means the format does not store it).
    """

    case_id: str
    kind: str
    status: str
    proof: str | None
    attack_trials: int
    successes: int
    trials: Sequence[object]
    pack_id: str | None = None
    family: str | None = None
    prompt: str | None = None


def derive_records(
    plan: Plan,
    packs: Mapping[str, Pack],
    canary: str,
    records: Iterable[CaseEvidence],
    disclosure_marker: str | None = None,
) -> VerifiedEvidence:
    """Bind records to the plan and derive every classification from its trials.

    Structural and plan-binding failures raise; the stored statuses are *not*
    compared here (see :func:`verify_records`).
    """
    if not isinstance(canary, str) or not canary:
        raise EvidenceError("evidence requires the run canary")
    cases = {c.case_id: c for c in plan.cases}
    parsed: list[tuple[CaseEvidence, PlannedCase, tuple[ExchangeOutcome, ...]]] = []
    seen: set[str] = set()
    for record in records:
        case = cases.get(record.case_id)
        if case is None:
            raise EvidenceError("record references a case not in the plan")
        if record.case_id in seen:
            raise EvidenceError("duplicate record for one plan case")
        seen.add(record.case_id)
        if record.kind != case.kind:
            raise EvidenceError("record kind does not match its plan case")
        if record.pack_id is not None and record.pack_id != case.pack_id:
            raise EvidenceError("record pack_id does not match its plan case")
        if record.family is not None and record.family != case.family:
            raise EvidenceError("record family does not match its plan case")
        if record.prompt is not None and record.prompt != rendered_prompt(case, canary):
            raise EvidenceError("record prompt does not match the rendered plan case")
        if case.pack_id not in packs:
            raise EvidenceError("record references a pack that does not resolve")
        trials = trials_from_list(
            record.trials, trial_ceiling(plan, case), plan.limits.max_physical_requests
        )
        parsed.append((record, case, trials))

    # Every trial is individually bounded by the budget, so the running sum is
    # checked after each addition and can never grow past budget + budget.
    budget = plan.limits.max_physical_requests
    controls: dict[str, str] = {}
    findings: dict[str, DerivedCase] = {}
    physical = 0
    for _record, _case, trials in parsed:
        for trial in trials:
            physical += trial.attempts
            if physical > budget:
                raise EvidenceError("persisted physical attempts exceed the plan budget")
    for _record, case, trials in parsed:
        if case.kind == "control":
            result = derive_control(
                plan, case, packs[case.pack_id], trials, canary, disclosure_marker
            )
            key = family_key(case)
            controls[key] = merge_control_results(controls.get(key), result)
            findings[case.case_id] = DerivedCase(CONTROL_STATUS[result], None, 0, 0)
    for _record, case, trials in parsed:
        if case.kind == "attack":
            derived, _rep = derive_attack(
                plan,
                case,
                packs[case.pack_id],
                trials,
                canary,
                disclosure_marker,
                controls.get(family_key(case)),
            )
            findings[case.case_id] = derived
    return VerifiedEvidence(controls, findings, physical)


def verify_records(
    plan: Plan,
    packs: Mapping[str, Pack],
    canary: str,
    records: Iterable[CaseEvidence],
    disclosure_marker: str | None = None,
) -> VerifiedEvidence:
    """Re-derive every record from its persisted trials; fail closed on mismatch."""
    records = list(records)
    verified = derive_records(plan, packs, canary, records, disclosure_marker)
    for record in records:
        derived = verified.findings[record.case_id]
        mismatched = [
            name
            for name, stored, expected in (
                ("status", record.status, derived.status.value),
                ("proof", record.proof, derived.proof),
                ("attack_trials", record.attack_trials, derived.attack_trials),
                ("successes", record.successes, derived.successes),
            )
            if stored != expected
        ]
        if mismatched:
            raise EvidenceError(
                f"{record.kind} record {', '.join(mismatched)} does not match its persisted trials"
            )
    return verified


__all__ = [
    "CONTROL_STATUS",
    "TRIAL_FIELDS",
    "CaseEvidence",
    "DerivedCase",
    "EvidenceError",
    "VerifiedEvidence",
    "derive_attack",
    "derive_control",
    "derive_records",
    "family_key",
    "rendered_prompt",
    "resolve_plan_packs",
    "trial_from_dict",
    "trial_to_dict",
    "trials_from_list",
    "verify_records",
    "disclosure_semantic",
]
