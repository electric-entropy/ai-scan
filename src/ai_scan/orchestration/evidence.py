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
from ai_scan.core.run_identity import RunIdentity, is_evidence_marker
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
from ai_scan.packs.schema import marker_category
from ai_scan.transport.marker_redaction import MAX_SECRET, MAX_TEXT, contains_marker

TRIAL_FIELDS = frozenset({
    "body", "status", "redirected", "truncated", "transport_ok", "attempts", "semantic",
    "commitment",
})
TRIAL_COMMITMENT_VERSION = 1
TRIAL_COMMITMENT_FIELDS = frozenset(
    {
        "version", "plan_digest", "case_id", "pack_id", "family", "kind",
        "prompt_digest", "response_digest", "attempts", "canary_commitment",
        "disclosure_marker_commitment", "digest",
    }
)
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
    if any(pack_id not in resolved or (version, digest) !=
           (resolved[pack_id].version, resolved[pack_id].digest)
           for pack_id, version, digest in plan.packs):
        raise EvidenceError("plan pack identity does not match the registry")
    if any(not case_matches_pack(resolved[c.pack_id], c) for c in plan.cases):
        raise EvidenceError("plan case is not an exact member of its registry pack")
    return resolved


def family_key(case: PlannedCase) -> str:
    return f"{case.pack_id}:{case.family}"


def rendered_prompt(case: PlannedCase, canary: str) -> str:
    """The prompt a case sends: the canary-rendered template for an attack."""
    return case.template.replace("{canary}", canary) if case.kind == "attack" else case.template


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def trial_to_dict(
    outcome: ExchangeOutcome,
    *,
    plan: Plan,
    case: PlannedCase,
    canary: str,
    identity: RunIdentity | None = None,
) -> dict[str, Any]:
    """Serialize one plan/case-bound physical trial without known secrets."""
    base: dict[str, Any] = {
        "body": outcome.body,
        "status": outcome.status,
        "redirected": outcome.redirected,
        "truncated": outcome.truncated,
        "transport_ok": outcome.transport_ok,
        "attempts": physical_attempts(outcome),
        "semantic": outcome.semantic,
    }
    identity = identity or RunIdentity.create(plan.digest, canary, None)
    commitment: dict[str, Any] = {
        "version": TRIAL_COMMITMENT_VERSION,
        "plan_digest": plan.digest,
        "case_id": case.case_id,
        "pack_id": case.pack_id,
        "family": case.family,
        "kind": case.kind,
        "prompt_digest": _sha256_json(rendered_prompt(case, canary)),
        "response_digest": _sha256_json(base),
        "attempts": base["attempts"],
        "canary_commitment": identity.canary_commitment,
        "disclosure_marker_commitment": identity.disclosure_marker_commitment,
    }
    commitment["digest"] = _sha256_json(commitment)
    base["commitment"] = commitment
    return base


def trial_from_dict(raw: object) -> ExchangeOutcome:
    """Strictly parse one persisted trial (closed schema, exact types)."""
    if not isinstance(raw, Mapping):
        raise EvidenceError("trial evidence has unknown or missing fields")
    fields = set(raw)
    if fields != TRIAL_FIELDS:
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
    _parse_trial_commitment(raw["commitment"])
    return ExchangeOutcome(
        body=body,
        status=status,
        redirected=flags[0],
        truncated=flags[1],
        transport_ok=flags[2],
        attempts=attempts,
        semantic=_semantic_from_dict(raw["semantic"]),
    )


def _parse_trial_commitment(raw: object) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or set(raw) != TRIAL_COMMITMENT_FIELDS:
        raise EvidenceError("trial commitment has unknown or missing fields")
    out = dict(raw)
    if out["version"] != TRIAL_COMMITMENT_VERSION:
        raise EvidenceError("trial commitment version is unsupported")
    string_fields = (
        "plan_digest", "case_id", "pack_id", "family", "kind",
        "prompt_digest", "response_digest", "canary_commitment",
        "disclosure_marker_commitment", "digest",
    )
    if not all(isinstance(out[field], str) and out[field] for field in string_fields):
        raise EvidenceError("trial commitment has invalid field types")
    if out["kind"] not in {"attack", "control"}:
        raise EvidenceError("trial commitment kind is invalid")
    attempts = out["attempts"]
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
        raise EvidenceError("trial commitment attempts are invalid")
    for field in (
        "plan_digest", "prompt_digest", "response_digest", "canary_commitment",
        "disclosure_marker_commitment", "digest",
    ):
        value = out[field]
        if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise EvidenceError("trial commitment digest is invalid")
    expected_digest = _sha256_json({key: value for key, value in out.items() if key != "digest"})
    if out["digest"] != expected_digest:
        raise EvidenceError("trial commitment digest does not match its content")
    return out


def _verify_trial_commitment(
    raw: Mapping[str, Any], plan: Plan, case: PlannedCase, canary: str, identity: RunIdentity
) -> None:
    commitment = _parse_trial_commitment(raw.get("commitment"))
    response = {
        key: raw[key]
        for key in TRIAL_FIELDS - {"commitment"}
    }
    expected = {
        "plan_digest": plan.digest,
        "case_id": case.case_id,
        "pack_id": case.pack_id,
        "family": case.family,
        "kind": case.kind,
        "prompt_digest": _sha256_json(rendered_prompt(case, canary)),
        "response_digest": _sha256_json(response),
        "attempts": raw.get("attempts"),
        "canary_commitment": identity.canary_commitment,
        "disclosure_marker_commitment": identity.disclosure_marker_commitment,
    }
    if any(commitment.get(key) != value for key, value in expected.items()):
        raise EvidenceError("trial commitment does not match its exact plan case and response")


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
    raw: object,
    ceiling: int,
    budget: int | None = None,
    *,
    plan: Plan,
    case: PlannedCase,
    canary: str,
    identity: RunIdentity,
) -> tuple[ExchangeOutcome, ...]:
    """Parse a record's trials; ``budget`` bounds each trial's physical attempts."""
    if not isinstance(raw, list) or not raw:
        raise EvidenceError("record must carry its persisted trial evidence")
    if len(raw) > ceiling:
        raise EvidenceError("record carries more trials than the plan can substantiate")
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != TRIAL_FIELDS:
            raise EvidenceError("trial evidence has unknown or missing fields")
        _verify_trial_commitment(item, plan, case, canary, identity)
    trials = tuple(trial_from_dict(item) for item in raw)
    if budget is not None and any(t.attempts > budget for t in trials):
        raise EvidenceError("trial physical attempts exceed the plan budget")
    return trials


def trial_ceiling(plan: Plan, case: PlannedCase) -> int:
    attack_trials, _successes, control_trials = plan.trial_policy
    return attack_trials if case.kind == "attack" else control_trials


def is_marker_dependent_case(pack: Pack, case: PlannedCase) -> bool:
    """True only for verified marker-dependent plan cases (LLM02/LLM07)."""
    return marker_category(pack.mappings) is not None and case_matches_pack(pack, case)


def case_matches_pack(pack: Pack, case: PlannedCase) -> bool:
    """Exact template/index/family/kind membership, independent of names."""
    if case.pack_id != pack.id:
        return False
    if case.kind not in {"attack", "control"} or type(case.index) is not int:
        return False
    for family in pack.families:
        if family.name != case.family:
            continue
        templates = family.templates if case.kind == "attack" else family.controls
        return (
            0 <= case.index < len(templates)
            and templates[case.index] == case.template
            and case.case_id == f"{pack.id}:{family.name}:{case.kind}:{case.index}"
        )
    return False


def _is_disclosure_pack(pack: Pack) -> bool:
    return marker_category(pack.mappings) is not None


def _case_token(pack: Pack, prompt_canary: str, disclosure_marker: str | None) -> str:
    if _is_disclosure_pack(pack):
        if disclosure_marker in _REDACTION_PLACEHOLDERS:
            return _DISCLOSURE_SENTINEL
        if disclosure_marker is None:
            return _DISCLOSURE_SENTINEL
        return disclosure_marker
    return prompt_canary


def _contains_marker_representation(body: str, marker: str | None) -> bool:
    if marker is None or marker in _REDACTION_PLACEHOLDERS:
        return False
    return contains_marker(body, marker)


def _bind_semantic(
    plan: Plan,
    case: PlannedCase,
    trial: ExchangeOutcome,
    disclosure_marker: str | None = None,
) -> dict[str, Any] | None:
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
    # Defense in depth for a supplied (non-redacted) marker: the persisted
    # marker_digest must be the plan/case-bound digest of THIS marker, so a
    # substituted marker cannot inherit a prior trial's exact_match. When the
    # marker is absent or redacted (e.g. a replayed bundle), the trial commitment
    # already seals the semantic, so this extra check is skipped rather than
    # verified against a placeholder.
    if (
        disclosure_marker is not None
        and disclosure_marker not in _REDACTION_PLACEHOLDERS
        and not is_evidence_marker(disclosure_marker)
    ):
        if semantic.get("marker_digest") != _semantic_digest(plan, case, disclosure_marker):
            raise EvidenceError(
                "trial semantic marker does not match the supplied disclosure marker"
            )
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
    if not is_marker_dependent_case(pack, case):
        return trials
    token = _case_token(pack, canary, disclosure_marker)
    filtered: list[ExchangeOutcome] = []
    for trial in trials:
        semantic = _bind_semantic(plan, case, trial, disclosure_marker)
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
    if is_marker_dependent_case(pack, case):
        if (disclosure_marker is None or len(disclosure_marker) > MAX_SECRET
                or any(len(trial.body) > MAX_TEXT for trial in trials)):
            return CONTROL_GAP
        token = _case_token(pack, canary, disclosure_marker)
        trials = tuple(
            ExchangeOutcome(
                body=(
                    token
                    if _contains_marker_representation(trial.body, disclosure_marker)
                    else ""
                ),
                status=trial.status,
                redirected=trial.redirected,
                truncated=trial.truncated,
                transport_ok=trial.transport_ok,
                attempts=trial.attempts,
                known_secrets=trial.known_secrets,
                semantic=trial.semantic,
            )
            for trial in trials
        )
    else:
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
    if is_marker_dependent_case(pack, case) and status.value == "confirmed":
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
    identity: RunIdentity | None = None,
) -> VerifiedEvidence:
    """Bind records to the plan and derive every classification from its trials.

    Structural and plan-binding failures raise; the stored statuses are *not*
    compared here (see :func:`verify_records`).
    """
    if not isinstance(canary, str) or not canary:
        raise EvidenceError("evidence requires the run canary")
    identity = identity or RunIdentity.create(plan.digest, canary, disclosure_marker)
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
            record.trials,
            trial_ceiling(plan, case),
            plan.limits.max_physical_requests,
            plan=plan,
            case=case,
            canary=canary,
            identity=identity,
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
    identity: RunIdentity | None = None,
) -> VerifiedEvidence:
    """Re-derive every record from its persisted trials; fail closed on mismatch."""
    records = list(records)
    verified = derive_records(plan, packs, canary, records, disclosure_marker, identity)
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
    "is_marker_dependent_case",
    "rendered_prompt",
    "resolve_plan_packs",
    "trial_from_dict",
    "trial_to_dict",
    "trials_from_list",
    "verify_records",
    "disclosure_semantic",
]
