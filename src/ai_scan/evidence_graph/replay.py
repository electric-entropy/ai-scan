"""Offline replay: verify a bundle, then reproduce the M7 classification.

:func:`replay_bundle` first loads and fully verifies the bundle (all digests,
plan validity, graph invariants, secret-free boundary). It then reconstructs the
stored redacted response/control evidence and re-runs the *same* validator
selection and confidence predicate used at scan time — constructing no
transport, adapter, or network call — and asserts the reproduced finding
statuses/proofs match the stored ones. Any inconsistency (missing plan, plan
digest mismatch, missing response for a finding, duplicate ids, dangling edge,
re-digested tamper, or unredacted secret) fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ai_scan.core.modes import resolve_policy
from ai_scan.evidence_graph.bundle import Bundle, BundleError, load_bundle
from ai_scan.injection import (
    ExchangeOutcome,
    _select_validators,
    classify_record,
)
from ai_scan.packs import Pack, resolve_packs


class ReplayError(Exception):
    """Raised when a bundle cannot be verified or its findings do not reproduce."""


@dataclass(frozen=True)
class ReplayResult:
    """The outcome of a successful replay."""

    verified: bool
    findings: Mapping[str, str] = field(default_factory=dict)
    coverage_gaps: tuple[str, ...] = field(default_factory=tuple)
    canary: str = ""


def _family_key(pack_id: str, family: str) -> str:
    return f"{pack_id}:{family}"


def _expected_prompt(case: Any, canary: str) -> str:
    """The prompt the runner recorded for ``case`` (rendered for attacks).

    Attacks record the canary-substituted template; controls record the template
    verbatim. Replay derives this from the *verified plan*, never trusting the
    prompt stored on the (potentially re-digested) record.
    """
    if case.kind == "attack":
        return str(case.template).replace("{canary}", canary)
    return str(case.template)


def _bind_records_to_plan(
    records: list[dict[str, Any]],
    case_by_id: Mapping[str, Any],
    canary: str,
    trial_policy: tuple[int, int, int],
) -> None:
    """Fail closed unless every record matches its plan case exactly.

    Runs before any control aggregation or classification, so a forged record
    (re-digested with a mutated prompt/pack/family/kind, referencing a case not
    in the plan, or inflating its physical trial counts) can never contribute
    its metadata to the replayed result.
    """
    # The runner runs at most trial_policy[0] physical attempts per attack case
    # (trial_policy[2] for controls), so those are the plan-substantiated per-case
    # ceilings; a re-digested bundle cannot claim more attempts than the plan
    # could physically have produced.
    attack_ceiling, control_ceiling = trial_policy[0], trial_policy[2]
    for record in records:
        case_id = str(record.get("case_id"))
        case = case_by_id.get(case_id)
        if case is None:
            raise ReplayError(f"record {case_id} references a case not in the plan")
        if str(record.get("pack_id")) != case.pack_id:
            raise ReplayError(f"record {case_id} pack_id does not match the plan case")
        if str(record.get("family")) != case.family:
            raise ReplayError(f"record {case_id} family does not match the plan case")
        if str(record.get("kind")) != case.kind:
            raise ReplayError(f"record {case_id} kind does not match the plan case")
        if str(record.get("prompt", "")) != _expected_prompt(case, canary):
            raise ReplayError(
                f"record {case_id} prompt does not match the rendered plan case"
            )
        finding = record.get("finding")
        if not isinstance(finding, Mapping):
            raise ReplayError(f"record {case_id} is missing its finding metadata")
        trials = finding.get("attack_trials")
        successes = finding.get("successes")
        ceiling = attack_ceiling if case.kind == "attack" else control_ceiling
        if (
            not isinstance(trials, int) or isinstance(trials, bool) or trials < 0
            or not isinstance(successes, int) or isinstance(successes, bool) or successes < 0
        ):
            raise ReplayError(f"record {case_id} has invalid trial metadata")
        if successes > trials:
            raise ReplayError(f"record {case_id} reports more successes than trials")
        if trials > ceiling:
            raise ReplayError(
                f"record {case_id} claims more physical trials than the plan can substantiate"
            )


def _usable(response: Mapping[str, Any]) -> bool:
    return (
        bool(response.get("transport_ok"))
        and not response.get("redirected")
        and int(response.get("status", 0)) < 400
        and not response.get("truncated")
    )


def replay_bundle(source: str | Bundle) -> ReplayResult:
    """Verify ``source`` and reproduce its classification offline."""
    try:
        bundle = source if isinstance(source, Bundle) else load_bundle(source)
        plan = bundle.plan()
    except BundleError as exc:
        raise ReplayError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - load_bundle already validated
        raise ReplayError("bundle plan is unusable") from exc

    canary = bundle.canary
    records = bundle.records
    case_ids = [str(r["case_id"]) for r in records]
    if len(set(case_ids)) != len(case_ids):
        raise ReplayError("duplicate record id in bundle")

    packs = _resolve_packs(plan.mode)
    case_kinds = {c.case_id: c for c in plan.cases}

    # Bind every record to its verified plan case (case_id → exact
    # pack_id/family/kind/rendered-prompt) BEFORE any field is used for control
    # aggregation or classification. A re-digested forgery cannot smuggle a
    # mutated prompt/pack/family/kind past this gate.
    _bind_records_to_plan(records, case_kinds, canary, plan.trial_policy)

    # Re-derive per-family control coverage from the stored control evidence
    # (tri-state, mirroring the runner: emitted > clean > gap). pack_id/family
    # come from the bound plan case, not the (now-verified-equal) record fields.
    _control_priority = {"emitted": 2, "clean": 1, "gap": 0}
    control_results: dict[str, str] = {}
    for record in records:
        if record.get("kind") != "control":
            continue
        response = record["response"]
        case = case_kinds[str(record["case_id"])]
        key = _family_key(case.pack_id, case.family)
        if _usable(response) and canary in str(response.get("body", "")):
            result = "emitted"
        elif _usable(response):
            result = "clean"
        else:
            result = "gap"
        previous = control_results.get(key)
        if previous is None or _control_priority[result] > _control_priority[previous]:
            control_results[key] = result

    reproduced: dict[str, str] = {}
    for record in records:
        if record.get("kind") != "attack":
            continue
        case_id = str(record["case_id"])
        # case_id/pack_id/family/kind/prompt were bound to the plan above; use
        # the plan-derived case fields from here on, not the record's.
        case = case_kinds[case_id]
        response = record.get("response")
        if not isinstance(response, dict) or "body" not in response:
            raise ReplayError("finding is missing its response evidence")
        pack = packs.get(case.pack_id)
        if pack is None:
            raise ReplayError("record references a pack not in the plan")

        outcome = ExchangeOutcome(
            body=str(response["body"]),
            status=int(response.get("status", 200)),
            redirected=bool(response.get("redirected", False)),
            truncated=bool(response.get("truncated", False)),
            transport_ok=bool(response.get("transport_ok", True)),
        )
        # Re-derive at the *real* plan thresholds using the trial counts the
        # bundle carries — never inferred as 1/1. A confirmed record therefore
        # cannot be replay-verified from a single execution; it must show enough
        # trials/successes (repeatability) under the plan policy.
        stored = record.get("finding", {})
        trials = stored.get("attack_trials")
        successes = stored.get("successes")
        if not isinstance(trials, int) or isinstance(trials, bool) or trials < 0 or \
                not isinstance(successes, int) or isinstance(successes, bool) or successes < 0:
            raise ReplayError(f"attack record {case_id} lacks valid trial metadata")
        # The canary is public (it is in the rendered prompt): a confirmed record
        # whose response evidence is only the bare canary — with no surrounding
        # response context — is not genuine execution evidence and fails closed.
        if str(stored.get("status")) == "confirmed" and not str(response["body"]).replace(
            canary, ""
        ).strip():
            raise ReplayError(f"confirmed record {case_id} has bare/public-canary evidence")
        control = control_results.get(_family_key(case.pack_id, case.family))
        try:
            status, proof = classify_record(
                outcome,
                canary,
                _expected_prompt(case, canary),
                _select_validators(pack.validators),
                control_succeeded=control == "emitted",
                matched_clean_control=control == "clean",
                attack_trials=trials,
                successes=successes,
                min_attack_trials=plan.trial_policy[0],
                min_successes=plan.trial_policy[1],
                requires_state_change=pack.side_effects,
            )
        except ValueError as exc:
            raise ReplayError(f"attack record {case_id} has inconsistent trial counts") from exc
        if str(stored.get("status")) != status.value:
            raise ReplayError(
                f"replayed status for {case_id} does not match the bundle"
            )
        if stored.get("proof") != proof:
            raise ReplayError(
                f"replayed proof for {case_id} does not match the bundle"
            )
        reproduced[case_id] = status.value

    return ReplayResult(
        verified=True,
        findings=reproduced,
        coverage_gaps=tuple(str(g) for g in bundle.content.get("coverage_gaps", [])),
        canary=canary,
    )


def _resolve_packs(mode: str) -> dict[str, Pack]:
    try:
        policy = resolve_policy(mode)
        return {p.id: p for p in resolve_packs(mode, trust=policy.pack_trust)}
    except Exception as exc:
        raise ReplayError(f"cannot resolve packs for replay in mode {mode!r}") from exc
