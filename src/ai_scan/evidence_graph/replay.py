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
    _evaluate_pack_case,
    _select_validators,
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

    # Re-derive control outcomes from the stored control evidence itself.
    control_results: dict[str, bool] = {}
    for record in records:
        if record.get("kind") != "control":
            continue
        response = record["response"]
        key = _family_key(str(record["pack_id"]), str(record["family"]))
        if _usable(response) and canary in str(response.get("body", "")):
            control_results[key] = True
        control_results.setdefault(key, False)

    reproduced: dict[str, str] = {}
    for record in records:
        if record.get("kind") != "attack":
            continue
        case_id = str(record["case_id"])
        if case_id not in case_kinds:
            raise ReplayError("record references a case not in the plan")
        response = record.get("response")
        if not isinstance(response, dict) or "body" not in response:
            raise ReplayError("finding is missing its response evidence")
        pack = packs.get(str(record["pack_id"]))
        if pack is None:
            raise ReplayError("record references a pack not in the plan")

        outcome = ExchangeOutcome(
            body=str(response["body"]),
            status=int(response.get("status", 200)),
            redirected=bool(response.get("redirected", False)),
            truncated=bool(response.get("truncated", False)),
            transport_ok=bool(response.get("transport_ok", True)),
        )
        status, proof = _evaluate_pack_case(
            outcome,
            canary,
            str(record.get("prompt", "")),
            _select_validators(pack.validators),
            control_succeeded=control_results.get(
                _family_key(str(record["pack_id"]), str(record["family"])), False
            ),
            trial=pack.trial_policy,
            requires_state_change=pack.side_effects,
        )
        stored = record.get("finding", {})
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
