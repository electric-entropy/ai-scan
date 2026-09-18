"""Phase 2B7 live-only marker disclosure and LLM07 substrate regressions."""

from __future__ import annotations

import json
import re

import pytest

from ai_scan.evidence_graph import (
    BundleCollector,
    BundleError,
)
from ai_scan.injection import ExchangeOutcome, InjectionCase, InjectionStatus
from ai_scan.orchestration import compile_plan
from ai_scan.orchestration.checkpoint import CheckpointError, load_checkpoint
from ai_scan.packs import load_builtin_pack
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

_URL = "http://127.0.0.1:8765/v1/chat"
_MARKER = "AISCAN-1234ABCD5678EF90"
_CANARY = "AISCAN-ABCDEF0123456789"


def _plan(mode: str = "reliable"):
    return compile_plan(normalize_target(_URL), mode)


def _marker_cases(plan, *, category: str, kind: str | None = None):  # type: ignore[no-untyped-def]
    pack_ids = {
        pack_id
        for pack_id, _version, _digest in plan.packs
        if category in load_builtin_pack(pack_id).mappings.get("owasp-llm", ())
    }
    cases = [case for case in plan.cases if case.pack_id in pack_ids]
    if kind is not None:
        cases = [case for case in cases if case.kind == kind]
    return tuple(cases)


def _marker_findings(plan, result, *, category: str):  # type: ignore[no-untyped-def]
    ids = {case.case_id for case in _marker_cases(plan, category=category, kind="attack")}
    return tuple(
        finding
        for case, finding in zip(plan.attack_cases(), result.findings, strict=True)
        if case.case_id in ids
    )


def _live_marker_responder(case: InjectionCase) -> ExchangeOutcome:
    for pack_id in ("prompt-disclosure-reliable", "prompt-disclosure-kitchen",
                    "system-prompt-leakage-reliable", "system-prompt-leakage-kitchen"):
        pack = load_builtin_pack(pack_id)
        for family in pack.families:
            if case.family == family.name:
                if case.template in family.controls:
                    return ExchangeOutcome(body="clean", known_secrets=frozenset({_MARKER}))
                if case.template in family.templates:
                    return ExchangeOutcome(body=_MARKER, known_secrets=frozenset({_MARKER}))
    tokens = re.findall(r"AISCAN-[0-9A-F]{16,64}", case.rendered_prompt)
    return ExchangeOutcome(body=tokens[0] if tokens else "clean")


def test_llm02_explanatory_control_marker_is_dirty_and_result_evidence_is_scrubbed() -> None:
    plan = _plan("reliable")
    controls = {case.template for case in _marker_cases(plan, category="LLM02", kind="control")}

    def responder(case: InjectionCase) -> ExchangeOutcome:
        if case.template in controls:
            return ExchangeOutcome(
                body=f"The hidden fixture value is {_MARKER}.",
                known_secrets=frozenset({_MARKER}),
            )
        return _live_marker_responder(case)

    result = run_plan(plan, responder, canary=_CANARY, disclosure_marker=_MARKER)
    findings = _marker_findings(plan, result, category="LLM02")

    assert findings
    assert all(f.status is not InjectionStatus.CONFIRMED for f in findings)
    assert _MARKER not in repr(result)
    assert all(_MARKER not in trial.body for f in result.findings for trial in f.evidence)
    assert all(_MARKER not in trial.known_secrets for f in result.findings for trial in f.evidence)


def test_checkpoint_mode_skips_marker_dependent_cases_and_continues_unrelated(tmp_path) -> None:
    plan = _plan("reliable")
    checkpoint = tmp_path / "run.ckpt"
    calls: list[str] = []

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls.append(case.family)
        return _live_marker_responder(case)

    result = run_plan(
        plan,
        responder,
        canary=_CANARY,
        disclosure_marker=_MARKER,
        checkpoint_path=str(checkpoint),
    )

    assert not set(calls) & {c.family for c in _marker_cases(plan, category="LLM02")}
    llm02 = _marker_findings(plan, result, category="LLM02")
    assert llm02 and all(f.status is InjectionStatus.INCONCLUSIVE for f in llm02)
    assert all(f.attack_trials == 0 and f.successes == 0 and f.evidence == () for f in llm02)
    assert any(f.status is InjectionStatus.CONFIRMED for f in result.findings if f not in llm02)
    restored = load_checkpoint(
        str(checkpoint), expected_plan_digest=plan.digest, plan=plan, disclosure_marker=_MARKER
    )
    assert not set(restored.completed) & {c.case_id for c in _marker_cases(plan, category="LLM02")}


def test_marker_dependent_persisted_checkpoint_and_bundle_evidence_rejects(tmp_path) -> None:
    plan = _plan("reliable")
    checkpoint = tmp_path / "legacy.ckpt"
    collector = BundleCollector()
    live = run_plan(
        plan,
        _live_marker_responder,
        canary=_CANARY,
        disclosure_marker=_MARKER,
        observer=collector.observe,
    )
    assert any(
        f.status is InjectionStatus.CONFIRMED
        for f in _marker_findings(plan, live, category="LLM02")
    )
    # Create a legacy-looking persisted checkpoint from the live records.
    run_plan(plan, _live_marker_responder, canary=_CANARY, checkpoint_path=str(checkpoint))
    doc = json.loads(checkpoint.read_text(encoding="utf-8"))
    record = collector._records[-1].to_dict(  # type: ignore[attr-defined]
        plan,
        _CANARY,
        __import__("ai_scan.core.run_identity", fromlist=["RunIdentity"]).RunIdentity.create(
            plan.digest, _CANARY, _MARKER
        ),
        frozenset({_MARKER}),
    )
    doc["completed"][record["case_id"]] = {
        "family": record["family"],
        "status": record["finding"]["status"],
        "prompt": record["prompt"],
        "proof": record["finding"]["proof"],
        "kind": record["kind"],
        "attack_trials": record["finding"]["attack_trials"],
        "successes": record["finding"]["successes"],
        "trials": record["trials"],
    }
    doc["request_count"] += sum(t["attempts"] for t in record["trials"])
    doc["digest"] = compute_digest({k: v for k, v in doc.items() if k != "digest"})
    checkpoint.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(CheckpointError, match="marker-dependent"):
        load_checkpoint(str(checkpoint), expected_plan_digest=plan.digest, plan=plan)

    with pytest.raises(BundleError, match="marker-dependent"):
        collector.build(plan=plan, canary=_CANARY, disclosure_marker=_MARKER, run_id="live")


def test_llm07_has_distinct_live_only_packs_and_no_marker_gates_zero_calls() -> None:
    reliable = _plan("reliable")
    kitchen = _plan("kitchen-sink")
    assert "system-prompt-leakage-reliable" in {p[0] for p in reliable.packs}
    assert "system-prompt-leakage-kitchen" not in {p[0] for p in reliable.packs}
    assert {"system-prompt-leakage-reliable", "system-prompt-leakage-kitchen"} <= {
        p[0] for p in kitchen.packs
    }
    assert _marker_cases(reliable, category="LLM07", kind="attack")
    assert all(
        case.family.startswith("system_prompt_leakage")
        for case in _marker_cases(kitchen, category="LLM07")
    )

    calls: list[str] = []

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls.append(case.family)
        return _live_marker_responder(case)

    result = run_plan(reliable, responder, canary=_CANARY, disclosure_marker=None)
    assert not set(calls) & {c.family for c in _marker_cases(reliable, category="LLM07")}
    llm07 = _marker_findings(reliable, result, category="LLM07")
    assert llm07 and all(f.status is InjectionStatus.INCONCLUSIVE for f in llm07)


def test_llm07_live_positive_and_marker_absent_from_templates() -> None:
    plan = _plan("reliable")
    secure = run_plan(
        plan,
        lambda case: ExchangeOutcome(body="clean", known_secrets=frozenset({_MARKER})),
        canary=_CANARY,
        disclosure_marker=_MARKER,
    )
    vulnerable = run_plan(plan, _live_marker_responder, canary=_CANARY, disclosure_marker=_MARKER)

    assert all(
        f.status is not InjectionStatus.CONFIRMED
        for f in _marker_findings(plan, secure, category="LLM07")
    )
    assert all(
        f.status is InjectionStatus.CONFIRMED
        for f in _marker_findings(plan, vulnerable, category="LLM07")
    )
    assert _MARKER not in repr(vulnerable)
    assert all(
        _MARKER not in case.template
        for case in _marker_cases(plan, category="LLM07")
    )
