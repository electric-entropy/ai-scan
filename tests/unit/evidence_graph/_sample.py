"""Shared helpers: build a real sample plan + verified evidence bundle."""

from __future__ import annotations

import copy
from typing import Any

from ai_scan.evidence_graph import BundleCollector, dump_bundle
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import Plan, compile_plan
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

CANARY = "AISCAN-SAMPLE0001"


def sample_plan() -> Plan:
    return compile_plan(normalize_target("http://127.0.0.1:8080/chat"), "reliable")


def sample_bundle_text(*, confirm: bool = True) -> str:
    """Run a deterministic mock scan and return the exported bundle JSON."""
    plan = sample_plan()

    def responder(case):  # type: ignore[no-untyped-def]
        emit = confirm and "{canary}" in case.template
        # Whole final-token output, supported by persisted trials and controls.
        return ExchangeOutcome(body=CANARY if emit
                               else "benign response")

    collector = BundleCollector()
    result = run_plan(plan, responder, canary=CANARY, goal="g", observer=collector.observe)
    bundle = collector.build(
        plan=plan, canary=CANARY, run_id="run-1", coverage_gaps=result.coverage_gaps
    )
    return dump_bundle(bundle)


def redigest(doc: dict[str, Any]) -> dict[str, Any]:
    """Recompute the top-level bundle digest after mutating content."""
    out = copy.deepcopy(doc)
    out.pop("digest", None)
    out["digest"] = compute_digest(out)
    return out
