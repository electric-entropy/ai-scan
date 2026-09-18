"""Offline bounded-workload comparison acceptance."""
from __future__ import annotations

import json

import pytest

from ai_scan import consumption as api

NUMBERS = ("requests", "input_tokens", "output_tokens", "total_tokens", "duration_ms",
           "peak_concurrency", "queue_depth", "retries", "tool_steps", "request_bytes",
           "response_bytes")
CONTROLS = ("deadline_enforced", "cancellation_enforced", "backpressure", "circuit_breaker",
            "cleanup_enforced", "per_scope_limits", "fail_closed_on_exhaustion")
EVENTS = ("cancellation_observed", "exhaustion_observed", "cleanup_observed",
          "work_after_cancellation", "work_after_exhaustion")
RULES = ("request_volume", "token_budget", "deadline", "concurrency", "retry_tool_budget",
         "byte_budget", "termination", "isolation")


def manifest():
    numbers = dict.fromkeys(NUMBERS, 10)
    numbers["total_tokens"] = 20
    return {"schema_version": "ai-scan-consumption-manifest-v1",
            "context_ref": "context.primary", "scenarios": [{
                "scenario_ref": "scenario.primary", "ceilings": numbers.copy(),
                "observations": numbers.copy(), "controls": dict.fromkeys(CONTROLS, True),
                "events": dict.fromkeys(EVENTS, False)}]}


def audit(doc):
    return api.audit_manifest_text(json.dumps(doc))


def vulnerable(rule):
    doc = manifest()
    scenario = doc["scenarios"][0]
    if rule == "request_volume":
        scenario["observations"]["requests"] += 1
    elif rule == "token_budget":
        scenario["observations"]["total_tokens"] += 1
    elif rule == "deadline":
        scenario["controls"]["deadline_enforced"] = False
    elif rule == "concurrency":
        scenario["controls"]["backpressure"] = False
    elif rule == "retry_tool_budget":
        scenario["observations"]["retries"] += 1
    elif rule == "byte_budget":
        scenario["observations"]["response_bytes"] += 1
    elif rule == "termination":
        scenario["events"]["cancellation_observed"] = True
    elif rule == "isolation":
        scenario["controls"]["per_scope_limits"] = False
    return doc


def test_secure_is_opaque_inert_and_bounded():
    result = audit(manifest())
    doc = result.to_dict()
    assert doc["status"] == "passed"
    assert doc["findings"] == []
    assert doc["executions"] == doc["network_requests"] == 0
    assert doc["owasp_category"] == "LLM10"
    assert doc["scope"] == "partial_offline_bounded_consumption"
    assert len(doc["manifest_sha256"]) == 64
    for ref in ("context.primary", "scenario.primary"):
        assert ref not in repr(result) + api.render_json(result) + api.render_text(result)
    assert "runtime enforcement" in " ".join(doc["limitations"])


@pytest.mark.parametrize("rule", RULES)
def test_independent_rules(rule):
    result = audit(vulnerable(rule))
    assert len(result.findings) == 1
    finding = result.findings[0].to_dict()
    assert finding["rule_id"] == "llm10." + rule
    assert finding["severity"] == ("medium" if rule in ("byte_budget", "isolation") else "high")
    assert finding["reason_code"] == "llm10_" + rule
    assert finding["remediation_code"] == "llm10.remediate." + rule
