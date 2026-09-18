"""Bounded offline structured-claim comparison contract."""
from __future__ import annotations

import json

import pytest

from ai_scan import misinformation as audit_api


def manifest():
    expected = {"claim_ref": "claim.primary", "source_ref": "source.primary",
                "value_sha256": "a" * 64}
    return {"schema_version": "ai-scan-misinformation-manifest-v1",
            "context_ref": "context.primary", "cases": [{
                "case_ref": "case.primary", "ground_truth_snapshot_ref": "snapshot.primary",
                "observed_snapshot_ref": "snapshot.primary", "expected_claims": [expected],
                "observed_claims": [{**expected, "citation_present": True}]}]}


def audit(doc):
    return audit_api.audit_manifest_text(json.dumps(doc))


def test_secure_comparison_is_opaque_and_inert():
    result = audit(manifest())
    doc = result.to_dict()
    assert result.status == "passed"
    assert doc["findings"] == []
    assert doc["network_requests"] == doc["executions"] == 0
    assert doc["owasp_category"] == "LLM09"
    assert doc["scope"] == "partial_offline_structured_claim_comparison"
    assert len(doc["manifest_sha256"]) == 64
    for raw in ["context.primary", "case.primary", "snapshot.primary", "claim.primary",
                "source.primary", "a" * 64]:
        assert raw not in repr(result)
        assert raw not in audit_api.render_json(result)
        assert raw not in audit_api.render_text(result)
    assert "general truth verification" in " ".join(doc["limitations"])


def vulnerable(rule):
    doc = manifest()
    case = doc["cases"][0]
    observed = case["observed_claims"][0]
    if rule == "missing_claim":
        case["observed_claims"] = []
    elif rule == "value_mismatch":
        observed["value_sha256"] = "b" * 64
    elif rule == "source_integrity":
        observed["citation_present"] = False
    elif rule == "unexpected_claim":
        case["observed_claims"].append({**observed, "claim_ref": "claim.extra"})
    elif rule == "snapshot_mismatch":
        case["observed_snapshot_ref"] = "snapshot.other"
    return doc


@pytest.mark.parametrize("rule,severity", [
    ("missing_claim", "high"), ("value_mismatch", "high"),
    ("source_integrity", "medium"), ("unexpected_claim", "medium"),
    ("snapshot_mismatch", "medium"),
])
def test_rules_independently(rule, severity):
    result = audit(vulnerable(rule))
    assert result.status == "finding"
    assert len(result.findings) == 1
    finding = result.findings[0].to_dict()
    assert finding["rule_id"] == "llm09." + rule
    assert finding["severity"] == severity
    assert finding["reason_code"] == "llm09_" + rule
    assert finding["remediation_code"] == "llm09.remediate." + rule


def test_source_mismatch_and_missing_citation_are_one_rule():
    doc = manifest()
    doc["cases"][0]["observed_claims"][0]["source_ref"] = "source.other"
    assert [f.rule for f in audit(doc).findings] == ["source_integrity"]
    doc["cases"][0]["observed_claims"][0]["citation_present"] = False
    assert [f.rule for f in audit(doc).findings] == ["source_integrity"]


def test_multiple_rules_and_unexpected_uncited_claim():
    doc = vulnerable("value_mismatch")
    case = doc["cases"][0]
    case["observed_claims"][0]["citation_present"] = False
    case["observed_claims"].append({**case["observed_claims"][0], "claim_ref": "claim.extra"})
    case["expected_claims"].append({**case["expected_claims"][0], "claim_ref": "claim.missing"})
    case["observed_snapshot_ref"] = "snapshot.other"
    result = audit(doc)
    assert {f.rule for f in result.findings} == set(audit_api._RULE_META)
    assert len(result.findings) == 6


def test_unexpected_uncited_claim_still_has_missing_citation():
    doc = vulnerable("unexpected_claim")
    doc["cases"][0]["observed_claims"][1]["citation_present"] = False
    assert {f.rule for f in audit(doc).findings} == {"unexpected_claim", "source_integrity"}
