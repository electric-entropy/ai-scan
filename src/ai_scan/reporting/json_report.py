"""Canonical JSON report rendering for analyst and CI outputs."""

from __future__ import annotations

import json
from typing import Any

from ai_scan.core.modes import resolve_policy
from ai_scan.transport.redaction import scrub_structure

from . import Report

_CONFIRMED = frozenset({"confirmed"})
_LEADS = frozenset({"potential", "likely", "suspected"})
_GAPS = frozenset({"inconclusive", "blocked", "not_tested"})


def report_document(report: Report, *, mode: str = "reliable") -> dict[str, Any]:
    """Return a v2-style report document without changing legacy report v1.

    The document separates confirmed findings from analyst leads and coverage
    gaps, preserves the legacy raw report under ``legacy_report_v1``, and never
    promotes heuristic/potential evidence to confirmed.
    """
    raw = report.to_dict()
    injection = raw.get("injection") if isinstance(raw.get("injection"), dict) else None
    findings = list(injection.get("findings", [])) if injection else []
    confirmed = [_finding(f) for f in findings if str(f.get("status")) in _CONFIRMED]
    leads = [_finding(f) for f in findings if str(f.get("status")) in _LEADS]
    coverage_gaps = _coverage_gaps(raw, findings)
    policy_obj = resolve_policy(mode)
    policy = {
        "name": policy_obj.name,
        "pack_trust": sorted(item.value for item in policy_obj.pack_trust),
        "include_experimental": policy_obj.include_experimental,
        "allow_adaptive_generation": policy_obj.allow_adaptive_generation,
        "minimum_attack_trials": policy_obj.minimum_attack_trials,
        "minimum_successes": policy_obj.minimum_successes,
        "minimum_control_trials": policy_obj.minimum_control_trials,
        "promote_statuses": sorted(item.value for item in policy_obj.promote_statuses),
        "requests_per_second": policy_obj.requests_per_second,
        "max_physical_requests": policy_obj.max_physical_requests,
        "max_duration_seconds": policy_obj.max_duration_seconds,
        "max_concurrency": policy_obj.max_concurrency,
        "require_deterministic_confirmation": policy_obj.require_deterministic_confirmation,
    }
    doc = {
        "tool": raw["tool"],
        "schema_version": "2.0-report",
        "generated_at": raw["created_at"],
        "scope_summary": {
            "target_origin": raw["target_origin"],
        },
        "resolved_mode_policy": policy,
        "coverage_matrix": _coverage_matrix(raw, findings),
        "confirmed_findings": confirmed,
        "analyst_leads": leads,
        "coverage_gaps": coverage_gaps,
        "fingerprint_attribution": raw.get("fingerprint"),
        "budgets": {"request": raw.get("request_budget", {})},
        "evidence_graph_refs": _evidence_refs(raw.get("evidence", [])),
        "reproduction": {
            "retest_command": "ai-scan run --target <URL> --plan <plan.json> --out <report.json>",
            "replay_command": "ai-scan bundle replay --file <bundle.json>",
        },
        "remediation": [],
        "framework_mappings": [],
        "versions": {"legacy_report_schema": raw["schema_version"]},
        "redaction_notice": "All untrusted evidence is recursively scrubbed before export.",
        "limitations": [
            "Confirmed findings require deterministic controlled evidence; "
            "analyst leads are not vulnerabilities."
        ],
        "legacy_report_v1": raw,
    }
    scrubbed = scrub_structure(doc)
    if not isinstance(scrubbed, dict):
        raise TypeError("report scrubber returned a non-object")
    return scrubbed


def render_json(report: Report, *, mode: str = "reliable") -> str:
    """Render the canonical report JSON with deterministic key ordering."""
    return json.dumps(report_document(report, mode=mode), indent=2, sort_keys=True, allow_nan=False)


def _finding(item: dict[str, Any]) -> dict[str, Any]:
    family = str(item.get("family", "unknown"))
    status = str(item.get("status", "inconclusive"))
    return {
        "id": f"finding:{family}:{status}",
        "family": family,
        "status": status,
        "severity": "medium" if status == "confirmed" else "informational",
        "summary": _summary(status, family),
        "evidence_ids": [],
        "proof": item.get("proof"),
    }


def _summary(status: str, family: str) -> str:
    if status == "confirmed":
        return f"Deterministic canary execution observed for {family}."
    return f"Analyst lead for {family}; confirmation requirements were not met."


def _coverage_gaps(raw: dict[str, Any], findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    gaps = [
        {
            "family": str(f.get("family", "unknown")),
            "status": str(f.get("status")),
            "reason": "not reportable",
        }
        for f in findings
        if str(f.get("status")) in _GAPS
    ]
    fp = raw.get("fingerprint")
    if isinstance(fp, dict) and fp.get("inconclusive"):
        gaps.append(
            {
                "family": "fingerprint",
                "status": "inconclusive",
                "reason": "fingerprint transport/evidence unusable",
            }
        )
    return gaps


def _coverage_matrix(raw: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    for f in findings:
        status = str(f.get("status", "unknown"))
        statuses[status] = statuses.get(status, 0) + 1
    return {
        "families_tested": sorted({str(f.get("family", "unknown")) for f in findings}),
        "status_counts": statuses,
        "fingerprint_attempted": raw.get("fingerprint") is not None,
        "injection_attempted": raw.get("injection") is not None,
    }


def _evidence_refs(evidence: Any) -> list[dict[str, Any]]:
    if not isinstance(evidence, list):
        return []
    refs: list[dict[str, Any]] = []
    for idx, item in enumerate(evidence):
        if isinstance(item, dict):
            refs.append({"id": f"evidence:{idx}", "kind": "exchange", "redacted": True})
    return refs
