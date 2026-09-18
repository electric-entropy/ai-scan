"""Stable baseline creation and comparison for CI regression gates."""

from __future__ import annotations

import json
from typing import Any

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.targets import normalize_target

from . import Report
from .json_report import report_document


def create_baseline(report: Report, *, mode: str = "reliable") -> dict[str, Any]:
    """Create a compact baseline keyed on stable finding identities."""
    doc = report_document(report, mode=mode)
    return {
        "schema_version": "1.0-baseline",
        "target_origin": doc["scope_summary"]["target_origin"],
        "confirmed_findings": {f["id"]: _baseline_item(f) for f in doc["confirmed_findings"]},
        "analyst_leads": {f["id"]: _baseline_item(f) for f in doc["analyst_leads"]},
    }


def compare_baselines(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare two baselines by stable identities, not mutable message text."""
    validate_baseline(old)
    validate_baseline(new)
    if old["target_origin"] != new["target_origin"]:
        raise ValueError("baseline origins must match")
    old_confirmed = set(old["confirmed_findings"])
    new_confirmed = set(new["confirmed_findings"])
    old_leads = set(old["analyst_leads"])
    new_leads = set(new["analyst_leads"])
    return {
        "schema_version": "1.0-baseline-diff",
        "new_confirmed": sorted(new_confirmed - old_confirmed),
        "resolved_confirmed": sorted(old_confirmed - new_confirmed),
        "new_analyst_leads": sorted(new_leads - old_leads),
        "resolved_analyst_leads": sorted(old_leads - new_leads),
    }


def render_baseline(baseline: dict[str, Any]) -> str:
    """Render a baseline/diff as deterministic JSON."""
    return json.dumps(baseline, indent=2, sort_keys=True, allow_nan=False)


def _baseline_item(finding: dict[str, Any]) -> dict[str, str]:
    return {
        "family": str(finding.get("family", "unknown")),
        "status": str(finding.get("status", "unknown")),
        "severity": str(finding.get("severity", "unknown")),
    }


def validate_baseline(doc: object) -> None:
    """Validate the closed baseline domain without coercion or missing defaults."""
    fields = {"schema_version", "target_origin", "confirmed_findings", "analyst_leads"}
    if not isinstance(doc, dict) or set(doc) != fields:
        raise ValueError("baseline fields are invalid")
    if doc["schema_version"] != "1.0-baseline":
        raise ValueError("baseline version is invalid")
    origin = doc["target_origin"]
    if not isinstance(origin, str):
        raise ValueError("baseline origin must be a canonical origin")
    try:
        target = normalize_target(origin)
    except ValueError:
        raise ValueError("baseline origin must be a canonical origin") from None
    if target.origin != origin or target.path or target.query:
        raise ValueError("baseline origin must be a canonical origin")
    for key, statuses in (
        ("confirmed_findings", {"confirmed"}),
        ("analyst_leads", {"potential", "likely", "suspected"}),
    ):
        findings = doc[key]
        if not isinstance(findings, dict):
            raise ValueError("baseline findings must be maps")
        for identity, item in findings.items():
            if not isinstance(identity, str) or not isinstance(item, dict):
                raise ValueError("baseline finding is invalid")
            if set(item) != {"family", "status", "severity"} or any(
                not isinstance(value, str) or not value for value in item.values()
            ):
                raise ValueError("baseline finding fields are invalid")
            if item["status"] not in statuses or item["severity"] not in {
                "informational", "low", "medium", "high", "critical"
            }:
                raise ValueError("baseline finding classification is invalid")
            if identity != f"finding:{item['family']}:{item['status']}":
                raise ValueError("baseline finding identity is invalid")


def load_baseline(text: str) -> dict[str, Any]:
    """Parse strict JSON and apply the same domain gate used by comparison."""
    try:
        doc = load_json_strict(text)
    except (ConfigError, ValueError, RecursionError):
        raise ValueError("baseline is not valid strict JSON") from None
    validate_baseline(doc)
    assert isinstance(doc, dict)
    return doc
