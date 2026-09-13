"""Stable baseline creation and comparison for CI regression gates."""

from __future__ import annotations

import json
from typing import Any

from . import Report
from .json_report import report_document


def create_baseline(report: Report, *, mode: str = "reliable") -> dict[str, Any]:
    """Create a compact baseline keyed on stable finding identities."""
    doc = report_document(report, mode=mode)
    return {
        "schema_version": "1.0-baseline",
        "target_origin": doc["scope_authorization_summary"]["target_origin"],
        "confirmed_findings": {f["id"]: _baseline_item(f) for f in doc["confirmed_findings"]},
        "analyst_leads": {f["id"]: _baseline_item(f) for f in doc["analyst_leads"]},
    }


def compare_baselines(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare two baselines by stable identities, not mutable message text."""
    old_confirmed = set(_mapping(old, "confirmed_findings"))
    new_confirmed = set(_mapping(new, "confirmed_findings"))
    old_leads = set(_mapping(old, "analyst_leads"))
    new_leads = set(_mapping(new, "analyst_leads"))
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


def _mapping(doc: dict[str, Any], key: str) -> dict[str, Any]:
    value = doc.get(key, {})
    return value if isinstance(value, dict) else {}
