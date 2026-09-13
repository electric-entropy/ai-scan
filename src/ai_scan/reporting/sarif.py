"""SARIF rendering with confirmed findings only by default."""

from __future__ import annotations

import json
from typing import Any

from . import Report
from .json_report import report_document


def sarif_document(
    report: Report, *, mode: str = "reliable", include_leads: bool = False
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document.

    Unconfirmed analyst leads are excluded unless ``include_leads`` is explicit;
    when included they remain warnings, not errors.
    """
    doc = report_document(report, mode=mode)
    results = [_sarif_result(f, level="error") for f in doc["confirmed_findings"]]
    if include_leads:
        results.extend(_sarif_result(f, level="warning") for f in doc["analyst_leads"])
    all_findings = [*doc["confirmed_findings"], *doc["analyst_leads"]]
    rules = {_rule_id(r): _sarif_rule(r) for r in all_findings}
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ai-scan", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }


def render_sarif(report: Report, *, mode: str = "reliable", include_leads: bool = False) -> str:
    """Render SARIF JSON."""
    document = sarif_document(report, mode=mode, include_leads=include_leads)
    return json.dumps(document, indent=2, sort_keys=True, allow_nan=False)


def _rule_id(finding: dict[str, Any]) -> str:
    return "ai-scan." + str(finding.get("family", "unknown")).replace(" ", "_")


def _sarif_rule(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": _rule_id(finding),
        "name": str(finding.get("family", "unknown")),
        "shortDescription": {"text": str(finding.get("summary", "AI-Scan finding"))},
    }


def _sarif_result(finding: dict[str, Any], *, level: str) -> dict[str, Any]:
    return {
        "ruleId": _rule_id(finding),
        "level": level,
        "message": {"text": str(finding.get("summary", "AI-Scan finding"))},
        "properties": {
            "status": finding.get("status"),
            "severity": finding.get("severity"),
        },
    }
