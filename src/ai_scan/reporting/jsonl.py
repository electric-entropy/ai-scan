"""JSON Lines rendering for report sections."""

from __future__ import annotations

import json
from typing import Any

from . import Report
from .json_report import report_document


def render_jsonl(report: Report, *, mode: str = "reliable") -> str:
    """Render material report objects as newline-delimited JSON records."""
    doc = report_document(report, mode=mode)
    rows: list[dict[str, Any]] = [
        {"type": "summary", "data": doc["scope_summary"]},
        {"type": "coverage_matrix", "data": doc["coverage_matrix"]},
        {"type": "budgets", "data": doc["budgets"]},
    ]
    for finding in doc["confirmed_findings"]:
        rows.append({"type": "confirmed_finding", "data": finding})
    for lead in doc["analyst_leads"]:
        rows.append({"type": "analyst_lead", "data": lead})
    for gap in doc["coverage_gaps"]:
        rows.append({"type": "coverage_gap", "data": gap})
    for evidence in doc["evidence_graph_refs"]:
        rows.append({"type": "evidence_ref", "data": evidence})
    return "\n".join(json.dumps(row, sort_keys=True, allow_nan=False) for row in rows) + "\n"
