"""Markdown report rendering."""

from __future__ import annotations

from . import Report
from .json_report import report_document


def render_markdown(report: Report, *, mode: str = "reliable") -> str:
    """Render a conservative Markdown report with separated leads/gaps."""
    doc = report_document(report, mode=mode)
    lines = [
        "# AI-Scan Report",
        "",
        "## Scope",
        f"- Target origin: `{doc['scope_summary']['target_origin']}`",
        f"- Mode: `{doc['resolved_mode_policy']['name']}`",
        "",
        "## Confirmed Findings",
    ]
    if doc["confirmed_findings"]:
        for finding in doc["confirmed_findings"]:
            lines.append(f"- **{finding['family']}** ({finding['severity']}): {finding['summary']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Analyst Leads"])
    if doc["analyst_leads"]:
        for lead in doc["analyst_leads"]:
            lines.append(f"- {lead['family']} ({lead['status']}): {lead['summary']}")
    else:
        lines.append("- None")
    lines.extend(["", "## Coverage Gaps"])
    if doc["coverage_gaps"]:
        for gap in doc["coverage_gaps"]:
            lines.append(f"- {gap['family']}: {gap['status']} — {gap['reason']}")
    else:
        lines.append("- None")
    lines.extend([
        "",
        "## Budgets",
        f"- Requests: `{doc['budgets']['request']}`",
        "",
        "## Redaction",
        f"{doc['redaction_notice']}",
        "",
    ])
    return "\n".join(lines)
