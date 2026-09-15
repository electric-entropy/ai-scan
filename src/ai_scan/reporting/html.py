"""Offline HTML report rendering with escaped evidence."""

from __future__ import annotations

from html import escape

from . import Report
from .json_report import report_document


def render_html(report: Report, *, mode: str = "reliable") -> str:
    """Render a self-contained HTML report with no scripts or remote assets."""
    doc = report_document(report, mode=mode)
    confirmed = "".join(_finding_li(f) for f in doc["confirmed_findings"]) or "<li>None</li>"
    leads = "".join(_finding_li(f) for f in doc["analyst_leads"]) or "<li>None</li>"
    gaps = "".join(_gap_li(g) for g in doc["coverage_gaps"]) or "<li>None</li>"
    target = escape(str(doc["scope_summary"]["target_origin"]))
    mode_name = escape(str(doc["resolved_mode_policy"]["name"]))
    redaction = escape(str(doc["redaction_notice"]))
    return f"""<!doctype html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>AI-Scan Report</title>
<style>
body{{font-family:sans-serif;max-width:72rem;margin:2rem auto;line-height:1.4}}
code{{background:#eee;padding:.1rem .2rem}}
</style>
</head>
<body>
<h1>AI-Scan Report</h1>
<h2>Scope</h2>
<p>Target origin: <code>{target}</code><br>Mode: <code>{mode_name}</code></p>
<h2>Confirmed Findings</h2><ul>{confirmed}</ul>
<h2>Analyst Leads</h2><ul>{leads}</ul>
<h2>Coverage Gaps</h2><ul>{gaps}</ul>
<h2>Redaction</h2><p>{redaction}</p>
</body>
</html>
"""


def _finding_li(finding: dict[str, object]) -> str:
    return (
        "<li><strong>"
        + escape(str(finding.get("family", "unknown")))
        + "</strong> ("
        + escape(str(finding.get("status", "unknown")))
        + "): "
        + escape(str(finding.get("summary", "")))
        + "</li>"
    )


def _gap_li(gap: dict[str, object]) -> str:
    return (
        "<li>"
        + escape(str(gap.get("family", "unknown")))
        + ": "
        + escape(str(gap.get("status", "unknown")))
        + " — "
        + escape(str(gap.get("reason", "")))
        + "</li>"
    )
