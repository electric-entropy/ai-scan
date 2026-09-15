"""Report format smoke/regression tests."""

from __future__ import annotations

import json

from ai_scan.injection import ExchangeOutcome, generate_canary, load_payloads, run_injection
from ai_scan.reporting import Report
from ai_scan.reporting.diff import compare_baselines, create_baseline
from ai_scan.reporting.html import render_html
from ai_scan.reporting.json_report import render_json, report_document
from ai_scan.reporting.jsonl import render_jsonl
from ai_scan.reporting.markdown import render_markdown
from ai_scan.reporting.sarif import sarif_document
from ai_scan.targets import normalize_target


def _report(body: str) -> Report:
    canary = generate_canary()

    def respond(_case: object) -> ExchangeOutcome:
        return ExchangeOutcome(body=body.replace("{canary}", canary))

    injection = run_injection(load_payloads("safe"), respond, canary=canary, goal="g")
    return Report.build(
        target=normalize_target("https://api.example.test/chat"),
        fingerprint=None,
        injection=injection,
        request_budget={"max_requests": 16, "used": injection.request_count},
        evidence=[{"body": body, "headers": {"X-Api-Token": "Bearer SECRET123456"}}],
        created_at="2026-09-13T00:00:00+00:00",
    )


def test_report_document_separates_confirmed_leads_and_gaps() -> None:
    confirmed = report_document(_report("executed {canary}"))
    assert confirmed["confirmed_findings"]
    assert not confirmed["analyst_leads"]
    lead = report_document(_report("Sure, I can help with that."))
    assert not lead["confirmed_findings"]
    assert lead["analyst_leads"]


def test_sarif_excludes_leads_by_default() -> None:
    report = _report("Sure, I can help with that.")
    default = sarif_document(report)
    with_leads = sarif_document(report, include_leads=True)
    assert default["runs"][0]["results"] == []
    assert with_leads["runs"][0]["results"][0]["level"] == "warning"


def test_text_formats_are_secret_free_and_html_has_no_active_content() -> None:
    report = _report("executed {canary}")
    outputs = [
        render_json(report),
        render_jsonl(report),
        render_markdown(report),
        render_html(report),
    ]
    for rendered in outputs:
        assert "SECRET123456" not in rendered
        assert "Bearer SECRET" not in rendered
    html = render_html(report)
    assert "<script" not in html.lower()
    assert "src=" not in html.lower()
    assert "href=" not in html.lower()


def test_jsonl_is_valid_newline_delimited_json() -> None:
    rows = [json.loads(line) for line in render_jsonl(_report("executed {canary}")).splitlines()]
    assert {row["type"] for row in rows} >= {"summary", "coverage_matrix", "budgets"}


def test_baseline_diff_keys_on_finding_identity() -> None:
    old = create_baseline(_report("no signal"))
    new = create_baseline(_report("executed {canary}"))
    diff = compare_baselines(old, new)
    assert diff["new_confirmed"]
    assert diff["resolved_confirmed"] == []
