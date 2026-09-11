"""Tests for report assembly, atomic writing, and exit-code mapping."""

from __future__ import annotations

import json

from ai_scan.fingerprint import DEFAULT_PROBES, ProbeExchange, run_fingerprint
from ai_scan.injection import (
    ExchangeOutcome,
    InjectionStatus,
    generate_canary,
    load_payloads,
    run_injection,
)
from ai_scan.reporting import (
    Report,
    exit_code_for,
    write_report_atomic,
)
from ai_scan.targets import normalize_target


def _confirmed_injection():
    canary = generate_canary()

    def respond(case) -> ExchangeOutcome:
        # Simulates instruction execution: emits only the canary.
        return ExchangeOutcome(body=canary)

    return run_injection(load_payloads("safe"), respond, canary=canary, goal="g")


def _clean_injection():
    canary = generate_canary()
    return run_injection(
        load_payloads("safe"),
        lambda case: ExchangeOutcome(body="no."),
        canary=canary,
        goal="g",
    )


def _fingerprint():
    bodies = {p.id: "I am Claude, helpful harmless honest." for p in DEFAULT_PROBES}
    return run_fingerprint(
        DEFAULT_PROBES,
        lambda p: ProbeExchange(p.id, bodies[p.id], {}),
    )


def _build(injection):
    target = normalize_target("https://api.example.com:8443/chat")
    return Report.build(
        target=target,
        authorization={"client": "Acme", "engagement": "ENG-1", "mode": "receipt"},
        fingerprint=_fingerprint(),
        injection=injection,
        request_budget={"max_requests": 24, "used": injection.request_count},
        evidence=[{"request": {"headers": {"Authorization": "REDACTED"}}}],
    )


def test_report_schema_has_required_sections() -> None:
    report = _build(_clean_injection())
    data = report.to_dict()
    for key in (
        "tool",
        "schema_version",
        "target_origin",
        "authorization",
        "created_at",
        "request_budget",
        "fingerprint",
        "injection",
        "evidence",
        "findings",
    ):
        assert key in data
    assert data["target_origin"] == "https://api.example.com:8443"


def test_report_never_includes_confirmation_input() -> None:
    report = _build(_confirmed_injection())
    dumped = json.dumps(report.to_dict())
    assert "I confirm I am authorized" not in dumped


def test_exit_code_confirmed_is_3() -> None:
    report = _build(_confirmed_injection())
    assert exit_code_for(report) == 3


def test_exit_code_inconclusive_is_4() -> None:
    canary = generate_canary()
    # A responder that raises → every case inconclusive.
    def boom(case) -> str:
        raise RuntimeError("transport down")

    injection = run_injection(load_payloads("safe"), boom, canary=canary, goal="g")
    assert injection.status == InjectionStatus.INCONCLUSIVE
    report = _build(injection)
    assert exit_code_for(report) == 4


def test_exit_code_clean_is_0() -> None:
    report = _build(_clean_injection())
    assert exit_code_for(report) == 0


def test_exit_code_4_when_fingerprint_inconclusive_and_no_injection() -> None:
    # Fingerprint-only run whose probes all failed at transport → inconclusive.
    def respond(probe) -> ProbeExchange:
        return ProbeExchange(probe.id, "", {}, status=0, transport_ok=False)

    fp = run_fingerprint(DEFAULT_PROBES, respond)
    target = normalize_target("https://api.example.com:8443/chat")
    report = Report.build(
        target=target,
        authorization={"mode": "interactive"},
        fingerprint=fp,
        injection=None,
        request_budget={"max_requests": 64, "used": fp.request_count},
        evidence=[],
    )
    assert exit_code_for(report) == 4


def test_atomic_write_produces_valid_json(tmp_path) -> None:
    report = _build(_clean_injection())
    path = tmp_path / "report.json"
    write_report_atomic(report, str(path))
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded["target_origin"] == "https://api.example.com:8443"
    # No leftover temp files in the directory.
    assert [p.name for p in tmp_path.iterdir()] == ["report.json"]


def test_console_summary_has_no_secrets() -> None:
    report = _build(_confirmed_injection())
    summary = report.console_summary()
    assert "Authorization" not in summary or "REDACTED" in summary
    assert "Bearer" not in summary
