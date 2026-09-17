"""Offline `ai-scan doctor` health-check command."""

from __future__ import annotations

import pytest

from ai_scan import cli


def test_doctor_listed_in_help() -> None:
    assert "doctor" in cli.build_parser().format_help()
    assert "owasp-coverage" in cli.build_parser().format_help()


def test_doctor_exits_zero_and_prints_summary(capsys: pytest.CaptureFixture) -> None:
    rc = cli.main(["doctor"])
    assert rc == cli.EXIT_OK
    out = capsys.readouterr().out.lower()
    assert "doctor" in out or "healthy" in out or "ok" in out
    # Mentions the resource classes it validated.
    assert "schema" in out and "pack" in out and "owasp" in out


def test_doctor_requires_no_target() -> None:
    # No --target is needed; doctor is fully offline.
    assert cli.main(["doctor"]) == cli.EXIT_OK


def test_doctor_constructs_no_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_controller):  # type: ignore[no-untyped-def]
        raise AssertionError("doctor must not construct transport")

    monkeypatch.setattr(cli, "_make_transport", boom)
    assert cli.main(["doctor"]) == cli.EXIT_OK


def test_doctor_validates_packs_and_schemas_and_metadata(capsys: pytest.CaptureFixture) -> None:
    rc = cli.main(["doctor"])
    assert rc == cli.EXIT_OK
    out = capsys.readouterr().out.lower()
    from importlib import metadata

    assert metadata.version("ai-scan") in out  # reports the package version
    assert "py.typed" in out
    assert "license" in out


def test_doctor_json_output_is_machine_readable(capsys: pytest.CaptureFixture) -> None:
    import json

    rc = cli.main(["doctor", "--json"])
    assert rc == cli.EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["ok"] is True
    assert doc["version"]
    assert doc["checks"]
    assert all(c["ok"] for c in doc["checks"])
    assert any(c["name"] == "owasp-llm-coverage" for c in doc["checks"])


def test_owasp_coverage_requires_no_target_and_constructs_no_transport(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
) -> None:
    def boom(_controller):  # type: ignore[no-untyped-def]
        raise AssertionError("owasp-coverage must not construct transport")

    monkeypatch.setattr(cli, "_make_transport", boom)
    assert cli.main(["owasp-coverage"]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "OWASP Top 10 for LLM Applications 2025" in out
    assert "does not claim full OWASP coverage or compliance" in out


def test_owasp_coverage_json_is_machine_readable(capsys: pytest.CaptureFixture) -> None:
    import json

    assert cli.main(["owasp-coverage", "--format", "json"]) == cli.EXIT_OK
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema_version"] == "owasp-llm-coverage-v1"
    assert len(doc["categories"]) == 10
