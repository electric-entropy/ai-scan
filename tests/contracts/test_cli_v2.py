"""Milestone 19 CLI v2 compatibility and migration contract."""

from __future__ import annotations

import json

from ai_scan import cli
from ai_scan.authorization import Receipt, write_receipt
from ai_scan.targets import normalize_target
from tests.conftest import MockRequest, MockResponse


def _receipt(tmp_path, url: str) -> str:
    path = tmp_path / "auth.json"
    write_receipt(
        Receipt.create(
            target=normalize_target(url), client="C", engagement="E", expires="2999-01-01"
        ),
        str(path),
    )
    return str(path)


def _plan_bound_receipt(tmp_path, url: str, plan_digest: str) -> str:
    path = tmp_path / "auth.json"
    write_receipt(
        Receipt.create(
            target=normalize_target(url), client="C", engagement="E",
            expires="2999-01-01", plan_digest=plan_digest,
        ),
        str(path),
    )
    return str(path)


def _legacy_report(path) -> None:
    path.write_text(
        json.dumps(
            {
                "tool": "ai-scan",
                "schema_version": "1.0",
                "target_origin": "https://api.example.com",
                "authorization": {"mode": "receipt", "client": "C", "engagement": "E"},
                "created_at": "2026-09-13T00:00:00+00:00",
                "request_budget": {"max_requests": 10, "used": 2},
                "fingerprint": None,
                "injection": {
                    "status": "potential",
                    "goal": "g",
                    "request_count": 2,
                    "findings": [
                        {
                            "family": "direct",
                            "status": "potential",
                            "prompt": "token-like canary label",
                            "proof": None,
                        }
                    ],
                },
                "evidence": [],
                "findings": [],
            }
        ),
        encoding="utf-8",
    )


def test_v2_subcommands_are_registered_and_mvp_commands_remain_subset() -> None:
    parser = cli.build_parser()
    action = next(a for a in parser._actions if a.dest == "command")  # noqa: SLF001
    choices = set(action.choices)
    assert {"authorize", "fingerprint", "inject", "assess", "validate-receipt"} <= choices
    assert {"packs", "adapters", "plan", "run", "report", "baseline", "bundle"} <= choices


def test_offline_commands_do_not_construct_transport(tmp_path, monkeypatch) -> None:
    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))

    report_path = tmp_path / "report.json"
    baseline_path = tmp_path / "baseline.json"
    _legacy_report(report_path)

    assert cli.main(["adapters", "list"]) == cli.EXIT_OK
    assert cli.main(["adapters", "show", "generic_http"]) == cli.EXIT_OK
    assert cli.main(["report", "--file", str(report_path), "--format", "sarif"]) == cli.EXIT_OK
    assert cli.main(
        ["baseline", "create", "--file", str(report_path), "--out", str(baseline_path)]
    ) == cli.EXIT_OK
    assert cli.main(
        ["baseline", "diff", "--old", str(baseline_path), "--new", str(baseline_path)]
    ) == cli.EXIT_OK
    assert constructed["n"] == 0


def test_plan_and_run_execute_through_authorized_runner(mock_server, tmp_path) -> None:
    hits = {"n": 0}

    def app(req: MockRequest) -> MockResponse:
        hits["n"] += 1
        payload = json.loads(req.body or b"{}")
        text = payload.get("input", "")
        # Emit canaries only for attack prompts; control prompts should stay benign.
        reply = next((part for part in text.split() if part.startswith("AISCAN-")), "benign")
        return MockResponse(status=200, body=json.dumps({"reply": reply}).encode("utf-8"))

    server = mock_server(app)
    url = f"{server.base_url}/chat"
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "run-report.json"

    assert cli.main(["plan", "--target", url, "--out", str(plan_path)]) == cli.EXIT_OK
    plan_digest = json.loads(plan_path.read_text(encoding="utf-8"))["digest"]
    receipt = _plan_bound_receipt(tmp_path, url, plan_digest)
    rc = cli.main(
        [
            "run",
            "--target",
            url,
            "--plan",
            str(plan_path),
            "--auth-receipt",
            receipt,
            "--non-interactive",
            "--out",
            str(report_path),
        ]
    )
    assert rc in {cli.EXIT_OK, cli.EXIT_CONFIRMED_FINDING}
    assert hits["n"] > 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["request_budget"]["plan_digest"] == json.loads(plan_path.read_text())["digest"]


def test_headless_v1_receipt_cannot_select_kitchen_sink_for_run(
    mock_server, tmp_path, monkeypatch
) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    receipt = _receipt(tmp_path, url)
    plan_path = tmp_path / "ks-plan.json"
    assert cli.main(
        ["plan", "--target", url, "--mode", "kitchen-sink", "--out", str(plan_path)]
    ) == cli.EXIT_OK

    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))

    assert cli.main(
        [
            "run",
            "--target",
            url,
            "--plan",
            str(plan_path),
            "--auth-receipt",
            receipt,
            "--non-interactive",
        ]
    ) == cli.EXIT_AUTH_DENIED
    assert constructed["n"] == 0


def test_assess_preserves_existing_default_profile_and_no_mode_selector() -> None:
    parser = cli.build_parser()
    command_action = next(a for a in parser._actions if a.dest == "command")  # noqa: SLF001
    assess = command_action.choices["assess"]
    defaults = {a.dest: a.default for a in assess._actions}  # noqa: SLF001
    assert "mode" not in defaults
    assert defaults["profile"] == "safe"
