"""Integration: run → bundle → replay, plus offline bundle CLI (no transport)."""

from __future__ import annotations

import dataclasses

from ai_scan import cli
from ai_scan.evidence_graph import BundleCollector, dump_bundle, replay_bundle
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import compile_plan, run_plan
from ai_scan.orchestration.planner import load_plan, plan_to_dict
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target

CANARY = "AISCAN-INTEG0001"


def _plan():  # type: ignore[no-untyped-def]
    return compile_plan(normalize_target("http://127.0.0.1:8080/chat"), "reliable")


def _confirming_responder(case):  # type: ignore[no-untyped-def]
    # Realistic execution response: canary in response context, not a bare echo.
    body = f"model output: {CANARY} (executed)" if "{canary}" in case.template else "benign"
    return ExchangeOutcome(body=body)


def test_run_bundle_replay_reproduces_findings(tmp_path) -> None:
    plan = _plan()
    collector = BundleCollector()
    result = run_plan(plan, _confirming_responder, canary=CANARY, goal="g",
                      observer=collector.observe)
    bundle = collector.build(plan=plan, canary=CANARY, run_id="run-1",
                             coverage_gaps=result.coverage_gaps)

    replayed = replay_bundle(dump_bundle(bundle))
    original = {f.prompt: f.status.value for f in result.findings}
    assert replayed.verified
    # Every confirmed attack in the run reproduces as confirmed in replay.
    assert all(s == "confirmed" for s in replayed.findings.values())
    assert any(s == "confirmed" for s in original.values())


def test_budget_gaps_are_preserved_in_bundle_and_replay(tmp_path) -> None:
    plan = _plan()
    # Re-digest a small-budget variant so its digest matches its (modified)
    # content — a Plan's digest is content-bound, so a bare dataclasses.replace
    # would leave it stale.
    doc = plan_to_dict(
        dataclasses.replace(plan, limits=dataclasses.replace(plan.limits, max_physical_requests=6))
    )
    doc.pop("digest")
    doc["digest"] = compute_digest(doc)
    tight = load_plan(doc)
    collector = BundleCollector()
    result = run_plan(tight, _confirming_responder, canary=CANARY, goal="g",
                      observer=collector.observe)
    assert result.coverage_gaps  # some attacks were skipped
    bundle = collector.build(plan=tight, canary=CANARY, run_id="run-2",
                             coverage_gaps=result.coverage_gaps)
    replayed = replay_bundle(dump_bundle(bundle))
    assert replayed.coverage_gaps == tuple(result.coverage_gaps)


def test_cli_bundle_validate_and_replay_are_offline(tmp_path, monkeypatch, capsys) -> None:
    plan = _plan()
    collector = BundleCollector()
    result = run_plan(plan, _confirming_responder, canary=CANARY, goal="g",
                      observer=collector.observe)
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(
        dump_bundle(collector.build(plan=plan, canary=CANARY, run_id="run-3",
                                    coverage_gaps=result.coverage_gaps)),
        encoding="utf-8",
    )

    def boom(_controller):  # type: ignore[no-untyped-def]
        raise AssertionError("bundle commands must not construct transport")

    monkeypatch.setattr(cli, "_make_transport", boom)

    assert cli.main(["bundle", "validate", "--file", str(bundle_path)]) == cli.EXIT_OK
    assert "valid: bundle digest=" in capsys.readouterr().out

    assert cli.main(["bundle", "replay", "--file", str(bundle_path)]) == cli.EXIT_OK
    assert "replayed: verified=True" in capsys.readouterr().out


def test_cli_bundle_validate_rejects_tampered_file(tmp_path, capsys) -> None:
    plan = _plan()
    collector = BundleCollector()
    run_plan(plan, _confirming_responder, canary=CANARY, goal="g", observer=collector.observe)
    bundle_path = tmp_path / "bad.json"
    text = dump_bundle(collector.build(plan=plan, canary=CANARY, run_id="run-4"))
    bundle_path.write_text(text.replace(CANARY, "AISCAN-TWEAKED1"), encoding="utf-8")

    assert cli.main(["bundle", "validate", "--file", str(bundle_path)]) == cli.EXIT_RUNTIME_ERROR
    assert "invalid:" in capsys.readouterr().out
