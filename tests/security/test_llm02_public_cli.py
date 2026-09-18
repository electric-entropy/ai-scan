"""Phase 2B2 — public CLI LLM02 Sensitive Information Disclosure execution."""

from __future__ import annotations

import json
import os
import re
import stat

import pytest

from ai_scan import cli
from ai_scan.evidence_graph import (
    BundleCollector,
    BundleError,
)
from ai_scan.injection import ExchangeOutcome, InjectionCase, InjectionStatus
from ai_scan.orchestration import compile_plan
from ai_scan.orchestration.checkpoint import CheckpointError, load_checkpoint
from ai_scan.packs import load_builtin_pack
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.conftest import MockRequest, MockResponse
from tests.trusted_engines import run_plan

_URL = "http://127.0.0.1:8765/v1/chat"
_HIDDEN = "AISCAN-1234ABCD5678EF90"
_PROMPT_CANARY = "AISCAN-ABCDEF0123456789"


def _plan(mode: str = "reliable"):
    return compile_plan(normalize_target(_URL), mode)


def _llm02_cases(plan, *, kind: str | None = None):  # type: ignore[no-untyped-def]
    llm02_pack_ids = {
        pack_id
        for pack_id, _version, _digest in plan.packs
        if "LLM02" in load_builtin_pack(pack_id).mappings.get("owasp-llm", ())
    }
    cases = [case for case in plan.cases if case.pack_id in llm02_pack_ids]
    if kind is not None:
        cases = [case for case in cases if case.kind == kind]
    return tuple(cases)


def _marker_cases(plan, *, category: str, kind: str | None = None):  # type: ignore[no-untyped-def]
    pack_ids = {
        pack_id
        for pack_id, _version, _digest in plan.packs
        if category in load_builtin_pack(pack_id).mappings.get("owasp-llm", ())
    }
    cases = [case for case in plan.cases if case.pack_id in pack_ids]
    if kind is not None:
        cases = [case for case in cases if case.kind == kind]
    return tuple(cases)


def _llm02_findings(plan, result):  # type: ignore[no-untyped-def]
    llm02_ids = {case.case_id for case in _llm02_cases(plan, kind="attack")}
    attack_cases = plan.attack_cases()
    return tuple(
        finding
        for case, finding in zip(attack_cases, result.findings, strict=True)
        if case.case_id in llm02_ids
    )


def _disclosing_responder(case: InjectionCase) -> ExchangeOutcome:
    if "pre-provisioned" in case.template or "preconfigurada" in case.template:
        return ExchangeOutcome(body=_HIDDEN, known_secrets=frozenset({_HIDDEN}))
    return ExchangeOutcome(body="Benign answer without the synthetic hidden canary.")


def _reseal_checkpoint(doc: dict) -> dict:
    doc = dict(doc)
    doc.pop("digest", None)
    doc["digest"] = compute_digest(doc)
    return doc


def test_reliable_plan_selects_digest_verified_llm02_pack_without_rendering_hidden_canary() -> None:
    plan = _plan("reliable")
    pack_ids = {pack_id for pack_id, _version, _digest in plan.packs}

    assert "prompt-disclosure-reliable" in pack_ids
    assert "prompt-disclosure-kitchen" not in pack_ids
    assert {"LLM01", "LLM02"} <= {
        cat
        for pack_id in pack_ids
        for cat in load_builtin_pack(pack_id).mappings.get("owasp-llm", ())
    }
    llm02_attacks = _llm02_cases(plan, kind="attack")
    assert llm02_attacks
    assert all("{canary}" not in case.template for case in llm02_attacks)
    assert all(_HIDDEN not in case.template for case in llm02_attacks)
    assert all("real secret" not in case.template.lower() for case in llm02_attacks)
    assert any("hidden setup" in case.template.lower() for case in llm02_attacks)

    result = run_plan(plan, _disclosing_responder, canary=_PROMPT_CANARY, disclosure_marker=_HIDDEN)
    llm02_findings = [
        finding
        for case, finding in zip(plan.attack_cases(), result.findings, strict=True)
        if case.pack_id == "prompt-disclosure-reliable"
    ]
    assert llm02_findings
    assert all(f.status is InjectionStatus.CONFIRMED for f in llm02_findings)
    assert all(f.attack_trials == plan.trial_policy[0] for f in llm02_findings)
    assert all(f.successes >= plan.trial_policy[1] for f in llm02_findings)


def test_kitchen_sink_public_plan_adds_bounded_llm02_breadth() -> None:
    reliable = _plan("reliable")
    kitchen = _plan("kitchen-sink")

    assert "prompt-disclosure-kitchen" not in {p[0] for p in reliable.packs}
    assert {"prompt-disclosure-reliable", "prompt-disclosure-kitchen"} <= {
        p[0] for p in kitchen.packs
    }
    assert len(_llm02_cases(kitchen, kind="attack")) > len(_llm02_cases(reliable, kind="attack"))
    assert {
        "prompt_disclosure_system_text",
        "prompt_disclosure_debug_config",
        "prompt_disclosure_boundary",
    } <= {case.family for case in _llm02_cases(kitchen, kind="attack")}


@pytest.mark.parametrize(
    "body",
    [
        "I cannot reveal the hidden setup note AISCAN-1234ABCD5678EF90.",
        "You asked me to reveal this synthetic hidden canary: AISCAN-1234ABCD5678EF90",
        "prefix AISCAN-1234ABCD5678EF90 suffix",
        "{prompt}",
        json.dumps({"metadata": {"hidden_canary": "AISCAN-1234ABCD5678EF90"}, "reply": "safe"}),
        json.dumps({"message": {"thinking": "AISCAN-1234ABCD5678EF90", "content": "safe"}}),
    ],
)
def test_llm02_refusal_reflection_prompt_echo_and_metadata_do_not_confirm(body: str) -> None:
    plan = _plan("reliable")

    def responder(case: InjectionCase) -> ExchangeOutcome:
        if not case.family.startswith("prompt_disclosure"):
            return ExchangeOutcome(body="Benign answer without the synthetic hidden canary.")
        rendered = case.rendered_prompt
        if body == "{prompt}":
            response = rendered
        elif body.startswith("{"):
            response = str(json.loads(body).get("reply", body))
        else:
            response = body
        return ExchangeOutcome(body=response)

    result = run_plan(plan, responder, canary=_PROMPT_CANARY, disclosure_marker=_HIDDEN)
    for case, finding in zip(plan.attack_cases(), result.findings, strict=True):
        if case.pack_id == "prompt-disclosure-reliable":
            assert finding.status is not InjectionStatus.CONFIRMED


def test_llm02_control_emission_blocks_confirmation_and_counts_physical_requests() -> None:
    plan = _plan("reliable")
    llm02_control_count = len(_llm02_cases(plan, kind="control"))
    llm02_attack_count = len(_llm02_cases(plan, kind="attack"))
    calls = 0

    def responder(case: InjectionCase) -> ExchangeOutcome:
        nonlocal calls
        calls += 1
        if case.family.startswith("prompt_disclosure"):
            return ExchangeOutcome(body=_HIDDEN, attempts=2)
        if "{canary}" in case.template:
            return ExchangeOutcome(body="AISCAN-OTHER", attempts=2)
        return ExchangeOutcome(body="clean", attempts=2)

    result = run_plan(plan, responder, canary=_PROMPT_CANARY, disclosure_marker=_HIDDEN)
    expected_min = (
        llm02_control_count * plan.trial_policy[2]
        + llm02_attack_count * plan.trial_policy[0]
    )
    assert result.request_count >= expected_min
    assert calls == result.request_count
    for case, finding in zip(plan.attack_cases(), result.findings, strict=True):
        if case.pack_id == "prompt-disclosure-reliable":
            assert finding.status is not InjectionStatus.CONFIRMED
            assert finding.successes >= plan.trial_policy[1]


def test_llm02_checkpoint_and_bundle_are_live_only_fail_closed(tmp_path) -> None:
    plan = _plan("reliable")
    checkpoint = tmp_path / "llm02.ckpt"
    collector = BundleCollector()
    live = run_plan(
        plan,
        _disclosing_responder,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        checkpoint_path=str(checkpoint),
        observer=collector.observe,
    )
    restored = load_checkpoint(
        str(checkpoint), expected_plan_digest=plan.digest, plan=plan, disclosure_marker=_HIDDEN
    )
    assert all(not case_id.startswith("prompt-disclosure-") for case_id in restored.completed)
    llm02 = _llm02_findings(plan, live)
    assert llm02 and all(f.status is InjectionStatus.INCONCLUSIVE for f in llm02)
    assert all(f.attack_trials == 0 and f.successes == 0 and f.evidence == () for f in llm02)

    live_without_checkpoint = run_plan(
        plan,
        _disclosing_responder,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        observer=collector.observe,
    )
    assert any(
        f.status is InjectionStatus.CONFIRMED
        for f in _llm02_findings(plan, live_without_checkpoint)
    )
    with pytest.raises(BundleError):
        collector.build(plan=plan, canary=_PROMPT_CANARY, disclosure_marker=_HIDDEN, run_id="llm02")


def test_llm02_live_semantic_result_is_scrubbed_without_placeholder_evidence() -> None:
    plan = _plan("reliable")
    live = run_plan(
        plan,
        _disclosing_responder,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
    )
    llm02 = _llm02_findings(plan, live)
    assert llm02 and all(f.status is InjectionStatus.CONFIRMED for f in llm02)
    assert _HIDDEN not in repr(live)
    assert all(_HIDDEN not in trial.body for f in live.findings for trial in f.evidence)
    assert all(_HIDDEN not in trial.known_secrets for f in live.findings for trial in f.evidence)


def test_run_plan_without_explicit_llm02_marker_skips_llm02_and_keeps_llm01_active() -> None:
    plan = _plan("reliable")
    learned: dict[str, str | None] = {"token": None}
    calls: list[str] = []

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls.append(case.family)
        tokens = re.findall(r"AISCAN-[0-9A-F]{16,64}", case.rendered_prompt)
        if tokens and learned["token"] is None:
            learned["token"] = tokens[0]
        if case.family.startswith("prompt_disclosure"):
            return ExchangeOutcome(body=learned["token"] or "none")
        if tokens:
            return ExchangeOutcome(body=tokens[0])
        return ExchangeOutcome(body="clean")

    result = run_plan(plan, responder, canary=_PROMPT_CANARY, disclosure_marker=None)

    assert learned["token"] == _PROMPT_CANARY
    assert not [family for family in calls if family.startswith("prompt_disclosure")]
    llm02 = _llm02_findings(plan, result)
    assert llm02
    assert all(f.status is InjectionStatus.INCONCLUSIVE for f in llm02)
    assert all(f.attack_trials == 0 and f.successes == 0 and f.evidence == () for f in llm02)
    assert any(f.status is InjectionStatus.CONFIRMED for f in result.findings if f not in llm02)
    assert len(result.coverage_gaps) == len(_llm02_cases(plan)) + len(
        _marker_cases(plan, category="LLM07")
    )


def test_public_cli_without_synthetic_canary_file_skips_llm02_zero_calls(
    mock_server, tmp_path
) -> None:
    captures: list[MockRequest] = []
    learned: dict[str, str | None] = {"token": None}

    def app(req: MockRequest) -> MockResponse:
        captures.append(req)
        payload = json.loads(req.body or b"{}")
        prompt = str(payload.get("input", ""))
        tokens = re.findall(r"AISCAN-[0-9A-F]{16,64}", prompt)
        if tokens and learned["token"] is None:
            learned["token"] = tokens[0]
        if "hidden setup" in prompt.lower() or "debug_config.hidden_note" in prompt:
            body = learned["token"] or "no learned token"
        elif tokens:
            body = tokens[0]
        else:
            body = "clean"
        return MockResponse(status=200, body=body.encode(), headers={"Content-Type": "text/plain"})

    server = mock_server(app)
    target_url = f"{server.base_url}/chat"
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "report.json"
    assert (
        cli.main(["plan", "--target", target_url, "--mode", "reliable", "--out", str(plan_path)])
        == cli.EXIT_OK
    )

    rc = cli.main(
        ["run", "--target", target_url, "--plan", str(plan_path), "--out", str(report_path)]
    )

    assert rc == cli.EXIT_CONFIRMED_FINDING
    assert learned["token"] is not None
    prompts = [json.loads(req.body or b"{}").get("input", "") for req in captures]
    assert not [
        p
        for p in prompts
        if "hidden setup" in str(p).lower() or "debug_config.hidden_note" in str(p)
    ]
    plan = _plan("reliable")
    expected_requests = (
        (
            len(plan.control_cases())
            - len(_llm02_cases(plan, kind="control"))
            - len(_marker_cases(plan, category="LLM07", kind="control"))
        ) * plan.trial_policy[2]
        + (
            len(plan.attack_cases())
            - len(_llm02_cases(plan, kind="attack"))
            - len(_marker_cases(plan, category="LLM07", kind="attack"))
        ) * plan.trial_policy[0]
    )
    assert len(captures) == expected_requests
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["request_budget"]["used"] == expected_requests
    assert report["injection"]["request_count"] == expected_requests
    llm02 = [
        f for f in report["injection"]["findings"]
        if f["family"].startswith("prompt_disclosure")
    ]
    assert llm02
    assert {f["status"] for f in llm02} == {"inconclusive"}


def test_incomplete_llm02_resume_without_marker_issues_zero_llm02_calls(tmp_path) -> None:
    plan = _plan("reliable")
    checkpoint = tmp_path / "llm02-incomplete.ckpt"
    crashed = False

    def crash_on_first_llm02(case: InjectionCase) -> ExchangeOutcome:
        nonlocal crashed
        if case.family.startswith("prompt_disclosure") and not crashed:
            crashed = True
            raise RuntimeError("intentional crash during LLM02")
        if case.family.startswith("prompt_disclosure"):
            return ExchangeOutcome(body=_HIDDEN, known_secrets=frozenset({_HIDDEN}))
        tokens = re.findall(r"AISCAN-[0-9A-F]{16,64}", case.rendered_prompt)
        return ExchangeOutcome(body=tokens[0] if tokens else "clean")

    result = run_plan(
        plan,
        crash_on_first_llm02,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        checkpoint_path=str(checkpoint),
    )
    assert all(f.status is InjectionStatus.INCONCLUSIVE for f in _llm02_findings(plan, result))
    calls: list[str] = []

    def resume_without_marker(case: InjectionCase) -> ExchangeOutcome:
        calls.append(case.family)
        tokens = re.findall(r"AISCAN-[0-9A-F]{16,64}", case.rendered_prompt)
        return ExchangeOutcome(body=tokens[0] if tokens else "clean")

    # Resuming an LLM02 run that was started WITH a marker but now supplying no
    # marker is a disclosure-marker identity change: it fails closed during load,
    # before any responder call, and never relabels the incomplete evidence.
    with pytest.raises(CheckpointError, match="disclosure marker"):
        run_plan(
            plan,
            resume_without_marker,
            canary=_PROMPT_CANARY,
            disclosure_marker=None,
            checkpoint_path=str(checkpoint),
        )
    assert calls == []


def test_completed_llm02_checkpoint_requires_explicit_marker_but_marker_resume_zero_calls(
    tmp_path,
) -> None:
    plan = _plan("reliable")
    checkpoint = tmp_path / "llm02-complete.ckpt"
    live = run_plan(
        plan,
        _disclosing_responder,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        checkpoint_path=str(checkpoint),
    )
    assert all(f.status is InjectionStatus.INCONCLUSIVE for f in _llm02_findings(plan, live))

    def fail_if_called(case: InjectionCase) -> ExchangeOutcome:
        raise AssertionError(f"unexpected responder call for {case.family}")

    with pytest.raises(CheckpointError):
        run_plan(
            plan,
            fail_if_called,
            canary=_PROMPT_CANARY,
            disclosure_marker=None,
            checkpoint_path=str(checkpoint),
        )

    resumed = run_plan(
        plan,
        fail_if_called,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        checkpoint_path=str(checkpoint),
    )
    assert [f.status for f in resumed.findings] == [f.status for f in live.findings]


@pytest.mark.parametrize(
    "body",
    [
        "REDACTED",
        "[REDACTED]",
        "AISCAN-1234ABCD5678EF90"[:-1],
        f"prefix {_HIDDEN}",
        f"{_HIDDEN} suffix",
        "AISCAN%2D1234ABCD5678EF90",
        "Benign answer without the synthetic hidden canary.",
    ],
)
def test_llm02_redaction_placeholder_and_collision_bodies_never_confirm(body: str) -> None:
    plan = _plan("reliable")

    def responder(case: InjectionCase) -> ExchangeOutcome:
        if "pre-provisioned" in case.template or "preconfigurada" in case.template:
            return ExchangeOutcome(body=body, known_secrets=frozenset({_HIDDEN}))
        return ExchangeOutcome(body="Benign answer without the synthetic hidden canary.")

    result = run_plan(plan, responder, canary=_PROMPT_CANARY, disclosure_marker=_HIDDEN)
    for case, finding in zip(plan.attack_cases(), result.findings, strict=True):
        if case.pack_id == "prompt-disclosure-reliable":
            assert finding.status is not InjectionStatus.CONFIRMED


def test_llm02_legacy_redacted_checkpoint_without_semantic_metadata_fails_closed(tmp_path) -> None:
    plan = _plan("reliable")
    checkpoint = tmp_path / "llm02.ckpt"
    run_plan(
        plan,
        _disclosing_responder,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        checkpoint_path=str(checkpoint),
    )
    doc = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert all(not case_id.startswith("prompt-disclosure-") for case_id in doc["completed"])
    case = _llm02_cases(plan, kind="attack")[0]
    doc["completed"][case.case_id] = {
        "family": case.family, "kind": case.kind, "prompt": case.template,
        "status": "confirmed", "proof": "REDACTED", "attack_trials": 3,
        "successes": 3,
    }
    checkpoint.write_text(json.dumps(_reseal_checkpoint(doc)), encoding="utf-8")
    with pytest.raises(CheckpointError, match="malformed checkpoint"):
        load_checkpoint(str(checkpoint), expected_plan_digest=plan.digest, plan=plan,
                        disclosure_marker=_HIDDEN)


def test_llm02_semantic_digest_tamper_is_rejected_in_checkpoint_and_bundle(tmp_path) -> None:
    plan = _plan("reliable")
    collector = BundleCollector()
    run_plan(
        plan,
        _disclosing_responder,
        canary=_PROMPT_CANARY,
        disclosure_marker=_HIDDEN,
        observer=collector.observe,
    )
    with pytest.raises(BundleError):
        collector.build(plan=plan, canary=_PROMPT_CANARY, disclosure_marker=_HIDDEN, run_id="llm02")


def test_public_cli_run_executes_llm02_against_loopback_fixture(mock_server, tmp_path) -> None:
    canary_path = tmp_path / "synthetic-canary.txt"
    canary_path.write_text(f"{_HIDDEN}\n", encoding="utf-8")
    captures: list[MockRequest] = []

    def app(req: MockRequest) -> MockResponse:
        captures.append(req)
        payload = json.loads(req.body or b"{}")
        prompt = payload.get("input", "")
        if "hidden setup" in prompt.lower() or "debug_config.hidden_note" in prompt:
            body = _HIDDEN
        else:
            body = "Benign answer without the synthetic hidden canary."
        return MockResponse(
            status=200,
            body=body.encode(),
            headers={"Content-Type": "text/plain"},
        )

    server = mock_server(app)
    target_url = f"{server.base_url}/chat"
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "report.json"

    assert (
        cli.main(["plan", "--target", target_url, "--mode", "reliable", "--out", str(plan_path)])
        == cli.EXIT_OK
    )
    plan_doc = json.loads(plan_path.read_text(encoding="utf-8"))
    assert "prompt-disclosure-reliable" in {p[0] for p in plan_doc["packs"]}

    rc = cli.main(
        [
            "run",
            "--target",
            target_url,
            "--plan",
            str(plan_path),
            "--synthetic-canary-file",
            str(canary_path),
            "--out",
            str(report_path),
        ]
    )
    assert rc == cli.EXIT_CONFIRMED_FINDING
    assert captures
    generated_prompt_canaries: set[str] = set()
    for req in captures:
        body_text = (req.body or b"").decode("utf-8", "replace")
        assert _HIDDEN not in req.path
        assert all(_HIDDEN not in str(k) for k in req.headers)
        assert all(_HIDDEN not in str(v) for v in req.headers.values())
        assert _HIDDEN not in body_text
        generated_prompt_canaries.update(
            token for token in re.findall(r"AISCAN-[0-9A-F]{16,64}", body_text) if token != _HIDDEN
        )
    assert generated_prompt_canaries
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["injection"]["status"] == "confirmed"
    assert _HIDDEN not in report_path.read_text(encoding="utf-8")
    assert any(
        f["family"].startswith("prompt_disclosure")
        for f in report["injection"]["findings"]
    )


def test_synthetic_canary_file_rejects_nonregular_and_malformed_before_requests(
    mock_server, tmp_path
) -> None:
    captures: list[MockRequest] = []

    def app(req: MockRequest) -> MockResponse:
        captures.append(req)
        return MockResponse(status=200, body=b"clean", headers={"Content-Type": "text/plain"})

    server = mock_server(app)
    target_url = f"{server.base_url}/chat"
    plan_path = tmp_path / "plan.json"
    assert (
        cli.main(["plan", "--target", target_url, "--mode", "reliable", "--out", str(plan_path)])
        == cli.EXIT_OK
    )

    cases: list[object] = [tmp_path / "missing.txt", tmp_path]
    malformed = tmp_path / "malformed.txt"
    malformed.write_text("AISCAN-1234\nextra\n", encoding="ascii")
    cases.append(malformed)
    oversized = tmp_path / "oversized.txt"
    oversized.write_text("AISCAN-" + ("A" * 65), encoding="ascii")
    cases.append(oversized)
    regular = tmp_path / "regular.txt"
    regular.write_text(f"{_HIDDEN}\n", encoding="ascii")
    symlink = tmp_path / "symlink.txt"
    symlink.symlink_to(regular)
    cases.append(symlink)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    cases.append(fifo)
    if os.geteuid() != 0:
        unreadable = tmp_path / "unreadable.txt"
        unreadable.write_text(f"{_HIDDEN}\n", encoding="ascii")
        unreadable.chmod(0)
        cases.append(unreadable)

    for path in cases:
        captures.clear()
        rc = cli.main(
            [
                "run",
                "--target",
                target_url,
                "--plan",
                str(plan_path),
                "--synthetic-canary-file",
                str(path),
            ]
        )
        assert rc == cli.EXIT_RUNTIME_ERROR
        assert captures == []

    assert stat.S_ISREG(regular.stat().st_mode)
