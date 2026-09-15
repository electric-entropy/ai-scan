from __future__ import annotations

import json

import pytest

from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import (
    CheckpointError,
    PlanError,
    RunState,
    compile_plan,
    load_checkpoint,
    run_plan,
)
from ai_scan.orchestration.checkpoint import Checkpoint, write_checkpoint_atomic
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target


def test_run_result_status_preserves_seven_state() -> None:
    from ai_scan.injection import InjectionFinding, InjectionStatus
    from ai_scan.orchestration import RunResult

    def _result(*statuses):
        findings = tuple(InjectionFinding("fam", s, "p") for s in statuses)
        return RunResult(RunState.COMPLETED, findings, 1)

    # Suspected-only / likely-only runs must NOT collapse to not_observed.
    assert _result(InjectionStatus.SUSPECTED).status is InjectionStatus.SUSPECTED
    assert _result(InjectionStatus.LIKELY).status is InjectionStatus.LIKELY
    assert _result(InjectionStatus.BLOCKED).status is InjectionStatus.BLOCKED
    # Highest-severity finding wins across the seven-state vocabulary.
    assert _result(
        InjectionStatus.NOT_OBSERVED, InjectionStatus.SUSPECTED, InjectionStatus.LIKELY
    ).status is InjectionStatus.LIKELY
    assert _result(
        InjectionStatus.LIKELY, InjectionStatus.CONFIRMED
    ).status is InjectionStatus.CONFIRMED
    assert _result().status is InjectionStatus.NOT_OBSERVED


def test_runner_rejects_plan_digest_mismatch_before_requests() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    calls = 0

    def responder(_case):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return ExchangeOutcome("ok")

    with pytest.raises(PlanError, match="expected plan"):
        run_plan(plan, responder, canary="AISCAN-X", goal="", expected_plan_digest="0" * 64)

    assert calls == 0


def test_resume_does_not_repeat_completed_physical_attempt(tmp_path) -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    first_attack = plan.attack_cases()[0]
    checkpoint_path = tmp_path / "run.ckpt"
    # A legacy checkpoint (no canary field) whose completed confirmation is
    # *safety-valid*: enough trials/successes and a matched clean control, so it
    # legitimately resumes without repeating physical attempts.
    ckpt = Checkpoint(plan_digest=plan.digest, state=RunState.CONFIRMING.value, request_count=1)
    ckpt.completed[first_attack.case_id] = {
        "family": first_attack.family,
        "status": "confirmed",
        "prompt": first_attack.template.replace("{canary}", "AISCAN-X"),
        "proof": "model output >> AISCAN-X << executed",
        "kind": "attack",
        "attack_trials": 3,
        "successes": 3,
    }
    ckpt.control_results[f"{first_attack.pack_id}:{first_attack.family}"] = "clean"
    write_checkpoint_atomic(str(checkpoint_path), ckpt)
    seen: list[str] = []

    def responder(case):  # type: ignore[no-untyped-def]
        seen.append(case.template)
        return ExchangeOutcome("no signal")

    result = run_plan(
        plan, responder, canary="AISCAN-X", goal="", checkpoint_path=str(checkpoint_path)
    )

    assert result.state is RunState.COMPLETED
    assert first_attack.template not in seen
    # Repeated trials: controls run min_control_trials, attacks min_attack_trials;
    # the pre-completed attack is not re-run. The prior request_count (1) is kept.
    min_a, _, min_c = plan.trial_policy
    controls = plan.control_cases()
    attacks = plan.attack_cases()
    assert result.request_count == 1 + len(controls) * min_c + (len(attacks) - 1) * min_a


def test_control_canary_blocks_confirmation(tmp_path) -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")

    def responder(case):  # type: ignore[no-untyped-def]
        return ExchangeOutcome(f"benign echo AISCAN-X for {case.family}")

    result = run_plan(
        plan, responder, canary="AISCAN-X", goal="", checkpoint_path=str(tmp_path / "r.ckpt")
    )

    assert result.state is RunState.COMPLETED
    assert result.findings
    # A control that emits the canary poisons the family baseline: attacks are
    # capped at 'suspected' (7-state preserved, never collapsed to 'potential').
    assert all(f.status.value != "confirmed" for f in result.findings)
    assert any(f.status.value == "suspected" for f in result.findings)


def test_budget_exhaustion_emits_coverage_gap(tmp_path) -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    object.__setattr__(plan.limits, "max_physical_requests", 1)

    def responder(_case):  # type: ignore[no-untyped-def]
        return ExchangeOutcome("ok")

    result = run_plan(
        plan, responder, canary="AISCAN-X", goal="", checkpoint_path=str(tmp_path / "r.ckpt")
    )

    assert result.state is RunState.COMPLETED_WITH_GAPS
    assert result.coverage_gaps


def test_checkpoint_tamper_and_plan_mismatch_fail_closed(tmp_path) -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    path = tmp_path / "run.ckpt"
    write_checkpoint_atomic(str(path), Checkpoint(plan_digest=plan.digest, state="planned"))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["request_count"] = 999
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(CheckpointError, match="digest"):
        load_checkpoint(str(path), expected_plan_digest=plan.digest)

    other = tmp_path / "other.ckpt"
    write_checkpoint_atomic(str(other), Checkpoint(plan_digest="a" * 64, state="planned"))
    with pytest.raises(CheckpointError, match="different plan"):
        load_checkpoint(str(other), expected_plan_digest=plan.digest)


def test_checkpoint_rejects_redigested_malformed_fields(tmp_path) -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    path = tmp_path / "run.ckpt"
    write_checkpoint_atomic(str(path), Checkpoint(plan_digest=plan.digest, state="planned"))
    data = json.loads(path.read_text(encoding="utf-8"))
    data["request_count"] = True
    data["digest"] = compute_digest(data)
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(CheckpointError, match="malformed"):
        load_checkpoint(str(path), expected_plan_digest=plan.digest)


def test_ordinary_exception_transitions_to_failed_terminal_state(tmp_path) -> None:
    # An ordinary error mid-run must pass through the CLEANING_UP phase to the
    # terminal FAILED state (checkpoint persisted), then propagate the error.
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    checkpoint_path = tmp_path / "err.ckpt"

    def responder(case):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        run_plan(
            plan, responder, canary="AISCAN-X", goal="",
            checkpoint_path=str(checkpoint_path),
        )
    restored = load_checkpoint(str(checkpoint_path), expected_plan_digest=plan.digest)
    assert restored.state == RunState.FAILED.value


def test_run_plan_has_no_unbudgeted_cleanup_callback() -> None:
    # There must be no arbitrary, network-capable cleanup callback parameter: any
    # side-effect cleanup is a budgeted broker step, not an unaccounted path.
    import inspect

    assert "cleanup" not in inspect.signature(run_plan).parameters


def test_cancellation_transitions_to_cancelled_and_persists_state(tmp_path) -> None:
    # A responder that interrupts mid-run → runner passes through CLEANING_UP to
    # the CANCELLED terminal state and persists a safe, reloadable checkpoint.
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    checkpoint_path = tmp_path / "cancel.ckpt"
    calls = {"n": 0}

    def responder(case):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 3:
            raise KeyboardInterrupt
        return ExchangeOutcome("benign")

    result = run_plan(
        plan,
        responder,
        canary="AISCAN-X",
        goal="",
        checkpoint_path=str(checkpoint_path),
    )
    assert result.state is RunState.CANCELLED
    # The persisted checkpoint is valid and reloads (safe state, no secrets).
    restored = load_checkpoint(str(checkpoint_path), expected_plan_digest=plan.digest)
    assert restored.state == RunState.CANCELLED.value
