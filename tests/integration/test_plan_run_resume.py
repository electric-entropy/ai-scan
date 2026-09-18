from __future__ import annotations

import pytest

from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import CheckpointError, RunState, compile_plan, load_checkpoint
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan


def test_plan_run_resume_same_findings_no_duplicate_state_change(tmp_path) -> None:
    target = normalize_target("http://127.0.0.1:8000")
    plan = compile_plan(target, "reliable", seed=123)
    checkpoint = tmp_path / "resume.ckpt"
    canary = "AISCAN-RESUME"
    calls: list[str] = []
    crash_after = len(plan.control_cases()) + 1

    def crashing_responder(case):  # type: ignore[no-untyped-def]
        calls.append(case.template)
        if len(calls) > crash_after:
            raise KeyboardInterrupt
        return ExchangeOutcome(canary if "{canary}" in case.template else "benign")

    cancelled = run_plan(
        plan,
        crashing_responder,
        canary=canary,
        goal="",
        checkpoint_path=str(checkpoint),
    )
    assert cancelled.state is RunState.CANCELLED
    completed_checkpoint = load_checkpoint(str(checkpoint), expected_plan_digest=plan.digest)
    completed_before_resume = set(completed_checkpoint.completed)

    resumed_calls: list[str] = []

    def resumed_responder(case):  # type: ignore[no-untyped-def]
        resumed_calls.append(case.template)
        return ExchangeOutcome(canary if "{canary}" in case.template else "benign")

    with pytest.raises(CheckpointError, match="unresolved"):
        run_plan(
            plan, resumed_responder, canary=canary, goal="", checkpoint_path=str(checkpoint)
        )

    # The issued-but-interrupted control attempt is accounted and reconciled as
    # an unusable spent trial. That must not be re-issued to paper over the crash,
    # so the resumed run honestly ends with a coverage gap rather than pretending
    # to match a fresh uninterrupted run.
    assert resumed_calls == []
    final_checkpoint = load_checkpoint(str(checkpoint), expected_plan_digest=plan.digest)
    assert completed_before_resume <= set(final_checkpoint.completed)
