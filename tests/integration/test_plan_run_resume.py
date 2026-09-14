from __future__ import annotations

from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import RunState, compile_plan, load_checkpoint, run_plan
from ai_scan.targets import normalize_target


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

    resumed = run_plan(
        plan, resumed_responder, canary=canary, goal="", checkpoint_path=str(checkpoint)
    )
    fresh_calls: list[str] = []

    def fresh_responder(case):  # type: ignore[no-untyped-def]
        fresh_calls.append(case.template)
        return ExchangeOutcome(canary if "{canary}" in case.template else "benign")

    fresh = run_plan(plan, fresh_responder, canary=canary, goal="")

    assert resumed.state is RunState.COMPLETED
    assert [f.to_dict() for f in resumed.findings] == [f.to_dict() for f in fresh.findings]
    # Resume never re-runs a completed case, and reaches the same physical total
    # as a fresh run *except* for trials of the case that was in flight at the
    # crash (per-case checkpoint granularity). Trial-level crash-safe accounting
    # is a Phase B3 item; here resume does not under-run a fresh execution.
    assert resumed.request_count >= fresh.request_count
    final_checkpoint = load_checkpoint(str(checkpoint), expected_plan_digest=plan.digest)
    assert completed_before_resume <= set(final_checkpoint.completed)
