"""Step 1C / Astra M3 — honest interruption accounting and per-trial progress.

Physical request accounting is write-ahead: an attempt's intent (and its budget
cost) is persisted *before* the responder/broker call, so an attempt that is
issued but interrupted before its outcome is recorded is still counted. Per-case
trial progress is persisted so a resumed run never repeats a completed trial, an
uncertain in-flight attempt reconciles (fail closed) rather than reissuing, and
the cumulative physical count can never reset or undercount.
"""

from __future__ import annotations

import json
import re

import pytest

from ai_scan.injection import ExchangeOutcome, InjectionCase
from ai_scan.orchestration import RunState, compile_plan
from ai_scan.orchestration.checkpoint import CheckpointError, load_checkpoint
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

_URL = "http://127.0.0.1:8000/chat"
_CANARY = "AISCAN-M3ACCT0001"
_RELIABLE_REQUEST_COUNT = 32


def _plan():  # type: ignore[no-untyped-def]
    return compile_plan(normalize_target(_URL), "reliable")


def _tight_plan(max_physical_requests: int):  # type: ignore[no-untyped-def]
    import dataclasses

    from ai_scan.orchestration.planner import load_plan, plan_to_dict

    plan = _plan()
    doc = plan_to_dict(
        dataclasses.replace(
            plan,
            limits=dataclasses.replace(
                plan.limits, max_physical_requests=max_physical_requests
            ),
        )
    )
    doc.pop("digest")
    doc["digest"] = compute_digest(doc)
    return load_plan(doc)


def _reply(case: InjectionCase) -> ExchangeOutcome:
    if "{canary}" in case.template:
        tok = re.search(r"AISCAN-[A-Z0-9]+", case.rendered_prompt).group(0)  # type: ignore[union-attr]
        return ExchangeOutcome(body=tok)
    return ExchangeOutcome(body="benign synthetic answer")


def _load(path) -> dict:  # type: ignore[no-untyped-def]
    return json.loads(path.read_text(encoding="utf-8"))


def _reseal(path, data) -> None:  # type: ignore[no-untyped-def]
    data.pop("digest", None)
    data["digest"] = compute_digest(data)
    path.write_text(json.dumps(data), encoding="utf-8")


class _InterruptAt:
    """Raises after entering the N-th physical responder call (attempt issued)."""

    def __init__(self, n: int) -> None:
        self.n = n
        self.calls = 0

    def __call__(self, case: InjectionCase) -> ExchangeOutcome:
        self.calls += 1
        if self.calls == self.n:
            raise KeyboardInterrupt
        return _reply(case)


class _CountView:
    def __init__(self, responder) -> None:  # type: ignore[no-untyped-def]
        self._responder = responder

    @property
    def count(self) -> int:
        return self._responder.calls


def _run_trusted(plan, counter, *, checkpoint_path):  # type: ignore[no-untyped-def]
    return run_plan(
        plan,
        counter,
        canary=_CANARY,
        checkpoint_path=str(checkpoint_path),
        physical_request_count=_CountView(counter),
    )


# --- honest accounting on interruption ---------------------------------------------


def test_no_interruption_counts_every_physical_attempt(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "run.ckpt"
    counter = _InterruptAt(10**9)
    result = _run_trusted(plan, counter, checkpoint_path=path)
    assert result.request_count == counter.calls == _RELIABLE_REQUEST_COUNT
    assert _load(path)["request_count"] == _RELIABLE_REQUEST_COUNT


def test_interrupt_on_second_control_is_counted_not_undercounted(tmp_path) -> None:
    # Astra regression: an attempt issued but interrupted before its outcome was
    # persisted used to be dropped (persisted 1, final 33 vs 34 actual). The count
    # must equal the attempts actually issued — persisted and returned alike.
    plan = _plan()
    path = tmp_path / "run.ckpt"
    control_trials = plan.trial_policy[2]
    interrupt_call = control_trials + 1  # first attempt of the SECOND control case
    counter = _InterruptAt(interrupt_call)

    result = _run_trusted(plan, counter, checkpoint_path=path)
    assert result.state is RunState.CANCELLED
    assert counter.calls == interrupt_call
    # Honest equality: returned == persisted == actually-issued attempts.
    assert result.request_count == interrupt_call
    assert _load(path)["request_count"] == interrupt_call


def test_intent_persisted_before_responder_call(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "run.ckpt"

    class _CheckIntent:
        def __init__(self) -> None:
            self.calls = 0

        def __call__(self, case: InjectionCase) -> ExchangeOutcome:
            self.calls += 1
            # Intent is durable before the trusted ledger reports acquisition.
            assert path.exists()
            persisted = _load(path)
            assert persisted["request_count"] == self.calls - 1
            assert persisted["in_flight"]["attempts"] == 0
            if self.calls == 3:
                raise KeyboardInterrupt
            return _reply(case)

    counter = _CheckIntent()
    _run_trusted(plan, counter, checkpoint_path=path)
    assert _load(path)["request_count"] == 3


# --- resume does not repeat completed work -----------------------------------------


def test_resume_does_not_repeat_completed_trials(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "run.ckpt"
    interrupt_call = 15
    interrupted = _InterruptAt(interrupt_call)
    _run_trusted(plan, interrupted, checkpoint_path=path)
    before = _load(path)["request_count"]
    assert before == interrupt_call

    counter = _InterruptAt(10**9)
    result = _run_trusted(plan, counter, checkpoint_path=path)
    assert result.state in (RunState.COMPLETED, RunState.COMPLETED_WITH_GAPS)
    # The resumed run issues only the REMAINING attempts; total never resets and
    # equals a single clean run's count. No completed trial is replayed.
    assert counter.calls == _RELIABLE_REQUEST_COUNT - before
    assert result.request_count == _RELIABLE_REQUEST_COUNT
    assert any(f.status.value == "confirmed" for f in result.findings)


def test_uncertain_in_flight_attempt_is_reconciled_not_reissued(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "run.ckpt"
    interrupted = _InterruptAt(5)
    _run_trusted(plan, interrupted, checkpoint_path=path)
    data = _load(path)
    assert data.get("in_flight") is not None  # an attempt was in flight at the crash
    before = data["request_count"]

    counter = _InterruptAt(10**9)
    result = _run_trusted(plan, counter, checkpoint_path=path)
    # The in-flight attempt was already counted; resume neither re-counts nor
    # reissues it as an extra physical attempt.
    assert result.request_count == _RELIABLE_REQUEST_COUNT
    assert counter.calls == _RELIABLE_REQUEST_COUNT - before


# --- forged / malformed progress fails closed --------------------------------------


def _interrupted_checkpoint(tmp_path):  # type: ignore[no-untyped-def]
    # Interrupt on a case's SECOND trial so that case has one persisted partial
    # trial (progress non-empty) plus one in-flight attempt.
    plan = _plan()
    path = tmp_path / "run.ckpt"
    control_trials = plan.trial_policy[2]
    attack_trials = plan.trial_policy[0]
    executable_controls = [
        c
        for c in plan.control_cases()
        if not c.family.startswith(("prompt_disclosure", "system_prompt_leakage"))
    ]
    second_trial_of_first_attack = control_trials * len(executable_controls) + 2
    interrupted = _InterruptAt(second_trial_of_first_attack)
    _run_trusted(plan, interrupted, checkpoint_path=path)
    assert attack_trials >= 2  # the interrupt lands on a genuine second trial
    return plan, path, _load(path)


def test_progress_for_unknown_case_rejected(tmp_path) -> None:
    plan, path, data = _interrupted_checkpoint(tmp_path)
    data.setdefault("progress", {})["nope:absent:attack:0"] = {
        "kind": "attack", "family": "f", "prompt": "x",
        "trials": [{"body": "b", "status": 200, "redirected": False,
                    "truncated": False, "transport_ok": True, "attempts": 1}],
    }
    _reseal(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


def test_progress_trials_over_budget_rejected(tmp_path) -> None:
    plan, path, data = _interrupted_checkpoint(tmp_path)
    progress = data.get("progress") or {}
    assert progress, "an interrupted mid-case run should persist progress"
    case_id, rec = next(iter(progress.items()))
    rec["trials"][0]["attempts"] = plan.limits.max_physical_requests + 1
    _reseal(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


@pytest.mark.parametrize("mutation", ["missing_semantic", "extra_field"])
def test_progress_trial_requires_exact_current_schema(tmp_path, mutation) -> None:  # type: ignore[no-untyped-def]
    plan, path, data = _interrupted_checkpoint(tmp_path)
    progress = data.get("progress") or {}
    assert progress
    trial = next(iter(progress.values()))["trials"][0]
    if mutation == "missing_semantic":
        assert "semantic" in trial
        trial.pop("semantic")
    else:
        trial["extra"] = None
    _reseal(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


def test_request_count_below_persisted_attempts_rejected(tmp_path) -> None:
    plan, path, data = _interrupted_checkpoint(tmp_path)
    data["request_count"] = 0  # undercount vs persisted completed/progress/in-flight
    _reseal(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


def test_in_flight_for_unknown_case_rejected(tmp_path) -> None:
    plan, path, data = _interrupted_checkpoint(tmp_path)
    data["in_flight"] = {"case_id": "nope:absent:attack:0", "kind": "attack",
                         "family": "f", "prompt": "x"}
    _reseal(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


def test_progress_prompt_not_plan_derived_rejected(tmp_path) -> None:
    plan, path, data = _interrupted_checkpoint(tmp_path)
    progress = data.get("progress") or {}
    case_id, rec = next(iter(progress.items()))
    rec["prompt"] = "forged prompt not from the plan"
    _reseal(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


# --- exhausted budget & legacy compatibility ---------------------------------------


def test_exhausted_budget_stops_issuing_and_counts_honestly(tmp_path, monkeypatch) -> None:
    import dataclasses

    from ai_scan.orchestration.planner import load_plan, plan_to_dict

    plan = _plan()
    doc = plan_to_dict(
        dataclasses.replace(plan, limits=dataclasses.replace(plan.limits, max_physical_requests=5))
    )
    doc.pop("digest")
    doc["digest"] = compute_digest(doc)
    # A hand-tightened plan is not canonical; run it directly against the runner
    # (compile-time budgets are canonical, but the runner must honor the ceiling).
    tight = load_plan(doc)
    path = tmp_path / "run.ckpt"
    counter = _InterruptAt(10**9)
    result = _run_trusted(tight, counter, checkpoint_path=path)
    assert counter.calls <= 5
    assert result.request_count <= 5
    assert _load(path)["request_count"] <= 5


def test_outcome_attempts_over_remaining_budget_are_ignored_as_untrusted(
    tmp_path,
) -> None:
    plan = _tight_plan(5)
    path = tmp_path / "run.ckpt"
    calls = {"n": 0}

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome(body="benign", attempts=10)

    result = run_plan(plan, responder, canary=_CANARY, checkpoint_path=str(path))
    data = _load(path)

    assert calls["n"] == 5
    assert result.request_count == 5
    assert data["request_count"] == 5
    assert result.state is RunState.COMPLETED_WITH_GAPS
    assert not any(f.status.value == "confirmed" for f in result.findings)
    assert all(
        all(t["attempts"] <= 5 for t in record.get("trials", []))
        for record in data.get("completed", {}).values()
    )


def test_outcome_attempts_equal_remaining_do_not_replace_trusted_counts(tmp_path) -> None:
    plan = _tight_plan(5)
    path = tmp_path / "run.ckpt"
    calls = {"n": 0}

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome(body="benign", attempts=5)

    result = run_plan(plan, responder, canary=_CANARY, checkpoint_path=str(path))
    assert result.request_count == 5
    assert _load(path)["request_count"] == 5
    assert calls["n"] == 5


@pytest.mark.parametrize("bad_attempts", [True, False, 0, -1])
def test_malformed_or_nonpositive_outcome_attempts_do_not_control_accounting(
    tmp_path, bad_attempts
) -> None:
    plan = _tight_plan(5)
    path = tmp_path / "run.ckpt"
    calls = {"n": 0}

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome(body="benign", attempts=bad_attempts)

    result = run_plan(plan, responder, canary=_CANARY, checkpoint_path=str(path))
    data = _load(path)
    assert calls["n"] == 5
    assert result.request_count == 5
    assert data["request_count"] == 5
    assert result.state is RunState.COMPLETED_WITH_GAPS
    assert not any(f.status.value == "confirmed" for f in result.findings)


def test_overshoot_after_resumed_progress_does_not_reset_or_persist_illegal_count(
    tmp_path,
) -> None:
    plan = _tight_plan(5)
    path = tmp_path / "run.ckpt"

    interrupted = _InterruptAt(3)
    _run_trusted(plan, interrupted, checkpoint_path=path)
    before = _load(path)["request_count"]
    assert before == 3

    calls = {"n": 0}

    def responder(case: InjectionCase) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome(body="benign", attempts=4)

    result = run_plan(plan, responder, canary=_CANARY, checkpoint_path=str(path))
    data = _load(path)
    assert calls["n"] == 2
    assert result.request_count == 5
    assert data["request_count"] == 5
    assert result.state is RunState.COMPLETED_WITH_GAPS


def test_legacy_checkpoint_without_progress_fields_fails_closed(tmp_path) -> None:
    # Current checkpoints have one exact closed schema; compatibility documents
    # missing crash-safe state cannot be interpreted as current evidence.
    plan = _plan()
    path = tmp_path / "run.ckpt"
    interrupted = _InterruptAt(15)
    _run_trusted(plan, interrupted, checkpoint_path=path)
    data = _load(path)
    data.pop("progress", None)
    data.pop("in_flight", None)
    data.pop("digest", None)
    data["request_count"] = sum(
        t["attempts"] for r in data["completed"].values() for t in r.get("trials", [])
    )
    data["digest"] = compute_digest(data)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
