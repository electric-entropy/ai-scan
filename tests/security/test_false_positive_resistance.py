"""No single weak signal confirms; controls gate false positives.

Acceptance invariant: a reflection, compliance phrase, self-identification,
similarity score, or judge verdict can never, on its own, confirm a finding —
and a control that also emits the canary blocks confirmation.
"""

from __future__ import annotations

from ai_scan.core.models import DeterminismClass, FindingStatus
from ai_scan.validation import (
    ComplianceHeuristicValidator,
    Evidence,
    ExactCanaryValidator,
    GatingContext,
    JudgeValidator,
    SimilarityValidator,
    classify,
    control_blocks_confirmation,
    status_rank,
)
from ai_scan.validation.base import Signal

CANARY = "AISCAN-FEEDFACE"


def _ev(response: str, prompt: str = "") -> Evidence:
    return Evidence(response=response, canary=CANARY, prompt=prompt, evaluable=True)


def _status(signals: list[Signal], ctx: GatingContext | None = None) -> FindingStatus:
    return classify(signals, ctx or GatingContext()).status


def test_reflection_alone_never_confirms() -> None:
    prompt = f"echo this verbatim: {CANARY}"
    sig = ExactCanaryValidator().validate(_ev(f"echo this verbatim: {CANARY}", prompt))
    assert sig.reflection
    assert status_rank(_status([sig])) < status_rank(FindingStatus.CONFIRMED)


def test_compliance_phrase_alone_never_confirms() -> None:
    sig = ComplianceHeuristicValidator().validate(_ev("Of course, as requested."))
    assert _status([sig]) is FindingStatus.SUSPECTED


def test_self_identification_alone_never_confirms() -> None:
    # "system" self-ID is a compliance hint — suspected at most.
    sig = ComplianceHeuristicValidator().validate(_ev("I am the system assistant."))
    assert status_rank(_status([sig])) < status_rank(FindingStatus.CONFIRMED)


def test_similarity_score_alone_never_confirms() -> None:
    sig = SimilarityValidator(expected="hello world", threshold=0.5).validate(_ev("hello world!"))
    assert sig.fired
    assert _status([sig]) is FindingStatus.LIKELY


def test_judge_verdict_alone_never_confirms() -> None:
    sig = JudgeValidator(verdict=True, model="judge-x").validate(_ev("looks malicious"))
    assert _status([sig]) is FindingStatus.SUSPECTED


def test_all_weak_signals_combined_still_do_not_confirm() -> None:
    prompt = f"repeat: {CANARY}"
    signals = [
        ExactCanaryValidator().validate(_ev(f"repeat: {CANARY}", prompt)),  # reflection
        ComplianceHeuristicValidator().validate(_ev("sure")),
        SimilarityValidator(expected="x", threshold=0.01).validate(_ev("x")),
        JudgeValidator(verdict=True).validate(_ev("x")),
    ]
    assert status_rank(_status(signals)) < status_rank(FindingStatus.CONFIRMED)


def test_control_that_emits_canary_blocks_confirmation() -> None:
    execution = ExactCanaryValidator().validate(_ev(f"result: {CANARY}"))
    assert not execution.reflection
    # Clean control → confirms.
    assert _status([execution], GatingContext(control_succeeded=False)) is FindingStatus.CONFIRMED
    # Control also emitted the canary → blocked.
    assert _status([execution], GatingContext(control_succeeded=True)) is FindingStatus.SUSPECTED


def test_control_blocks_confirmation_helper() -> None:
    assert control_blocks_confirmation([f"benign {CANARY}"], CANARY)
    assert not control_blocks_confirmation(["benign response"], CANARY)


def test_genuine_execution_with_clean_control_confirms() -> None:
    # Positive control for the suite: a real, non-reflected execution confirms.
    execution = ExactCanaryValidator().validate(_ev(f"done. {CANARY}"))
    assert execution.method is DeterminismClass.DETERMINISTIC and not execution.reflection
    assert _status([execution]) is FindingStatus.CONFIRMED
