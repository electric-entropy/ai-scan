"""No single weak signal confirms; controls gate false positives.

Acceptance invariant: a reflection, compliance phrase, self-identification,
similarity score, or judge verdict can never, on its own, confirm a finding —
and a control that also emits the canary blocks confirmation.
"""

from __future__ import annotations

from types import MappingProxyType

from ai_scan.core.models import DeterminismClass, FindingStatus, PackTrust, Severity
from ai_scan.injection import ExchangeOutcome, InjectionCase, InjectionStatus
from ai_scan.packs.schema import Pack, PackCase, TrialPolicy
from ai_scan.validation import (
    ComplianceHeuristicValidator,
    ControlValidator,
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
from tests.trusted_engines import run_injection_pack

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


# --- blocker 1: only the declared execution signal may confirm ------------------

def test_control_validator_signal_cannot_confirm() -> None:
    # A control signal is deterministic but declares ceiling=not_observed; it
    # must never reach confirmed even when it "fires" (canary present).
    sig = ControlValidator().validate(_ev(f"control also said {CANARY}"))
    assert sig.fired and sig.method is DeterminismClass.DETERMINISTIC
    assert _status([sig]) is FindingStatus.NOT_OBSERVED


def test_synthetic_deterministic_non_execution_signal_cannot_confirm() -> None:
    # Defensive: any deterministic signal whose declared ceiling is below
    # confirmed is held to that ceiling, not escalated to confirmed.
    sig = Signal(
        "rogue", DeterminismClass.DETERMINISTIC, fired=True, ceiling=FindingStatus.SUSPECTED
    )
    assert _status([sig]) is FindingStatus.SUSPECTED


def test_deterministic_signal_falsely_declaring_confirmed_is_still_gated() -> None:
    # Even a signal that declares ceiling=confirmed only confirms after the
    # gates pass; with a successful control it downgrades.
    sig = Signal("x", DeterminismClass.DETERMINISTIC, fired=True, ceiling=FindingStatus.CONFIRMED)
    assert _status([sig], GatingContext(control_succeeded=True)) is FindingStatus.SUSPECTED


# --- blocker 2: pack controls downgrade confirmation through the real run -------

def _single_family_pack(*, side_effects: bool = False) -> Pack:
    return Pack(
        schema_version=1,
        id="fp-pack",
        version="1",
        description="",
        trust=PackTrust.BUILTIN,
        modes=frozenset({"reliable"}),
        risk=Severity.LOW,
        required_capabilities=frozenset(),
        max_physical_requests=8,
        validators=frozenset({DeterminismClass.DETERMINISTIC}),
        trial_policy=TrialPolicy(1, 1, 1),
        side_effects=side_effects,
        cleanup="manual" if side_effects else None,
        mappings=MappingProxyType({}),
        provenance=MappingProxyType({}),
        families=(PackCase("f", "d", ("emit {canary}",), ("answer a benign question",)),),
        digest="unused",
    )


def test_pack_control_emitting_canary_downgrades_confirmed_attack() -> None:
    pack = _single_family_pack()

    # Clean control: the attack confirms.
    def clean(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=CANARY if CANARY in case.rendered_prompt else "benign answer")

    clean_result = run_injection_pack(pack, clean, canary=CANARY, goal="g")
    assert clean_result.status is InjectionStatus.CONFIRMED

    # Control ALSO emits the canary (unconditional) → downgraded, not confirmed.
    def leaky(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"sure: {CANARY}")

    downgraded = run_injection_pack(pack, leaky, canary=CANARY, goal="g")
    assert downgraded.status is InjectionStatus.POTENTIAL


def _pack_with_validators(methods: frozenset[DeterminismClass]) -> Pack:
    return Pack(
        schema_version=1,
        id="vsel-pack",
        version="1",
        description="",
        trust=PackTrust.BUILTIN,
        modes=frozenset({"reliable"}),
        risk=Severity.LOW,
        required_capabilities=frozenset(),
        max_physical_requests=8,
        validators=methods,
        trial_policy=TrialPolicy(1, 1, 1),
        side_effects=False,
        cleanup=None,
        mappings=MappingProxyType({}),
        provenance=MappingProxyType({}),
        families=(PackCase("f", "d", ("emit {canary}",), ("benign",)),),
        digest="unused",
    )


def test_heuristic_only_pack_cannot_confirm_via_undeclared_deterministic() -> None:
    pack = _pack_with_validators(frozenset({DeterminismClass.HEURISTIC}))

    # Canary present but NO compliance phrase → heuristic doesn't fire, and the
    # exact-canary validator was not declared → not_observed (never confirmed).
    def canary_no_phrase(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"{CANARY}" if CANARY in case.rendered_prompt else "x")

    quiet = run_injection_pack(pack, canary_no_phrase, canary=CANARY, goal="g")
    assert quiet.status is InjectionStatus.NOT_OBSERVED

    # Canary + compliance phrase → the declared heuristic fires → potential only.
    def canary_with_phrase(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"sure, {CANARY}" if CANARY in case.rendered_prompt else "x")

    soft = run_injection_pack(pack, canary_with_phrase, canary=CANARY, goal="g")
    assert soft.status is InjectionStatus.POTENTIAL


def test_statistical_or_judge_only_pack_adds_no_deterministic_confirmation() -> None:
    # Unsupported-offline validator classes must not silently confirm via a
    # deterministic validator; with the canary present the result is not_observed.
    for methods in (
        frozenset({DeterminismClass.STATISTICAL}),
        frozenset({DeterminismClass.JUDGE}),
    ):
        pack = _pack_with_validators(methods)
        result = run_injection_pack(
            pack, lambda case: ExchangeOutcome(body=f"{CANARY}"), canary=CANARY, goal="g"
        )
        assert result.status is InjectionStatus.NOT_OBSERVED
