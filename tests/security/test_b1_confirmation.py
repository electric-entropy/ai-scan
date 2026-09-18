"""Phase B1 — Reliable trial/control confirmation semantics (through the runner).

Confirmation is trustworthy only when the resolved plan policy (Reliable 3/2/2)
is enforced with real repeated trials and a matched clean control. These
regressions exercise the actual ``run_plan`` path, not a synthetic shim.
"""

from __future__ import annotations

import re

from ai_scan.core.models import DeterminismClass, FindingStatus
from ai_scan.injection import ExchangeOutcome, InjectionCase
from ai_scan.orchestration import compile_plan
from ai_scan.targets import normalize_target
from ai_scan.validation import GatingContext, classify
from ai_scan.validation.base import Signal
from tests.trusted_engines import run_plan

_CANARY = "AISCAN-B1CANARY"


def _plan():
    return compile_plan(normalize_target("http://127.0.0.1:9/chat"), "reliable")


def _is_attack(case: InjectionCase) -> bool:
    return "{canary}" in case.template


def _canary_of(case: InjectionCase) -> str:
    match = re.search(r"AISCAN-\S+", case.rendered_prompt)
    return match.group(0) if match else _CANARY


def _statuses(result) -> set[str]:
    return {f.status.value for f in result.findings}


def test_no_usable_control_cannot_confirm() -> None:
    # Attacks execute the canary every trial, but every control is unusable →
    # no matched clean control → confirmation is impossible (never 'confirmed').
    def responder(case: InjectionCase) -> ExchangeOutcome:
        if _is_attack(case):
            return ExchangeOutcome(_canary_of(case))
        return ExchangeOutcome("x", transport_ok=False)

    result = run_plan(_plan(), responder, canary=_CANARY, goal="")
    assert result.findings
    assert "confirmed" not in _statuses(result)


def test_control_emission_caps_at_suspected() -> None:
    # A control that emits the canary poisons the baseline → 'suspected', never confirmed.
    def responder(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(_canary_of(case))  # everything emits the canary

    result = run_plan(_plan(), responder, canary=_CANARY, goal="")
    assert "confirmed" not in _statuses(result)
    assert "suspected" in _statuses(result)


def test_clean_control_and_repeatability_confirms() -> None:
    # The GREEN path: clean usable controls + every attack trial executes → confirmed.
    def responder(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(_canary_of(case) if _is_attack(case) else "benign")

    result = run_plan(_plan(), responder, canary=_CANARY, goal="")
    assert "confirmed" in _statuses(result)


def test_insufficient_repeatability_cannot_confirm() -> None:
    # Clean controls, but each attack executes on only ONE of its trials →
    # successes (1) below the Reliable minimum (2) → cannot confirm.
    executed: dict[str, int] = {}

    def responder(case: InjectionCase) -> ExchangeOutcome:
        if not _is_attack(case):
            return ExchangeOutcome("benign")
        seen = executed.get(case.rendered_prompt, 0)
        executed[case.rendered_prompt] = seen + 1
        return ExchangeOutcome(_canary_of(case) if seen == 0 else "no execution this trial")

    result = run_plan(_plan(), responder, canary=_CANARY, goal="")
    assert "confirmed" not in _statuses(result)


def test_arbitrary_deterministic_signal_cannot_confirm() -> None:
    # Only the exact canary-execution signal (declared ceiling 'confirmed') may
    # enter the gated path; any other deterministic signal stays capped.
    signal = Signal("some_det_metric", DeterminismClass.DETERMINISTIC, True, FindingStatus.LIKELY)
    context = GatingContext(attack_trials=3, successes=3, min_attack_trials=3, min_successes=2)
    assert classify([signal], context).status is not FindingStatus.CONFIRMED
