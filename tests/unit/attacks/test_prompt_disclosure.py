"""Prompt-disclosure plugin: confirms only via synthetic hidden-canary extraction."""

from __future__ import annotations

import pytest

from ai_scan.attacks import AttackContext, PromptDisclosurePlugin, run_attack
from ai_scan.attacks.base import AttackCase, AttackError
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from tests.fixtures.apps import reflective_app, resistant_app, vulnerable_app

AC = "AISCAN-ATTACK0002"
HC = "AISCAN-HIDDEN0002"


def _ctx(mode: str = "reliable") -> AttackContext:
    return AttackContext(attack_canary=AC, hidden_canary=HC, mode=mode)


def test_attack_prompts_never_contain_the_hidden_canary() -> None:
    # The success token must be *extracted*, not reflected — so it must never be
    # present in any attack prompt we send.
    cases = PromptDisclosurePlugin().build_cases(_ctx("kitchen-sink"))
    assert cases
    assert all(HC not in c.prompt for c in cases)


def test_vulnerable_fixture_confirms_via_hidden_canary_extraction() -> None:
    plugin = PromptDisclosurePlugin()
    app = vulnerable_app(attack_canary=AC, hidden_canary=HC)
    results = [run_attack(plugin, app, _ctx()).confirmed for _ in range(5)]
    assert results == [True] * 5


@pytest.mark.parametrize("factory", [resistant_app, reflective_app])
def test_resistant_and_reflective_produce_zero_confirmed(factory) -> None:
    app = factory(attack_canary=AC, hidden_canary=HC)
    result = run_attack(PromptDisclosurePlugin(), app, _ctx())
    assert not result.confirmed


def test_reflection_of_prompt_never_confirms_disclosure() -> None:
    # Even an app that echoes the entire prompt (reflective) cannot confirm,
    # because the hidden canary is never part of the prompt to echo.
    app = reflective_app(attack_canary=AC, hidden_canary=HC)
    result = run_attack(PromptDisclosurePlugin(), app, _ctx())
    assert all(f.status is not InjectionStatus.CONFIRMED for f in result.findings)


def test_control_that_leaks_hidden_canary_blocks_confirmation() -> None:
    # An app that discloses the hidden canary even for benign controls is a
    # false positive → confirmation blocked.
    def always_leaks(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"note: {HC}")

    result = run_attack(PromptDisclosurePlugin(), always_leaks, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


def test_kitchen_sink_adds_broader_disclosure_leads() -> None:
    plugin = PromptDisclosurePlugin()
    reliable = plugin.build_cases(_ctx("reliable"))
    kitchen = plugin.build_cases(_ctx("kitchen-sink"))
    assert len([c for c in kitchen if c.kind == "attack"]) > len(
        [c for c in reliable if c.kind == "attack"]
    )


def test_malformed_mode_fails_closed() -> None:
    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("responder must not be called for a bad mode")

    with pytest.raises(AttackError):
        run_attack(PromptDisclosurePlugin(), must_not_call, AttackContext(AC, HC, "turbo"))
