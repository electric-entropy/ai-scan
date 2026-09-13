"""Direct-injection plugin: vulnerable confirms; resistant/reflective do not."""

from __future__ import annotations

import pytest

from ai_scan.attacks import AttackContext, DirectInjectionPlugin, run_attack
from ai_scan.attacks.base import AttackCase, AttackError
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from ai_scan.packs.schema import TrialPolicy
from tests.fixtures.apps import reflective_app, resistant_app, vulnerable_app

AC = "AISCAN-ATTACK0001"
HC = "AISCAN-HIDDEN0001"


def _ctx(mode: str = "reliable") -> AttackContext:
    return AttackContext(attack_canary=AC, hidden_canary=HC, mode=mode)


def test_vulnerable_fixture_confirms_deterministically_across_seeds() -> None:
    plugin = DirectInjectionPlugin()
    app = vulnerable_app(attack_canary=AC, hidden_canary=HC)
    results = [run_attack(plugin, app, _ctx()).confirmed for _ in range(5)]
    assert results == [True] * 5  # deterministic, repeatable confirmation


@pytest.mark.parametrize("factory", [resistant_app, reflective_app])
def test_resistant_and_reflective_produce_zero_confirmed(factory) -> None:
    app = factory(attack_canary=AC, hidden_canary=HC)
    result = run_attack(DirectInjectionPlugin(), app, _ctx())
    assert not result.confirmed
    assert all(f.status is not InjectionStatus.CONFIRMED for f in result.findings)


def test_kitchen_sink_adds_more_cases_but_still_confirms() -> None:
    plugin = DirectInjectionPlugin()
    app = vulnerable_app(attack_canary=AC, hidden_canary=HC)
    reliable = run_attack(plugin, app, _ctx("reliable"))
    kitchen = run_attack(plugin, app, _ctx("kitchen-sink"))
    assert len(kitchen.findings) > len(reliable.findings)  # broader seeded leads
    assert kitchen.confirmed


def test_matched_control_blocks_confirmation() -> None:
    # An app that emits the attack canary even for benign controls is a false
    # positive — confirmation must be blocked (downgraded to potential).
    def leaky(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"token: {AC}")

    result = run_attack(DirectInjectionPlugin(), leaky, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


def test_malformed_plugin_fails_closed_before_any_request() -> None:
    class BadPlugin:
        id = "bad"
        validators = frozenset()  # empty → invalid
        trial_policy = TrialPolicy(1, 1, 1)
        side_effects = False

        def success_token(self, ctx: AttackContext) -> str:
            return ctx.attack_canary

        def build_cases(self, ctx: AttackContext) -> list[AttackCase]:
            return []

    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("responder must not be called for a malformed plugin")

    with pytest.raises(AttackError):
        run_attack(BadPlugin(), must_not_call, _ctx())


def test_plugin_build_exception_is_scrubbed() -> None:
    secret = "ghp_abcdefghijklmnopqrstuvwxyz0123"

    class ExplodingPlugin:
        id = "boom"
        validators = frozenset(DirectInjectionPlugin().validators)
        trial_policy = TrialPolicy(1, 1, 1)
        side_effects = False

        def success_token(self, ctx: AttackContext) -> str:
            return ctx.attack_canary

        def build_cases(self, ctx: AttackContext) -> list[AttackCase]:
            raise RuntimeError(f"leak {secret}")

    with pytest.raises(AttackError) as exc:
        run_attack(ExplodingPlugin(), lambda c: ExchangeOutcome(body="x"), _ctx())
    assert secret not in str(exc.value)
    assert "REDACTED" in str(exc.value)


_SECRET = "ghp_abcdefghijklmnopqrstuvwxyz0123"


def _never(_case: AttackCase) -> ExchangeOutcome:
    raise AssertionError("responder must not be called before validation passes")


def test_success_token_exception_is_scrubbed() -> None:
    class TokenBoom:
        id = "tok"
        validators = frozenset(DirectInjectionPlugin().validators)
        trial_policy = TrialPolicy(1, 1, 1)
        side_effects = False

        def success_token(self, ctx: AttackContext) -> str:
            raise RuntimeError(f"leak {_SECRET}")

        def build_cases(self, ctx: AttackContext) -> list[AttackCase]:
            return []

    with pytest.raises(AttackError) as exc:
        run_attack(TokenBoom(), _never, _ctx())
    assert _SECRET not in str(exc.value)
    assert "REDACTED" in str(exc.value)


def test_invalid_case_kind_value_is_scrubbed() -> None:
    class BadKind:
        id = "bk"
        validators = frozenset(DirectInjectionPlugin().validators)
        trial_policy = TrialPolicy(1, 1, 1)
        side_effects = False

        def success_token(self, ctx: AttackContext) -> str:
            return ctx.attack_canary

        def build_cases(self, ctx: AttackContext) -> list[AttackCase]:
            return [AttackCase(family="f", kind=_SECRET, prompt="p")]

    with pytest.raises(AttackError) as exc:
        run_attack(BadKind(), _never, _ctx())
    assert _SECRET not in str(exc.value)
    assert "REDACTED" in str(exc.value)


def test_non_attackcase_item_fails_before_responder() -> None:
    class BadItems:
        id = "bi"
        validators = frozenset(DirectInjectionPlugin().validators)
        trial_policy = TrialPolicy(1, 1, 1)
        side_effects = False

        def success_token(self, ctx: AttackContext) -> str:
            return ctx.attack_canary

        def build_cases(self, ctx: AttackContext):  # type: ignore[no-untyped-def]
            return [object()]

    with pytest.raises(AttackError):
        run_attack(BadItems(), _never, _ctx())
