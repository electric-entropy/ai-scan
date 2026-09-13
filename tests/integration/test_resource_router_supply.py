"""Milestone 17: bounded resource, router consistency, and supply-chain checks."""

from __future__ import annotations

import pytest

from ai_scan.attacks import (
    AttackContext,
    AttackError,
    ResourceAmplificationPlugin,
    RouterConsistencyPlugin,
    SupplyChainPlugin,
    run_attack,
)
from ai_scan.attacks.base import AttackCase
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from tests.fixtures.apps import (
    resistant_resource_router_supply_app,
    vulnerable_resource_router_supply_app,
)

AC = "AISCAN-BUDGET-STOP"
HC = "AISCAN-POSTURE-EVIDENCE"


def _ctx(
    mode: str = "reliable", *, capabilities: frozenset[str] = frozenset()
) -> AttackContext:
    return AttackContext(AC, HC, mode, capabilities)


@pytest.mark.parametrize(
    "plugin_cls", [ResourceAmplificationPlugin, RouterConsistencyPlugin, SupplyChainPlugin]
)
def test_vulnerable_fixture_confirms_only_synthetic_bounded_evidence(plugin_cls) -> None:
    result = run_attack(
        plugin_cls(),
        vulnerable_resource_router_supply_app(attack_canary=AC, hidden_canary=HC),
        _ctx(),
    )
    assert result.confirmed


@pytest.mark.parametrize(
    "plugin_cls", [ResourceAmplificationPlugin, RouterConsistencyPlugin, SupplyChainPlugin]
)
def test_resistant_fixture_has_zero_confirmed_findings(plugin_cls) -> None:
    result = run_attack(
        plugin_cls(),
        resistant_resource_router_supply_app(attack_canary=AC, hidden_canary=HC),
        _ctx(),
    )
    assert not result.confirmed
    assert result.status is InjectionStatus.NOT_OBSERVED


@pytest.mark.parametrize(
    "plugin_cls", [ResourceAmplificationPlugin, RouterConsistencyPlugin, SupplyChainPlugin]
)
def test_control_evidence_blocks_confirmation(plugin_cls) -> None:
    token = AC if plugin_cls is ResourceAmplificationPlugin else HC

    def always_evidence(_case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"synthetic evidence {token}")

    result = run_attack(plugin_cls(), always_evidence, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


def test_resource_kitchen_sink_requires_separate_stress_capability_before_request() -> None:
    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("resource stress must fail before responder calls")

    with pytest.raises(AttackError):
        run_attack(ResourceAmplificationPlugin(), must_not_call, _ctx("kitchen-sink"))


def test_kitchen_sink_broadens_m17_cases_without_changing_confirmation() -> None:
    for plugin in (ResourceAmplificationPlugin(), RouterConsistencyPlugin(), SupplyChainPlugin()):
        reliable_ctx = _ctx("reliable")
        kitchen_ctx = _ctx("kitchen-sink", capabilities=frozenset({"resource_stress"}))
        reliable = plugin.build_cases(reliable_ctx)
        kitchen = plugin.build_cases(kitchen_ctx)
        assert len([c for c in kitchen if c.kind == "attack"]) > len(
            [c for c in reliable if c.kind == "attack"]
        )


def test_resource_prompts_are_bounded_and_never_claim_actual_dos() -> None:
    cases = ResourceAmplificationPlugin().build_cases(
        _ctx("kitchen-sink", capabilities=frozenset({"resource_stress"}))
    )
    attack_prompts = [c.prompt.lower() for c in cases if c.kind == "attack"]
    assert attack_prompts
    assert all("hard limit" in prompt for prompt in attack_prompts)
    assert all(
        "denial of service" not in prompt and "dos" not in prompt for prompt in attack_prompts
    )


def test_router_and_supply_chain_prompts_are_advisory_or_passive() -> None:
    router = RouterConsistencyPlugin().build_cases(_ctx("kitchen-sink"))
    supply = SupplyChainPlugin().build_cases(_ctx("kitchen-sink"))
    assert all("self-ident" not in c.prompt.lower() for c in router if c.kind == "attack")
    assert all("inspect" in c.prompt.lower() for c in supply if c.kind == "attack")
