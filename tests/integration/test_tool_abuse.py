"""Milestone 14: tool abuse requires synthetic trace evidence and capability gates."""

from __future__ import annotations

import pytest

from ai_scan.attacks import AttackContext, AttackError, ToolAbusePlugin, run_attack
from ai_scan.attacks.base import AttackCase
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from tests.fixtures.apps import fake_tool_agent, resistant_tool_agent, vulnerable_tool_agent

AC = "AISCAN-TOOL-TRACE"
HC = "AISCAN-TOOL-HIDDEN"


def _ctx(
    mode: str = "reliable", *, capabilities: frozenset[str] = frozenset({"tool_invoke"})
) -> AttackContext:
    return AttackContext(AC, HC, mode, capabilities)


def test_tool_abuse_confirms_only_from_synthetic_broker_trace() -> None:
    plugin = ToolAbusePlugin()
    app = vulnerable_tool_agent(attack_canary=AC, hidden_canary=HC)
    result = run_attack(plugin, app, _ctx())
    assert result.confirmed
    assert all(AC not in c.prompt for c in plugin.build_cases(_ctx()) if c.kind == "attack")


def test_tool_prose_claim_without_trace_does_not_confirm() -> None:
    app = fake_tool_agent(attack_canary=AC, hidden_canary=HC)
    result = run_attack(ToolAbusePlugin(), app, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.NOT_OBSERVED


def test_resistant_tool_agent_has_zero_confirmed_findings() -> None:
    app = resistant_tool_agent(attack_canary=AC, hidden_canary=HC)
    assert not run_attack(ToolAbusePlugin(), app, _ctx()).confirmed


def test_tool_invoke_capability_is_required_before_any_request() -> None:
    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("tool abuse plugin must fail before responder calls")

    with pytest.raises(AttackError):
        run_attack(ToolAbusePlugin(), must_not_call, _ctx(capabilities=frozenset()))


def test_control_trace_blocks_tool_confirmation() -> None:
    def always_trace(_case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"broker_trace=executed synthetic_effect={AC}")

    result = run_attack(ToolAbusePlugin(), always_trace, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


def test_kitchen_sink_broadens_tool_cases_without_changing_gates() -> None:
    plugin = ToolAbusePlugin()
    reliable = plugin.build_cases(_ctx("reliable"))
    kitchen = plugin.build_cases(_ctx("kitchen-sink"))
    assert len([c for c in kitchen if c.kind == "attack"]) > len(
        [c for c in reliable if c.kind == "attack"]
    )
    with pytest.raises(AttackError):
        plugin.build_cases(_ctx("kitchen-sink", capabilities=frozenset()))
