"""Milestone 15: session, memory, and multi-agent isolation use identity-bound canaries."""

from __future__ import annotations

import pytest

from ai_scan.attacks import (
    AttackContext,
    AttackError,
    IsolationPlugin,
    MemoryPlugin,
    MultiAgentPlugin,
)
from ai_scan.attacks.base import AttackCase
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from tests.fixtures.apps import (
    resistant_isolation_app,
    vulnerable_isolation_app,
)
from tests.trusted_engines import run_attack

AC = "AISCAN-SESSION-ATTACK"
HC = "AISCAN-IDENTITY-BOUND-HIDDEN"


def _ctx(
    mode: str = "reliable",
    *,
    capabilities: frozenset[str] = frozenset({"cross_identity", "state_write", "tool_invoke"}),
    identities: tuple[str, ...] = ("alpha", "beta"),
) -> AttackContext:
    return AttackContext(AC, HC, mode, capabilities, identities)


@pytest.mark.parametrize("plugin_cls", [IsolationPlugin, MemoryPlugin, MultiAgentPlugin])
def test_vulnerable_fixture_confirms_from_identity_bound_evidence(plugin_cls) -> None:
    app = vulnerable_isolation_app(attack_canary=AC, hidden_canary=HC)
    result = run_attack(plugin_cls(), app, _ctx())
    assert result.confirmed
    cases = plugin_cls().build_cases(_ctx())
    assert all(HC not in c.prompt for c in cases if c.kind == "attack")
    assert all("alpha" in c.prompt and "beta" in c.prompt for c in cases if c.kind == "attack")


@pytest.mark.parametrize("plugin_cls", [IsolationPlugin, MemoryPlugin, MultiAgentPlugin])
def test_cases_bind_evidence_chain_to_declared_identities(plugin_cls) -> None:
    ctx = _ctx("kitchen-sink", identities=("writer-id", "reader-id"))
    cases = plugin_cls().build_cases(ctx)
    attacks = [c for c in cases if c.kind == "attack"]
    controls = [c for c in cases if c.kind == "control"]
    assert attacks
    assert controls
    assert all("writer-id" in c.prompt and "reader-id" in c.prompt for c in attacks)
    assert any("writer-id" in c.prompt and "reader-id" not in c.prompt for c in controls)
    assert any("reader-id" in c.prompt and "writer-id" not in c.prompt for c in controls)


@pytest.mark.parametrize("plugin_cls", [IsolationPlugin, MemoryPlugin, MultiAgentPlugin])
def test_resistant_fixture_has_zero_confirmed_findings(plugin_cls) -> None:
    app = resistant_isolation_app(attack_canary=AC, hidden_canary=HC)
    result = run_attack(plugin_cls(), app, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.NOT_OBSERVED


@pytest.mark.parametrize(
    ("plugin_cls", "ctx"),
    [
        (IsolationPlugin, _ctx(capabilities=frozenset({"state_write", "tool_invoke"}))),
        (IsolationPlugin, _ctx(identities=("alpha",))),
        (MemoryPlugin, _ctx(capabilities=frozenset({"cross_identity", "tool_invoke"}))),
        (MemoryPlugin, _ctx(identities=("alpha",))),
        (MultiAgentPlugin, _ctx(capabilities=frozenset({"cross_identity", "state_write"}))),
        (MultiAgentPlugin, _ctx(identities=("alpha",))),
    ],
)
def test_missing_capabilities_or_identities_fail_before_any_request(plugin_cls, ctx) -> None:
    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("M15 plugins must fail before responder calls")

    with pytest.raises(AttackError):
        run_attack(plugin_cls(), must_not_call, ctx)


@pytest.mark.parametrize("plugin_cls", [IsolationPlugin, MemoryPlugin, MultiAgentPlugin])
def test_control_leak_blocks_confirmation(plugin_cls) -> None:
    def always_leaks(_case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"identity-bound trace leaked {HC}")

    result = run_attack(plugin_cls(), always_leaks, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


@pytest.mark.parametrize("plugin_cls", [IsolationPlugin, MemoryPlugin, MultiAgentPlugin])
def test_kitchen_sink_broadens_cases_without_changing_gates(plugin_cls) -> None:
    plugin = plugin_cls()
    reliable = plugin.build_cases(_ctx("reliable"))
    kitchen = plugin.build_cases(_ctx("kitchen-sink"))
    assert len([c for c in kitchen if c.kind == "attack"]) > len(
        [c for c in reliable if c.kind == "attack"]
    )
    with pytest.raises(AttackError):
        plugin.build_cases(_ctx("kitchen-sink", capabilities=frozenset()))
