"""Milestone 13: RAG and indirect-injection plugins stay synthetic and gated."""

from __future__ import annotations

import pytest

from ai_scan.attacks import (
    AttackContext,
    AttackError,
    IndirectInjectionPlugin,
    RagIsolationPlugin,
    run_attack,
)
from ai_scan.attacks.base import AttackCase
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from tests.fixtures.apps import resistant_rag_app, vulnerable_rag_app

AC = "AISCAN-RAG-ATTACK"
HC = "AISCAN-RAG-HIDDEN"


def _ctx(
    mode: str = "reliable",
    *,
    capabilities: frozenset[str] = frozenset({"rag_upload", "cross_identity"}),
    identities: tuple[str, ...] = ("alpha", "beta"),
) -> AttackContext:
    return AttackContext(AC, HC, mode, capabilities, identities)


def test_indirect_injection_confirms_only_from_synthetic_retrieved_document() -> None:
    plugin = IndirectInjectionPlugin()
    app = vulnerable_rag_app(attack_canary=AC, hidden_canary=HC)
    result = run_attack(plugin, app, _ctx())
    assert result.confirmed
    assert all(AC not in c.prompt for c in plugin.build_cases(_ctx()) if c.kind == "attack")


def test_resistant_rag_fixture_has_zero_confirmed_findings() -> None:
    app = resistant_rag_app(attack_canary=AC, hidden_canary=HC)
    assert not run_attack(IndirectInjectionPlugin(), app, _ctx()).confirmed
    assert not run_attack(RagIsolationPlugin(), app, _ctx()).confirmed


def test_rag_cross_tenant_confirms_only_with_declared_identities() -> None:
    app = vulnerable_rag_app(attack_canary=AC, hidden_canary=HC)
    result = run_attack(RagIsolationPlugin(), app, _ctx())
    assert result.confirmed
    cases = RagIsolationPlugin().build_cases(_ctx())
    assert all(HC not in c.prompt for c in cases if c.kind == "attack")


@pytest.mark.parametrize(
    ("plugin", "ctx"),
    [
        (IndirectInjectionPlugin(), _ctx(capabilities=frozenset())),
        (RagIsolationPlugin(), _ctx(capabilities=frozenset({"rag_upload"}))),
        (RagIsolationPlugin(), _ctx(identities=("alpha",))),
    ],
)
def test_missing_capabilities_or_identities_fail_before_any_request(plugin, ctx) -> None:
    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("RAG plugins must fail before responder calls")

    with pytest.raises(AttackError):
        run_attack(plugin, must_not_call, ctx)


def test_control_leak_blocks_rag_confirmation() -> None:
    def always_leaks(_case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"leak {HC}")

    result = run_attack(RagIsolationPlugin(), always_leaks, _ctx())
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


def test_kitchen_sink_broadens_rag_cases_without_changing_gates() -> None:
    plugin = RagIsolationPlugin()
    reliable = plugin.build_cases(_ctx("reliable"))
    kitchen = plugin.build_cases(_ctx("kitchen-sink"))
    assert len([c for c in kitchen if c.kind == "attack"]) > len(
        [c for c in reliable if c.kind == "attack"]
    )
