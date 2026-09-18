"""Architecture regressions for the single trusted accounting boundary."""

from __future__ import annotations

from collections.abc import Callable
from types import MappingProxyType

import pytest

from ai_scan.attacks import AttackContext, DirectInjectionPlugin, run_attack
from ai_scan.core.accounting import LedgerError, delta, snapshot
from ai_scan.core.models import DeterminismClass, PackTrust, Severity
from ai_scan.core.modes import resolve_policy
from ai_scan.fingerprint import ProbeExchange, run_fingerprint
from ai_scan.injection import (
    ExchangeOutcome,
    PayloadFamily,
    PayloadPack,
    generate_canary,
    run_injection,
    run_injection_pack,
)
from ai_scan.models import Probe
from ai_scan.orchestration import compile_plan, run_plan
from ai_scan.packs.schema import Pack, PackCase, TrialPolicy
from ai_scan.targets import normalize_target


class _Counter:
    def __init__(self) -> None:
        self.count = 0


def _pack() -> Pack:
    return Pack(
        schema_version=1,
        id="architecture-accounting",
        version="1",
        description="",
        trust=PackTrust.BUILTIN,
        modes=frozenset({"reliable"}),
        risk=Severity.LOW,
        required_capabilities=frozenset(),
        max_physical_requests=64,
        validators=frozenset({DeterminismClass.DETERMINISTIC}),
        trial_policy=TrialPolicy(1, 1, 1),
        side_effects=False,
        cleanup=None,
        mappings=MappingProxyType({}),
        provenance=MappingProxyType({}),
        families=(PackCase("family", "", ("emit {canary}",), ("benign",)),),
        digest="unused",
    )


@pytest.mark.parametrize("engine", ["fingerprint", "inject", "pack", "plugin", "plan"])
def test_public_active_engines_require_independent_trusted_counter(engine: str) -> None:
    calls = 0
    canary = generate_canary()

    def probe(_probe: Probe) -> ProbeExchange:
        nonlocal calls
        calls += 1
        return ProbeExchange("probe", "benign", {})

    def injection(_case: object) -> ExchangeOutcome:
        nonlocal calls
        calls += 1
        return ExchangeOutcome("benign")

    with pytest.raises(LedgerError, match="trusted physical request counter is required"):
        if engine == "fingerprint":
            run_fingerprint([Probe("probe", "prompt", "category")], probe)
        elif engine == "inject":
            run_injection(
                PayloadPack("1", "", [PayloadFamily("family", "", ["emit {canary}"])]),
                injection,
                canary=canary,
                goal="",
            )
        elif engine == "pack":
            run_injection_pack(_pack(), injection, canary=canary, goal="")
        elif engine == "plugin":
            run_attack(
                DirectInjectionPlugin(),
                injection,
                AttackContext(attack_canary=canary, hidden_canary=generate_canary()),
            )
        else:
            run_plan(
                compile_plan(normalize_target("http://127.0.0.1:8000/chat"), "reliable"),
                injection,
                canary=canary,
            )
    assert calls == 0


@pytest.mark.parametrize("forged", [True, 0, -1, 41, 10**100])
def test_public_engines_count_only_monotonic_ledger_deltas(forged: object) -> None:
    canary = generate_canary()
    counter = _Counter()

    def counted(result: Callable[[], object]) -> object:
        counter.count += 2
        return result()

    fingerprint = run_fingerprint(
        [Probe("probe", "prompt", "category")],
        lambda probe: counted(lambda: ProbeExchange(probe.id, "benign", {}, attempts=forged)),
        physical_request_count=counter,
    )
    assert fingerprint.request_count == 2

    injection = run_injection(
        PayloadPack("1", "", [PayloadFamily("family", "", ["emit {canary}"])]),
        lambda _case: counted(lambda: ExchangeOutcome("benign", attempts=forged)),
        canary=canary,
        goal="",
        physical_request_count=counter,
    )
    assert injection.request_count == 2

    pack = run_injection_pack(
        _pack(),
        lambda _case: counted(lambda: ExchangeOutcome("benign", attempts=forged)),
        canary=canary,
        goal="",
        physical_request_count=counter,
    )
    assert pack.request_count == 4
    assert {trial.attempts for finding in pack.findings for trial in finding.evidence} == {2}

    before = counter.count
    plugin = run_attack(
        DirectInjectionPlugin(),
        lambda _case: counted(lambda: ExchangeOutcome("benign", attempts=forged)),
        AttackContext(attack_canary=canary, hidden_canary=generate_canary()),
        physical_request_count=counter,
    )
    assert plugin.request_count == counter.count - before
    assert {trial.attempts for finding in plugin.findings for trial in finding.evidence} == {2}


def test_legacy_callable_counter_is_rejected_before_responder_call() -> None:
    calls = 0

    def responder(probe: Probe) -> ProbeExchange:
        nonlocal calls
        calls += 1
        return ProbeExchange(probe.id, "benign", {})

    with pytest.raises(LedgerError, match="RequestController-compatible"):
        run_fingerprint(
            [Probe("probe", "prompt", "category")],
            responder,
            physical_request_count=lambda: 0,
        )
    assert calls == 0


@pytest.mark.parametrize("value", [True, -1, 1 << 63])
def test_snapshot_rejects_noncanonical_or_unbounded_totals(value: object) -> None:
    counter = _Counter()
    counter.count = value  # type: ignore[assignment]
    with pytest.raises(LedgerError, match="malformed"):
        snapshot(counter)


def test_delta_rejects_incoherent_or_decreasing_per_kind_totals() -> None:
    class Ledger:
        def __init__(self) -> None:
            self.values = {"attack": 1, "control": 1, "total": 2}

        def totals(self) -> dict[str, int]:
            return dict(self.values)

    class Controller:
        def __init__(self) -> None:
            self.ledger = Ledger()

        @property
        def count(self) -> int:
            return self.ledger.values["total"]

    controller = Controller()
    before = snapshot(controller)
    controller.ledger.values = {"attack": 0, "control": 3, "total": 3}
    with pytest.raises(LedgerError, match="kinds are non-monotonic"):
        delta(before, controller)

    controller.ledger.values = {"attack": 2, "control": 3, "total": 6}
    with pytest.raises(LedgerError, match="incoherent"):
        snapshot(controller)


def test_pack_engine_rejects_trusted_delta_beyond_declared_budget() -> None:
    counter = _Counter()

    def responder(_case: object) -> ExchangeOutcome:
        counter.count += _pack().max_physical_requests + 1
        return ExchangeOutcome("benign")

    with pytest.raises(LedgerError, match="remaining budget"):
        run_injection_pack(
            _pack(),
            responder,
            canary=generate_canary(),
            goal="",
            physical_request_count=counter,
        )


def test_plugin_engine_rejects_trusted_delta_beyond_mode_budget() -> None:
    counter = _Counter()
    budget = resolve_policy("reliable").max_physical_requests

    def responder(_case: object) -> ExchangeOutcome:
        counter.count += budget + 1
        return ExchangeOutcome("benign")

    with pytest.raises(LedgerError, match="remaining budget"):
        run_attack(
            DirectInjectionPlugin(),
            responder,
            AttackContext(attack_canary=generate_canary(), hidden_canary=generate_canary()),
            physical_request_count=counter,
        )


@pytest.mark.parametrize("engine", ["fingerprint", "inject", "pack", "plugin"])
def test_public_engines_validate_trusted_delta_after_interrupt(engine: str) -> None:
    counter = _Counter()
    canary = generate_canary()

    def interrupted(_value: object) -> object:
        counter.count = 1 << 63
        raise KeyboardInterrupt

    with pytest.raises(LedgerError, match="malformed"):
        if engine == "fingerprint":
            run_fingerprint(
                [Probe("probe", "prompt", "category")],
                interrupted,  # type: ignore[arg-type]
                physical_request_count=counter,
            )
        elif engine == "inject":
            run_injection(
                PayloadPack("1", "", [PayloadFamily("family", "", ["emit {canary}"])]),
                interrupted,  # type: ignore[arg-type]
                canary=canary,
                goal="",
                physical_request_count=counter,
            )
        elif engine == "pack":
            run_injection_pack(
                _pack(),
                interrupted,  # type: ignore[arg-type]
                canary=canary,
                goal="",
                physical_request_count=counter,
            )
        else:
            run_attack(
                DirectInjectionPlugin(),
                interrupted,  # type: ignore[arg-type]
                AttackContext(attack_canary=canary, hidden_canary=generate_canary()),
                physical_request_count=counter,
            )


def test_plugin_validates_trusted_delta_before_rejecting_responder_shape() -> None:
    counter = _Counter()

    def malformed(_case: object) -> object:
        counter.count = 1 << 63
        return object()

    with pytest.raises(LedgerError, match="malformed"):
        run_attack(
            DirectInjectionPlugin(),
            malformed,  # type: ignore[arg-type]
            AttackContext(attack_canary=generate_canary(), hidden_canary=generate_canary()),
            physical_request_count=counter,
        )
