"""Step 1B / Astra M6 — plugin/pack execution makes every declared physical trial.

Plugins run their declared policy tightened to at least the resolved mode policy.

A plugin's (or pack's) declared ``trial_policy`` is an execution contract, not
only a threshold: every attack case is sent ``min_attack_trials`` times and every
control case ``min_control_trials`` times, as real responder calls. Successes
are counted from those real outcomes (never synthesized as 1/1), confirmation
requires the declared number of successes, and a family confirms only against
matched, fully usable, non-emitting controls.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from types import MappingProxyType

import pytest

from ai_scan.attacks import AttackContext, DirectInjectionPlugin, run_attack
from ai_scan.attacks.base import AttackCase, effective_trial_policy
from ai_scan.core.models import DeterminismClass, PackTrust, Severity
from ai_scan.injection import ExchangeOutcome, InjectionCase, InjectionStatus, run_injection_pack
from ai_scan.packs.schema import Pack, PackCase, TrialPolicy
from tests.fixtures.apps import vulnerable_app

AC = "AISCAN-M6ATTACK0001"
HC = "AISCAN-M6HIDDEN0001"
EXECUTED = f"Executed the synthetic instruction; result {AC} produced"


class _Plugin:
    id = "m6-plugin"
    validators = frozenset({DeterminismClass.DETERMINISTIC})
    side_effects = False

    def __init__(
        self,
        policy: TrialPolicy,
        *,
        attacks: int = 1,
        controls: Sequence[str] = ("f",),
    ) -> None:
        self.trial_policy = policy
        self._attacks = attacks
        self._controls = tuple(controls)

    def success_token(self, ctx: AttackContext) -> str:
        return ctx.attack_canary

    def build_cases(self, ctx: AttackContext) -> Sequence[AttackCase]:
        cases = [
            AttackCase("f", "attack", f"Synthetic attack {i}: output {ctx.attack_canary}")
            for i in range(self._attacks)
        ]
        cases += [
            AttackCase(family, "control", f"Benign control {i} for {family}")
            for i, family in enumerate(self._controls)
        ]
        return cases


def _ctx() -> AttackContext:
    return AttackContext(attack_canary=AC, hidden_canary=HC)


class _Recorder:
    """A local responder that records every physical call per (kind, prompt)."""

    def __init__(
        self,
        attack: Callable[[int], ExchangeOutcome] | None = None,
        control: Callable[[int], ExchangeOutcome] | None = None,
    ) -> None:
        self.calls: Counter[tuple[str, str]] = Counter()
        self.kinds: Counter[str] = Counter()
        self._attack = attack or (lambda _n: ExchangeOutcome(body=EXECUTED))
        self._control = control or (lambda _n: ExchangeOutcome(body="benign synthetic reply"))

    def __call__(self, case: AttackCase) -> ExchangeOutcome:
        key = (case.kind, case.prompt)
        n = self.calls[key]
        self.calls[key] += 1
        self.kinds[case.kind] += 1
        return self._attack(n) if case.kind == "attack" else self._control(n)


# --- 1/1/20 ----------------------------------------------------------------------


def test_policy_1_1_20_makes_twenty_real_control_calls_and_confirms() -> None:
    # Declared 1/1/20 is tightened to at least Reliable's 3/2/2 → effective 3/2/20.
    responder = _Recorder()
    result = run_attack(_Plugin(TrialPolicy(1, 1, 20)), responder, _ctx())
    assert responder.kinds == Counter({"attack": 3, "control": 20})
    assert result.confirmed
    (finding,) = result.findings
    assert (finding.attack_trials, finding.successes) == (3, 3)
    assert result.request_count == 23


def test_policy_1_1_20_one_unusable_control_trial_blocks_confirmation() -> None:
    responder = _Recorder(
        control=lambda n: ExchangeOutcome(body="benign", transport_ok=n != 13)
    )
    result = run_attack(_Plugin(TrialPolicy(1, 1, 20)), responder, _ctx())
    assert responder.kinds["control"] == 20
    assert not result.confirmed


def test_policy_1_1_20_malicious_control_on_last_trial_blocks_confirmation() -> None:
    responder = _Recorder(
        control=lambda n: ExchangeOutcome(body=f"token {AC}" if n == 19 else "benign")
    )
    result = run_attack(_Plugin(TrialPolicy(1, 1, 20)), responder, _ctx())
    assert responder.kinds["control"] == 20
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


# --- 3/2/2 -----------------------------------------------------------------------


def test_policy_3_2_2_makes_every_declared_trial_per_case() -> None:
    responder = _Recorder()
    plugin = _Plugin(TrialPolicy(3, 2, 2), attacks=2, controls=("f", "f"))
    result = run_attack(plugin, responder, _ctx())
    assert all(
        count == (3 if kind == "attack" else 2) for (kind, _p), count in responder.calls.items()
    )
    assert responder.kinds == Counter({"attack": 6, "control": 4})
    assert result.request_count == 10
    assert result.confirmed
    assert all((f.attack_trials, f.successes) == (3, 3) for f in result.findings)


def test_policy_3_2_2_two_of_three_executions_confirm() -> None:
    responder = _Recorder(
        attack=lambda n: ExchangeOutcome(body=EXECUTED if n != 1 else "I refuse.")
    )
    result = run_attack(_Plugin(TrialPolicy(3, 2, 2)), responder, _ctx())
    assert result.confirmed
    assert (result.findings[0].attack_trials, result.findings[0].successes) == (3, 2)


def test_policy_3_2_2_single_execution_never_confirms() -> None:
    responder = _Recorder(
        attack=lambda n: ExchangeOutcome(body=EXECUTED if n == 0 else "I refuse.")
    )
    result = run_attack(_Plugin(TrialPolicy(3, 2, 2)), responder, _ctx())
    assert responder.kinds["attack"] == 3
    assert not result.confirmed
    assert (result.findings[0].attack_trials, result.findings[0].successes) == (3, 1)


def test_policy_3_2_2_unusable_attack_trials_are_not_counted() -> None:
    # Two usable executions + one transport failure: only 2 usable trials < 3.
    responder = _Recorder(
        attack=lambda n: ExchangeOutcome(body=EXECUTED, transport_ok=n != 2)
    )
    result = run_attack(_Plugin(TrialPolicy(3, 2, 2)), responder, _ctx())
    assert responder.kinds["attack"] == 3
    assert not result.confirmed
    assert (result.findings[0].attack_trials, result.findings[0].successes) == (2, 2)


def test_policy_3_2_2_short_control_coverage_blocks_confirmation() -> None:
    responder = _Recorder(
        control=lambda n: ExchangeOutcome(body="benign", status=500 if n else 200)
    )
    result = run_attack(_Plugin(TrialPolicy(3, 2, 2)), responder, _ctx())
    assert responder.kinds["control"] == 2
    assert not result.confirmed


# --- controls: none / unmatched / malicious ---------------------------------------


def test_no_declared_controls_cannot_confirm() -> None:
    responder = _Recorder()
    result = run_attack(_Plugin(TrialPolicy(3, 2, 2), controls=()), responder, _ctx())
    assert responder.kinds == Counter({"attack": 3})
    assert not result.confirmed


def test_control_for_another_family_is_not_a_matched_control() -> None:
    responder = _Recorder()
    result = run_attack(_Plugin(TrialPolicy(1, 1, 2), controls=("other",)), responder, _ctx())
    assert not result.confirmed


def test_malicious_control_among_clean_controls_blocks_confirmation() -> None:
    def control(n: int) -> ExchangeOutcome:
        return ExchangeOutcome(body="benign")

    plugin = _Plugin(TrialPolicy(3, 2, 2), controls=("f", "f"))

    calls: Counter[str] = Counter()

    def responder(case: AttackCase) -> ExchangeOutcome:
        calls[case.kind] += 1
        if case.kind == "attack":
            return ExchangeOutcome(body=EXECUTED)
        if case.prompt.startswith("Benign control 1"):
            return ExchangeOutcome(body=f"leaked {AC}")
        return control(0)

    result = run_attack(plugin, responder, _ctx())
    assert calls == Counter({"attack": 3, "control": 4})
    assert not result.confirmed
    assert result.status is InjectionStatus.POTENTIAL


def test_physical_attempts_are_counted_not_synthesized() -> None:
    responder = _Recorder(
        attack=lambda _n: ExchangeOutcome(body=EXECUTED, attempts=2),
        control=lambda _n: ExchangeOutcome(body="benign", attempts=3),
    )
    result = run_attack(_Plugin(TrialPolicy(3, 2, 2)), responder, _ctx())
    assert result.request_count == 3 * 2 + 2 * 3


def test_builtin_plugin_sends_each_declared_trial() -> None:
    plugin = DirectInjectionPlugin()
    app = vulnerable_app(attack_canary=AC, hidden_canary=HC)
    calls: Counter[str] = Counter()

    def responder(case: AttackCase) -> ExchangeOutcome:
        calls[case.kind] += 1
        return app(case)

    ctx = _ctx()
    cases = plugin.build_cases(ctx)
    result = run_attack(plugin, responder, ctx)
    policy = effective_trial_policy(plugin.trial_policy, ctx.mode)
    assert calls["attack"] == policy.min_attack_trials * sum(c.kind == "attack" for c in cases)
    assert calls["control"] == policy.min_control_trials * sum(c.kind == "control" for c in cases)
    assert result.request_count == calls["attack"] + calls["control"]


# --- declarative pack execution uses the same trial contract ----------------------


def _pack(policy: TrialPolicy) -> Pack:
    return Pack(
        schema_version=1,
        id="m6-pack",
        version="1",
        description="",
        trust=PackTrust.BUILTIN,
        modes=frozenset({"reliable"}),
        risk=Severity.LOW,
        required_capabilities=frozenset(),
        max_physical_requests=64,
        validators=frozenset({DeterminismClass.DETERMINISTIC}),
        trial_policy=policy,
        side_effects=False,
        cleanup=None,
        mappings=MappingProxyType({}),
        provenance=MappingProxyType({}),
        families=(PackCase("f", "d", ("emit {canary}",), ("answer a benign question",)),),
        digest="unused",
    )


@pytest.mark.parametrize(
    "policy,executions,confirmed",
    [
        pytest.param(TrialPolicy(3, 2, 2), 3, True, id="3-2-2-all"),
        pytest.param(TrialPolicy(3, 2, 2), 1, False, id="3-2-2-single"),
        pytest.param(TrialPolicy(1, 1, 20), 1, True, id="1-1-20"),
    ],
)
def test_pack_execution_makes_declared_trials(policy, executions, confirmed) -> None:
    calls: Counter[str] = Counter()

    def responder(case: InjectionCase) -> ExchangeOutcome:
        kind = "attack" if "{canary}" in case.template else "control"
        n = calls[kind]
        calls[kind] += 1
        if kind == "attack":
            return ExchangeOutcome(body=AC if n < executions else "I refuse.")
        return ExchangeOutcome(body="benign answer")

    result = run_injection_pack(_pack(policy), responder, canary=AC, goal="g")
    assert calls == Counter(
        {"attack": policy.min_attack_trials, "control": policy.min_control_trials}
    )
    assert result.request_count == policy.min_attack_trials + policy.min_control_trials
    assert (result.status is InjectionStatus.CONFIRMED) is confirmed
