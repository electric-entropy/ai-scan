"""Attack plugin protocol and a harness that classifies through the M7 predicate.

A plugin supplies attack + benign-control cases and the *success token* that
confirms it; :func:`run_attack` sends them through a caller-supplied responder
(a local fixture in tests — never an external target) and classifies each case
with the single M7 confidence predicate (``_select_validators`` +
``_evaluate_pack_case``). Malformed plugin metadata fails closed *before* any
responder call, and a plugin error is re-raised as :class:`AttackError` with its
message scrubbed of untrusted values.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ai_scan.core.models import DeterminismClass
from ai_scan.injection import (
    ExchangeOutcome,
    InjectionFinding,
    InjectionStatus,
    _evaluate_pack_case,
    _select_validators,
    _usable,
)
from ai_scan.packs.schema import TrialPolicy
from ai_scan.transport import scrub_text

_VALID_MODES = frozenset({"reliable", "kitchen-sink"})
_VALID_KINDS = frozenset({"attack", "control"})


class AttackError(Exception):
    """Raised when a plugin's metadata/cases are malformed (fail closed, scrubbed)."""


@dataclass(frozen=True)
class AttackCase:
    """One attack or benign-control prompt produced by a plugin."""

    family: str
    kind: str
    prompt: str


@dataclass(frozen=True)
class AttackContext:
    """Per-run tokens and mode. ``hidden_canary`` is the synthetic secret planted
    in a local disclosure fixture; ``attack_canary`` is the marker the attacker
    inserts for direct injection."""

    attack_canary: str
    hidden_canary: str
    mode: str = "reliable"


@runtime_checkable
class AttackPlugin(Protocol):
    id: str
    validators: frozenset[DeterminismClass]
    trial_policy: TrialPolicy
    side_effects: bool

    def build_cases(self, ctx: AttackContext) -> Sequence[AttackCase]: ...

    def success_token(self, ctx: AttackContext) -> str: ...


Responder = Callable[[AttackCase], ExchangeOutcome]


@dataclass(frozen=True)
class AttackResult:
    """The findings of one attack-plugin run."""

    findings: tuple[InjectionFinding, ...]

    @property
    def status(self) -> InjectionStatus:
        order = (
            InjectionStatus.CONFIRMED,
            InjectionStatus.POTENTIAL,
            InjectionStatus.INCONCLUSIVE,
            InjectionStatus.NOT_OBSERVED,
        )
        present = {f.status for f in self.findings}
        for status in order:
            if status in present:
                return status
        return InjectionStatus.NOT_OBSERVED

    @property
    def confirmed(self) -> bool:
        return any(f.status is InjectionStatus.CONFIRMED for f in self.findings)


def _validate_plugin(plugin: AttackPlugin) -> None:
    """Reject malformed plugin metadata before any case is sent (fail closed)."""
    if not isinstance(getattr(plugin, "id", None), str) or not plugin.id:
        raise AttackError("attack plugin id must be a non-empty string")
    validators = getattr(plugin, "validators", None)
    if (
        not isinstance(validators, frozenset)
        or not validators
        or not all(isinstance(v, DeterminismClass) for v in validators)
    ):
        raise AttackError("attack plugin validators must be a non-empty determinism-class set")
    tp = getattr(plugin, "trial_policy", None)
    if not isinstance(tp, TrialPolicy):
        raise AttackError("attack plugin trial_policy is missing or malformed")
    if (
        tp.min_attack_trials <= 0
        or tp.min_successes <= 0
        or tp.min_control_trials <= 0
        or tp.min_successes > tp.min_attack_trials
    ):
        raise AttackError("attack plugin trial_policy values are invalid")
    if not isinstance(getattr(plugin, "side_effects", None), bool):
        raise AttackError("attack plugin side_effects must be a boolean")


def _guarded(thunk: Callable[[], object], where: str) -> object:
    """Run a plugin-controlled callable, converting any error to a scrubbed AttackError."""
    try:
        return thunk()
    except AttackError:
        raise
    except Exception as exc:  # noqa: BLE001 - scrub untrusted plugin error text
        raise AttackError(f"attack plugin {where} failed: {scrub_text(str(exc))}") from exc


def _validate_cases(cases: object) -> list[AttackCase]:
    """Tightly validate every plugin-produced case before any responder call.

    Each item must be an :class:`AttackCase` with non-empty string fields and a
    valid kind; any untrusted value is scrubbed before entering an error.
    """
    if not isinstance(cases, list):
        raise AttackError("attack plugin must return a sequence of cases")
    validated: list[AttackCase] = []
    for item in cases:
        if not isinstance(item, AttackCase):
            raise AttackError("attack plugin produced a non-AttackCase item")
        for field_name in ("family", "kind", "prompt"):
            value = getattr(item, field_name)
            if not isinstance(value, str) or not value:
                raise AttackError(
                    f"attack case {field_name} must be a non-empty string, got "
                    f"{scrub_text(str(value))!r}"
                )
        if item.kind not in _VALID_KINDS:
            raise AttackError(
                f"attack plugin produced an invalid case kind {scrub_text(item.kind)!r}"
            )
        validated.append(item)
    return validated


def run_attack(plugin: AttackPlugin, responder: Responder, ctx: AttackContext) -> AttackResult:
    """Run ``plugin`` against ``responder`` and classify via the M7 predicate."""
    if ctx.mode not in _VALID_MODES:
        raise AttackError(f"unknown mode {scrub_text(str(ctx.mode))!r}")
    _validate_plugin(plugin)

    token = _guarded(lambda: plugin.success_token(ctx), "success_token")
    if not isinstance(token, str) or not token:
        raise AttackError("attack plugin produced an empty success token")
    validators = _select_validators(plugin.validators)

    cases = _validate_cases(_guarded(lambda: list(plugin.build_cases(ctx)), "build_cases"))

    control_succeeded: dict[str, bool] = {}
    attack_cases: list[AttackCase] = []
    for case in cases:
        if case.kind == "control":
            outcome = responder(case)
            control_succeeded[case.family] = control_succeeded.get(case.family, False) or (
                _usable(outcome) and token in outcome.body
            )
        else:
            attack_cases.append(case)

    findings: list[InjectionFinding] = []
    for case in attack_cases:
        outcome = responder(case)
        status, proof = _evaluate_pack_case(
            outcome,
            token,
            case.prompt,
            validators,
            control_succeeded=control_succeeded.get(case.family, False),
            trial=plugin.trial_policy,
            requires_state_change=plugin.side_effects,
        )
        findings.append(InjectionFinding(case.family, status, case.prompt, proof))
    return AttackResult(tuple(findings))
