"""Attack plugin protocol and a harness that classifies through the M7 predicate.

A plugin supplies attack + benign-control cases and the *success token* that
confirms it; :func:`run_attack` sends every declared physical trial through a
caller-supplied responder (a local fixture in tests — never an external target)
and classifies each case's real trial outcomes with the single M7 confidence
predicate (``_select_validators`` + ``evaluate_trials``). Malformed plugin
metadata fails closed *before* any responder call, and a plugin error is
re-raised as :class:`AttackError` with its message scrubbed of untrusted values.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ai_scan.core.models import DeterminismClass
from ai_scan.core.modes import resolve_policy
from ai_scan.injection import (
    CONTROL_CLEAN,
    CONTROL_EMITTED,
    ExchangeOutcome,
    InjectionFinding,
    InjectionStatus,
    _select_validators,
    control_result,
    evaluate_trials,
    legacy_status,
    merge_control_results,
    physical_attempts,
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
    capabilities: frozenset[str] = frozenset()
    identities: tuple[str, ...] = ()


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
    request_count: int = 0

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


def _safe_render(exc: BaseException) -> str:
    """Render an exception's message, scrubbed — and never re-raise.

    A plugin's exception ``__str__`` is itself plugin-controlled and may raise
    (leaking raw text), so rendering is guarded: if it raises, we return a
    generic redaction rather than letting that secondary exception escape.
    """
    try:
        rendered = str(exc)
    except Exception:  # noqa: BLE001 - hostile __str__; do not render plugin text
        return "REDACTED"
    return scrub_text(rendered)


def _guarded(thunk: Callable[[], object], where: str) -> object:
    """Run a plugin-controlled callable, converting any error to a scrubbed AttackError.

    Every exception from a plugin hook is treated as plugin-controlled output —
    including :class:`AttackError` itself (plugins can import and raise it) — so
    its message is always re-rendered through :func:`_safe_render` and can never
    escape raw. The harness's own trusted ``AttackError``\\s are raised outside
    this guard.
    """
    try:
        return thunk()
    except Exception as exc:  # noqa: BLE001 - all plugin-hook output is untrusted
        raise AttackError(f"attack plugin {where} failed: {_safe_render(exc)}") from exc


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
            # Never render a non-string value: its __str__ is plugin-controlled
            # and could raise (leaking raw text). The field name is trusted.
            if not isinstance(value, str) or not value:
                raise AttackError(f"attack case {field_name} must be a non-empty string")
        if item.kind not in _VALID_KINDS:
            raise AttackError(
                f"attack plugin produced an invalid case kind {scrub_text(item.kind)!r}"
            )
        validated.append(item)
    return validated


def effective_trial_policy(declared: TrialPolicy, mode: str) -> TrialPolicy:
    """Tighten a plugin's declared trial policy to at least the resolved mode policy.

    A plugin may demand more trials/successes/controls than its mode, never fewer:
    a built-in ``1/1/1`` declaration runs as ``3/2/2`` under Reliable.
    """
    policy = resolve_policy(mode)
    return TrialPolicy(
        min_attack_trials=max(declared.min_attack_trials, policy.minimum_attack_trials),
        min_successes=max(declared.min_successes, policy.minimum_successes),
        min_control_trials=max(declared.min_control_trials, policy.minimum_control_trials),
    )


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

    policy = effective_trial_policy(plugin.trial_policy, ctx.mode)
    request_count = 0

    def send(case: AttackCase) -> ExchangeOutcome:
        nonlocal request_count
        outcome = responder(case)
        if not isinstance(outcome, ExchangeOutcome):
            raise AttackError("attack responder returned a non-ExchangeOutcome value")
        request_count += physical_attempts(outcome)
        return outcome

    # Every control case runs its full declared trial count. Per-family coverage
    # is tri-state: a usable emission poisons the baseline, and a family can
    # confirm only against a matched control whose every trial was usable+clean.
    controls: dict[str, str] = {}
    attack_cases: list[AttackCase] = []
    for case in cases:
        if case.kind == "control":
            outcomes = [send(case) for _ in range(policy.min_control_trials)]
            controls[case.family] = merge_control_results(
                controls.get(case.family),
                control_result(outcomes, token, policy.min_control_trials),
            )
        else:
            attack_cases.append(case)

    findings: list[InjectionFinding] = []
    for case in attack_cases:
        evidence = tuple(send(case) for _ in range(policy.min_attack_trials))
        control = controls.get(case.family)
        status, proof, trials, successes, _rep = evaluate_trials(
            evidence,
            token,
            case.prompt,
            validators,
            control_succeeded=control == CONTROL_EMITTED,
            matched_clean_control=control == CONTROL_CLEAN,
            min_attack_trials=policy.min_attack_trials,
            min_successes=policy.min_successes,
            requires_state_change=plugin.side_effects,
        )
        findings.append(
            InjectionFinding(
                case.family, legacy_status(status), case.prompt, proof,
                attack_trials=trials, successes=successes, evidence=evidence,
            )
        )
    return AttackResult(tuple(findings), request_count)
