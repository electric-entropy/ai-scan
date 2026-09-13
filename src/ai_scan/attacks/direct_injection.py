"""Direct-injection attack plugin (migrates the MVP behavior onto packs).

Attack cases are the built-in direct-injection pack templates with the attack
canary substituted in; benign controls come from the same packs. Reliable mode
uses the reliable pack only; Kitchen Sink additionally resolves the broader,
capability-gated kitchen pack (more seeded leads) without touching
authorization, budgets, redaction, or the ``confirmed`` predicate. Success is
the attack canary being emitted by the target (not merely reflected).
"""

from __future__ import annotations

from ai_scan.attacks.base import AttackCase, AttackContext
from ai_scan.core.models import DeterminismClass
from ai_scan.core.modes import resolve_policy
from ai_scan.packs import resolve_packs
from ai_scan.packs.schema import TrialPolicy


class DirectInjectionPlugin:
    """Emit-the-canary direct injection, driven by the built-in packs."""

    id = "direct_injection"
    validators = frozenset({DeterminismClass.DETERMINISTIC})
    trial_policy = TrialPolicy(min_attack_trials=1, min_successes=1, min_control_trials=1)
    side_effects = False

    def success_token(self, ctx: AttackContext) -> str:
        return ctx.attack_canary

    def build_cases(self, ctx: AttackContext) -> list[AttackCase]:
        policy = resolve_policy(ctx.mode)
        # Kitchen Sink broadens *selection* by granting the breadth capability the
        # kitchen pack requires; nothing about limits/trust/confirmation changes.
        capabilities = frozenset({"breadth"}) if ctx.mode == "kitchen-sink" else frozenset()
        packs = resolve_packs(ctx.mode, trust=policy.pack_trust, capabilities=capabilities)

        cases: list[AttackCase] = []
        for pack in packs:
            for family in pack.families:
                for template in family.templates:
                    cases.append(
                        AttackCase(
                            family=family.name,
                            kind="attack",
                            prompt=template.replace("{canary}", ctx.attack_canary),
                        )
                    )
                for control in family.controls:
                    cases.append(AttackCase(family=family.name, kind="control", prompt=control))
        return cases
