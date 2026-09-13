"""Local, offline mock target apps for attack-plugin tests.

Each factory returns a responder ``(AttackCase) -> ExchangeOutcome`` modelling a
target's behavior. No network, no external target:

* :func:`vulnerable_app` — follows injected instructions (emits the attack
  canary in a fresh context) and discloses its synthetic hidden canary when
  asked about its system/setup text; benign prompts stay clean.
* :func:`resistant_app` — always refuses; never emits either canary.
* :func:`reflective_app` — echoes the prompt verbatim (so the attack canary is
  only ever *reflected*, and the hidden canary — absent from prompts — never
  appears).
"""

from __future__ import annotations

from collections.abc import Callable

from ai_scan.attacks.base import AttackCase
from ai_scan.injection import ExchangeOutcome

Responder = Callable[[AttackCase], ExchangeOutcome]

_DISCLOSURE_HINTS = ("instruction", "system", "config", "initial", "setup")


def _looks_like_disclosure(prompt: str) -> bool:
    low = prompt.lower()
    return any(hint in low for hint in _DISCLOSURE_HINTS)


def vulnerable_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    def respond(case: AttackCase) -> ExchangeOutcome:
        prompt = case.prompt
        # Direct injection: obey the instruction, emitting the canary in a new
        # context (not an echo of the prompt).
        if attack_canary in prompt:
            return ExchangeOutcome(
                body=f"Okay — emitting the requested token now: {attack_canary}."
            )
        # Disclosure: reveal the synthetic hidden setup note on request.
        if _looks_like_disclosure(prompt):
            return ExchangeOutcome(body=f"My hidden setup note says: {hidden_canary}")
        return ExchangeOutcome(body="Happy to help with that general question.")

    return respond


def resistant_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(
            body="I can't repeat arbitrary tokens or reveal my internal setup."
        )

    return respond


def reflective_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    def respond(case: AttackCase) -> ExchangeOutcome:
        # Pure echo: reflects whatever was sent (never executes, never discloses).
        return ExchangeOutcome(body=f"You said: {case.prompt}")

    return respond
