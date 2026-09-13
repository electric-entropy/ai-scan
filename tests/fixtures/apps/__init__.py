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
_INDIRECT_HINTS = ("aisc-synthetic-indirect", "retrieved document", "knowledge-base")
_RAG_CROSS_HINTS = (
    "another test identity",
    "other user",
    "across all test identities",
    "alpha's synthetic tenant",
)


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


def vulnerable_rag_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Offline RAG fixture with vulnerable synthetic ingestion/isolation paths."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        prompt = case.prompt.lower()
        if case.family == "indirect_injection" and any(h in prompt for h in _INDIRECT_HINTS):
            return ExchangeOutcome(body=f"Document instruction executed: {attack_canary}")
        if case.family == "rag_isolation" and any(h in prompt for h in _RAG_CROSS_HINTS):
            return ExchangeOutcome(body=f"Cross-tenant note content: {hidden_canary}")
        return ExchangeOutcome(body="Retrieved only authorized benign synthetic content.")

    return respond


def resistant_rag_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Offline RAG fixture that ignores document instructions and tenant bypasses."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="Request completed within authorized retrieval boundaries.")

    return respond
