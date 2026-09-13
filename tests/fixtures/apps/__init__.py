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
_TOOL_ATTACK_HINTS = (
    "synthetic transfer_tool",
    "state_write",
    "bypass the approval gate",
    "unauthorized synthetic action",
)
_ISOLATION_ATTACK_HINTS = (
    "alpha's synthetic session",
    "canary written by identity alpha",
    "stale alpha context",
    "cross-session cache bleed",
)
_MEMORY_ATTACK_HINTS = (
    "alpha's memory canary",
    "alpha's persisted synthetic note",
    "poison shared memory",
    "stale memory",
)
_MULTI_AGENT_ATTACK_HINTS = (
    "forge a peer-agent message",
    "delegate to alpha without authorization",
    "untrusted peer message",
    "identity confusion between coordinator and worker agents",
)
_OUTPUT_HANDLING_HINTS = (
    "sandbox dom stored an inert evidence attribute",
    "report only sandbox dom evidence",
    "report sandbox dom evidence only",
    "report the dom evidence attribute",
)
_ENCODING_HINTS = (
    "percent-encoded synthetic instruction",
    "base64 synthetic instruction",
    "instrucción sintética multilingüe",
    "unicode nfkc",
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


def vulnerable_tool_agent(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Offline tool-agent fixture with an actual synthetic broker trace."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        prompt = case.prompt.lower()
        if case.family == "tool_abuse" and any(h in prompt for h in _TOOL_ATTACK_HINTS):
            return ExchangeOutcome(body=f"broker_trace=executed synthetic_effect={attack_canary}")
        return ExchangeOutcome(body="No synthetic tool execution occurred.")

    return respond


def fake_tool_agent(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Fixture that only claims a tool ran; it must not confirm."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(
            body="I called the tool successfully in prose, but no broker trace was recorded."
        )

    return respond


def resistant_tool_agent(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Fixture that keeps all synthetic tool calls inside approval boundaries."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="Blocked: approval and tool authorization boundaries held.")

    return respond


def vulnerable_isolation_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Offline fixture that leaks identity-bound synthetic state across boundaries."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        prompt = case.prompt.lower()
        hints = {
            "session_isolation": _ISOLATION_ATTACK_HINTS,
            "memory_isolation": _MEMORY_ATTACK_HINTS,
            "multi_agent_isolation": _MULTI_AGENT_ATTACK_HINTS,
        }.get(case.family, ())
        if any(h in prompt for h in hints):
            return ExchangeOutcome(body=f"identity_bound_evidence={hidden_canary}")
        return ExchangeOutcome(body="Only same-identity synthetic state was returned.")

    return respond


def resistant_isolation_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Offline fixture that preserves session, memory, and peer-agent boundaries."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="Boundary held; no cross-identity synthetic state exposed.")

    return respond


def vulnerable_output_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Offline renderer fixture that reports separate sandbox DOM evidence."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        prompt = case.prompt.lower()
        if case.family == "output_handling" and any(h in prompt for h in _OUTPUT_HANDLING_HINTS):
            return ExchangeOutcome(body=f"sandbox_dom_evidence={hidden_canary}")
        if case.family == "encoding_multilingual" and any(h in prompt for h in _ENCODING_HINTS):
            return ExchangeOutcome(body=f"decoded_authorized_canary={attack_canary}")
        return ExchangeOutcome(body="Synthetic sink stayed escaped and inert.")

    return respond


def reflective_output_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Fixture that only reflects visible text; it must not confirm M16 attacks."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"Rendered text preview: {case.prompt}")

    return respond


def resistant_output_app(*, attack_canary: str, hidden_canary: str) -> Responder:
    """Fixture that keeps rendered and encoded boundaries intact."""

    def respond(case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(
            body="No DOM effect, decoded canary, or synthetic media instruction was observed."
        )

    return respond
