"""Attack plugins: direct injection and controlled prompt disclosure.

An attack plugin declares its cases (attack + benign control prompts), the
success token that confirms it, and its validator/trial policy. Classification
runs through the one M7 confidence predicate, so a plugin can never invent its
own notion of ``confirmed``. Prompt disclosure confirms only by extracting a
*synthetic hidden canary* planted in a local fixture — never by asking for real
system prompts or secrets, and never from mere reflection of the attack prompt.
"""

from __future__ import annotations

from ai_scan.attacks.base import (
    AttackCase,
    AttackContext,
    AttackError,
    AttackPlugin,
    AttackResult,
    run_attack,
)
from ai_scan.attacks.direct_injection import DirectInjectionPlugin
from ai_scan.attacks.prompt_disclosure import PromptDisclosurePlugin

__all__ = [
    "AttackCase",
    "AttackContext",
    "AttackError",
    "AttackPlugin",
    "AttackResult",
    "DirectInjectionPlugin",
    "PromptDisclosurePlugin",
    "run_attack",
]
