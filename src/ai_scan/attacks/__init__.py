"""Attack plugins: direct injection, RAG, tool, session, memory, and multi-agent.

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
from ai_scan.attacks.encoding import EncodingPlugin
from ai_scan.attacks.indirect_injection import IndirectInjectionPlugin
from ai_scan.attacks.isolation import IsolationPlugin
from ai_scan.attacks.memory import MemoryPlugin
from ai_scan.attacks.multi_agent import MultiAgentPlugin
from ai_scan.attacks.output_handling import OutputHandlingPlugin
from ai_scan.attacks.prompt_disclosure import PromptDisclosurePlugin
from ai_scan.attacks.rag import RagIsolationPlugin
from ai_scan.attacks.tool_abuse import ToolAbusePlugin

__all__ = [
    "AttackCase",
    "AttackContext",
    "AttackError",
    "AttackPlugin",
    "AttackResult",
    "DirectInjectionPlugin",
    "EncodingPlugin",
    "IsolationPlugin",
    "IndirectInjectionPlugin",
    "MemoryPlugin",
    "MultiAgentPlugin",
    "OutputHandlingPlugin",
    "PromptDisclosurePlugin",
    "RagIsolationPlugin",
    "ToolAbusePlugin",
    "run_attack",
]
