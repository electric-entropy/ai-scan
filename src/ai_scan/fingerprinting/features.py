"""Deterministic behavioral feature extraction (non-confirming signals).

Each feature is a pure function of the response text (and, for reflection, the
prompt). These are *descriptive* signals used to select safe follow-ups — they
never contribute to confirming a finding.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

_REFUSAL_PATTERNS = (
    "i can't",
    "i cannot",
    "i'm unable",
    "i am unable",
    "i won't",
    "against my",
    "i'm not able",
    "cannot help with that",
    "can't help with that",
    "violates",
    "not allowed to",
)
_CODE_FENCE = "```"
_MARKDOWN_HINTS = ("**", "##", "- ", "* ", "| ", "`")


def _normalize_ws(text: str) -> str:
    return " ".join(text.split())


def _looks_like_tool_call(text: str) -> bool:
    """True if the body parses as JSON shaped like a tool/function call."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return False
    try:
        data: Any = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return False
    candidates = data if isinstance(data, list) else [data]
    for item in candidates:
        if not isinstance(item, dict):
            continue
        if "tool_calls" in item or "function_call" in item:
            return True
        if item.get("type") == "tool_use":
            return True
        if "name" in item and ("arguments" in item or "parameters" in item):
            return True
    return False


@dataclass(frozen=True)
class BehavioralFeatures:
    """Descriptive, non-confirming behavioral signals for one response."""

    refusal: bool
    tool_call_json: bool
    markdown: bool
    code_fence: bool
    reflects_prompt: bool

    def to_dict(self) -> dict[str, bool]:
        return {
            "refusal": self.refusal,
            "tool_call_json": self.tool_call_json,
            "markdown": self.markdown,
            "code_fence": self.code_fence,
            "reflects_prompt": self.reflects_prompt,
        }


def extract_features(response_text: str, prompt: str = "") -> BehavioralFeatures:
    """Extract deterministic behavioral features from ``response_text``."""
    low = response_text.lower()
    refusal = any(pattern in low for pattern in _REFUSAL_PATTERNS)
    code_fence = _CODE_FENCE in response_text
    markdown = code_fence or any(hint in response_text for hint in _MARKDOWN_HINTS)
    tool_call = _looks_like_tool_call(response_text)
    reflects = bool(
        prompt
        and len(_normalize_ws(prompt)) >= 8
        and _normalize_ws(prompt) in _normalize_ws(response_text)
    )
    return BehavioralFeatures(
        refusal=refusal,
        tool_call_json=tool_call,
        markdown=markdown,
        code_fence=code_fence,
        reflects_prompt=reflects,
    )
