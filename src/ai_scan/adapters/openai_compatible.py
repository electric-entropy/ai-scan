"""OpenAI-compatible chat-completions adapter (offline request shaper)."""

from __future__ import annotations

from typing import Any

from ai_scan.adapters.base import HttpJsonAdapter


class OpenAICompatibleAdapter(HttpJsonAdapter):
    """Shapes a ``/v1/chat/completions`` request; extracts the assistant message."""

    name = "openai_compatible"
    extraction_path = "/choices/0/message/content"

    def _payload(self, prompt: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
