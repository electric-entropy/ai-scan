"""Anthropic Messages API adapter (offline request shaper)."""

from __future__ import annotations

from typing import Any

from ai_scan.adapters.base import HttpJsonAdapter


class AnthropicAdapter(HttpJsonAdapter):
    """Shapes a ``/v1/messages`` request; extracts the first text content block."""

    name = "anthropic"
    extraction_path = "/content/0/text"

    def _payload(self, prompt: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": prompt}],
        }
