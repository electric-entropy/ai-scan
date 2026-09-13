"""Ollama chat adapter (offline request shaper)."""

from __future__ import annotations

from typing import Any

from ai_scan.adapters.base import HttpJsonAdapter


class OllamaAdapter(HttpJsonAdapter):
    """Shapes an ``/api/chat`` request; extracts the assistant message content."""

    name = "ollama"
    extraction_path = "/message/content"

    def _payload(self, prompt: str) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
