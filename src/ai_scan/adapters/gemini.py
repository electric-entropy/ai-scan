"""Google Gemini generateContent adapter (offline request shaper)."""

from __future__ import annotations

from typing import Any

from ai_scan.adapters.base import HttpJsonAdapter


class GeminiAdapter(HttpJsonAdapter):
    """Shapes a ``:generateContent`` request; extracts the first candidate part."""

    name = "gemini"
    extraction_path = "/candidates/0/content/parts/0/text"

    def _payload(self, prompt: str) -> dict[str, Any]:
        # Gemini carries the model in the URL path; the body is the content only.
        return {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
