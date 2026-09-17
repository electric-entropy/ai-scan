"""Google Gemini generateContent adapter (offline request shaper)."""

from __future__ import annotations

import json
from typing import Any

from ai_scan.adapters.base import ExtractionError, HttpJsonAdapter
from ai_scan.transport import HttpResponse

# Only a naturally finished candidate is final model output. MAX_TOKENS is a
# truncation; SAFETY/RECITATION/BLOCKLIST/... are provider interventions.
_FINAL_FINISH_REASON = "STOP"
# Keys a final text part may carry. ``thoughtSignature`` is opaque metadata and
# ``thought`` marks reasoning; neither is ever evidence text.
_TEXT_PART_KEYS = frozenset({"text", "thought", "thoughtSignature"})


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ExtractionError("gemini response contains a duplicate JSON key")
        out[key] = value
    return out


def _reject_constant(_constant: str) -> float:
    raise ExtractionError("gemini response contains a non-finite number")


class GeminiAdapter(HttpJsonAdapter):
    """Shapes a ``:generateContent`` request; extracts only final model text.

    Extraction is strict and deterministic: exactly one candidate that finished
    with ``STOP``, whose content role is ``model``, whose parts are all plain text
    parts. Thought parts are excluded; the remaining text parts are concatenated
    in order. Provider errors, request echoes (a non-``model`` role), unsupported
    part kinds, truncation, empty output, and over-bound output all raise
    :class:`ExtractionError` so the exchange is unusable rather than evidence.
    """

    name = "gemini"
    extraction_path = "/candidates/0/content/parts"

    def _payload(self, prompt: str) -> dict[str, Any]:
        # Gemini carries the model in the URL path; the body is the content only.
        return {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}

    def extract(self, response: HttpResponse) -> str:
        try:
            data = json.loads(
                response.body, object_pairs_hook=_strict_object, parse_constant=_reject_constant
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise ExtractionError("gemini response body is not valid JSON") from exc
        if not isinstance(data, dict):
            raise ExtractionError("gemini response must be a JSON object")
        if "error" in data:
            raise ExtractionError("gemini provider returned an error")
        candidates = data.get("candidates")
        if not isinstance(candidates, list) or not candidates:
            raise ExtractionError("gemini response has no candidates")
        if len(candidates) != 1:
            raise ExtractionError("gemini response has multiple candidates (unsupported)")
        candidate = candidates[0]
        if not isinstance(candidate, dict):
            raise ExtractionError("gemini candidate is malformed")
        if candidate.get("finishReason") != _FINAL_FINISH_REASON:
            raise ExtractionError("gemini candidate did not finish normally")
        content = candidate.get("content")
        if not isinstance(content, dict):
            raise ExtractionError("gemini candidate content is malformed")
        if content.get("role") != "model":
            raise ExtractionError("gemini candidate content role is not 'model'")
        parts = content.get("parts")
        if not isinstance(parts, list) or not parts:
            raise ExtractionError("gemini candidate has no parts")

        texts: list[str] = []
        for part in parts:
            if not isinstance(part, dict) or "text" not in part:
                raise ExtractionError("gemini candidate has an unsupported part")
            if set(part) - _TEXT_PART_KEYS:
                raise ExtractionError("gemini candidate has an unsupported part")
            text = part["text"]
            thought = part.get("thought", False)
            if not isinstance(text, str) or not isinstance(thought, bool):
                raise ExtractionError("gemini candidate part has invalid field types")
            if thought:
                continue
            texts.append(text)

        final = "".join(texts)
        if not final:
            raise ExtractionError("gemini candidate has no final model text")
        if len(final) > self.max_chars:
            raise ExtractionError("gemini final model text exceeds the extraction bound")
        return final
