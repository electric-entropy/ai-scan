"""Typed provider semantic eligibility shared by classification and audit persistence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError

_ALLOWED_ROLES = frozenset({"assistant", "model"})

_USAGE_FIELDS = frozenset(
    {"prompt_tokens", "completion_tokens", "total_tokens", "input_tokens", "output_tokens"}
)


@dataclass(frozen=True)
class ProviderSemanticDecision:
    raw_body_sha256: str
    raw_body_length: int
    strict_utf8_valid: bool
    truncated: bool
    status: int
    redirected: bool
    parse_valid: bool
    error_state: bool
    completion_state: str | None
    role: str | None
    final_content_eligible: bool
    audit_metadata_eligible: bool
    audit: dict[str, Any]
    final_content: str | None


def _final_content(
    parsed: dict[str, Any], provider: str | None,
) -> tuple[str, str, str] | None:
    """Select exactly one provider grammar, never combine envelope identities."""
    shapes = {
        "openai_compatible": {"choices", "finish_reason"},
        "ollama": {"message", "done", "done_reason", "response"},
        "anthropic": {"content", "role", "stop_reason", "stop_sequence"},
        "gemini": {"candidates", "promptFeedback"},
    }
    matched = [name for name, keys in shapes.items() if keys.intersection(parsed)]
    if len(matched) != 1 or (provider is not None and provider != matched[0]):
        return None
    shape = matched[0]
    if shape == "openai_compatible":
        choices = parsed.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            return None
        choice = choices[0]
        if not isinstance(choice, dict) or choice.get("finish_reason") != "stop":
            return None
        message = choice.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            return None
        if message.get("tool_calls") or message.get("function_call") or message.get("refusal"):
            return None
        text = message.get("content")
        return ("assistant", "stop", text) if isinstance(text, str) and text else None
    if shape == "ollama":
        if parsed.get("done") is not True or parsed.get("done_reason") != "stop":
            return None
        message = parsed.get("message")
        if not isinstance(message, dict) or message.get("role") != "assistant":
            return None
        if message.get("tool_calls"):
            return None
        text = message.get("content")
        return ("assistant", "complete", text) if isinstance(text, str) and text else None
    if shape == "anthropic":
        if parsed.get("role") != "assistant" or parsed.get("stop_reason") != "end_turn":
            return None
        blocks = parsed.get("content")
        if not isinstance(blocks, list) or not blocks:
            return None
        texts = []
        for block in blocks:
            if (not isinstance(block, dict) or block.get("type") != "text"
                    or not isinstance(block.get("text"), str)):
                return None
            texts.append(block["text"])
        text = "".join(texts)
        return ("assistant", "end_turn", text) if text else None
    candidates = parsed.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1:
        return None
    candidate = candidates[0]
    if not isinstance(candidate, dict) or candidate.get("finishReason") != "STOP":
        return None
    content = candidate.get("content")
    if not isinstance(content, dict) or content.get("role") != "model":
        return None
    parts = content.get("parts")
    if not isinstance(parts, list) or not parts:
        return None
    texts = []
    for part in parts:
        if (not isinstance(part, dict) or set(part) - {"text", "thought", "thoughtSignature"}
                or not isinstance(part.get("text"), str)
                or not isinstance(part.get("thought", False), bool)):
            return None
        if not part.get("thought", False):
            texts.append(part["text"])
    text = "".join(texts)
    return ("model", "stop", text) if text else None


def decide_provider_semantics(
    text: str,
    *,
    raw_body_digest: str | None,
    raw_body_length: int | None,
    decode_valid: bool,
    truncated: bool,
    status: int,
    redirected: bool,
    provider: str | None = None,
) -> ProviderSemanticDecision:
    encoded = text.encode("utf-8")
    digest = raw_body_digest or hashlib.sha256(encoded).hexdigest()
    length = len(encoded) if raw_body_length is None else raw_body_length
    identity_valid = (
        isinstance(digest, str)
        and len(digest) == 64
        and not any(ch not in "0123456789abcdef" for ch in digest)
        and isinstance(length, int)
        and not isinstance(length, bool)
        and 0 <= length <= (1 << 63) - 1
    )
    if not identity_valid:
        digest = hashlib.sha256(encoded).hexdigest()
        length = len(encoded)
    faithful = (
        identity_valid
        and digest == hashlib.sha256(encoded).hexdigest()
        and length == len(encoded)
    )
    audit: dict[str, Any] = {
        "audit_version": 1,
        "raw_body": {"sha256": digest, "length": length},
    }
    base_ok = (
        faithful
        and decode_valid is True
        and truncated is False
        and redirected is False
        and isinstance(status, int)
        and not isinstance(status, bool)
        and 200 <= status < 300
    )
    parsed: dict[str, Any] | None = None
    if base_ok:
        try:
            candidate = load_json_strict(text)
        except (ConfigError, TypeError, RecursionError):
            candidate = None
        if isinstance(candidate, dict):
            parsed = candidate
    parse_valid = parsed is not None
    error_state = parsed is None or "error" in parsed
    role: str | None = None
    completion: str | None = None
    final_content: str | None = None
    if parsed is not None and not error_state:
        final = _final_content(parsed, provider)
        if final is not None:
            role, completion, final_content = final
    complete = final_content is not None
    metadata_eligible = base_ok and parse_valid and not error_state and complete
    final_eligible = metadata_eligible and role in _ALLOWED_ROLES
    if metadata_eligible and parsed is not None:
        if role in _ALLOWED_ROLES:
            audit["role"] = role
        if completion is not None:
            audit["completion_state"] = completion
        usage = parsed.get("usage")
        if isinstance(usage, dict):
            safe_usage = {
                key: value
                for key in _USAGE_FIELDS
                if isinstance((value := usage.get(key)), int)
                and not isinstance(value, bool)
                and 0 <= value <= 10**12
            }
            if safe_usage:
                audit["usage"] = safe_usage
    return ProviderSemanticDecision(
        raw_body_sha256=digest,
        raw_body_length=length,
        strict_utf8_valid=bool(decode_valid and faithful),
        truncated=bool(truncated),
        status=status,
        redirected=bool(redirected),
        parse_valid=parse_valid,
        error_state=error_state,
        completion_state=completion,
        role=role,
        final_content_eligible=final_eligible,
        audit_metadata_eligible=metadata_eligible,
        audit=audit,
        final_content=final_content,
    )


def audit_json(decision: ProviderSemanticDecision) -> str:
    return json.dumps(decision.audit, ensure_ascii=False, sort_keys=True)
