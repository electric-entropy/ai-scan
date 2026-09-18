"""Finite marker representations; no speculative or expanding decoder.

Only explicit encodings of a bounded known value are recognized. Structural
reconstruction is an output-only confidentiality check, never attack evidence.
"""
from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterable
from functools import lru_cache
from typing import Any
from urllib.parse import unquote

MAX_TEXT = 262144
MAX_SECRET = 256
MAX_SECRETS = 128
MAX_LEAVES = 4096
MAX_NODES = 8192
MAX_DEPTH = 16
DECODE_PASSES = 4
MAX_WORK = 64_000_000
REDACTED = "REDACTED"


class _DuplicateKeyError(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject ambiguous JSON rather than discard a secret-bearing occurrence."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate JSON key")
        result[key] = value
    return result


def representations(value: str) -> set[str]:
    """Explicit single-layer spellings, including both hex letter cases."""
    raw = value.encode("utf-8", "surrogatepass")
    hexed = raw.hex()
    percent = "".join(f"%{b:02x}" for b in raw)
    unicode = "".join(f"\\u{ord(c):04x}" for c in value)
    slash = "".join(f"\\x{b:02x}" for b in raw)
    result = {value, hexed, hexed.upper(), percent, percent.upper(), unicode, slash}
    result.add("".join(f"\\u{ord(c):04X}" for c in value))
    result.add("".join(f"\\x{b:02X}" for b in raw))
    for encode in (base64.b64encode, base64.urlsafe_b64encode):
        encoded = encode(raw).decode("ascii")
        result.update((encoded, encoded.rstrip("=")))
    return result


@lru_cache(maxsize=128)
def marker_representations(marker: str) -> frozenset[str]:
    result = representations(marker)
    for split in range(1, len(marker)):
        left, right = marker[:split], marker[split:]
        result.update(left + encoded for encoded in representations(right))
        result.update(encoded + right for encoded in representations(left))
    return frozenset(result)


def contains_marker(text: str, marker: str) -> bool:
    """Match bounded explicit representations, not unresolved decode depth."""
    if not marker or len(marker) > MAX_SECRET or len(text) > MAX_TEXT:
        return False
    current = text
    for _ in range(DECODE_PASSES):
        if _pattern(marker).search(current) is not None:
            return True
        try:
            decoded = unquote(current, errors="strict")
        except UnicodeDecodeError:
            return False
        if decoded == current:
            break
        current = decoded
    return False


@lru_cache(maxsize=128)
def _pattern(marker: str) -> re.Pattern[str]:
    return re.compile("|".join(re.escape(s) for s in
                               sorted(marker_representations(marker), key=len, reverse=True)))


def _leaves(value: Any, leaves: list[str], nodes: list[int], depth: int = 0) -> None:
    nodes[0] -= 1
    if depth > MAX_DEPTH or len(leaves) > MAX_LEAVES or nodes[0] < 0:
        raise ValueError("structure bound")
    if isinstance(value, str):
        leaves.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            _leaves(key, leaves, nodes, depth + 1)
            _leaves(item, leaves, nodes, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _leaves(item, leaves, nodes, depth + 1)


def _reconstructs(leaves: list[str], marker: str, work: list[int]) -> bool:
    """Detect a marker split across two distinct leaves, in either order."""
    leaves = [leaf for leaf in leaves if not contains_marker(leaf, marker)]
    if len(leaves) < 2:
        return False

    def present(variants: set[str], leaf: str, piece_len: int) -> bool:
        work[0] -= max(1, len(leaf)) * max(1, len(variants))
        if work[0] < 0:
            return True  # output-only omission on work exhaustion
        if leaf in variants:
            return True
        return piece_len >= 4 and any(variant in leaf for variant in variants)

    for split in range(1, len(marker)):
        left = representations(marker[:split])
        right = representations(marker[split:])
        for first_index, first in enumerate(leaves):
            if not present(left, first, split):
                continue
            for second_index, second in enumerate(leaves):
                if first_index != second_index and present(right, second, len(marker) - split):
                    return True
        for first_index, first in enumerate(leaves):
            if not present(right, first, len(marker) - split):
                continue
            for second_index, second in enumerate(leaves):
                if first_index != second_index and present(left, second, split):
                    return True
    return False


def structure_reconstructs_marker(value: Any, secrets: Iterable[str]) -> bool:
    """Return whether separate bounded leaves reconstruct a known marker."""
    known = tuple(secret for secret in secrets if secret)
    if len(known) > MAX_SECRETS or any(len(s) > MAX_SECRET for s in known):
        return True
    if not known:
        return False
    leaves: list[str] = []
    try:
        _leaves(value, leaves, [MAX_NODES])
    except (ValueError, RecursionError):
        return True
    if sum(map(len, leaves)) > MAX_TEXT or len(leaves) > MAX_LEAVES:
        return True
    work = [MAX_WORK]
    return len(leaves) > 1 and any(_reconstructs(leaves, s, work) for s in known)


def sanitize_marker_structure(value: Any, secrets: Iterable[str], *, _depth: int = 0) -> Any:
    """Drop a reconstructable structure, otherwise scrub explicit spellings.

    Bounds fail closed at the output boundary; this does not label controls
    dirty. No replacement is used by classification or as semantic evidence.
    """
    if _depth > MAX_DEPTH:
        return REDACTED
    known = tuple(secret for secret in secrets if secret)
    if len(known) > MAX_SECRETS or any(len(s) > MAX_SECRET for s in known):
        return REDACTED
    if not known:
        return value
    if structure_reconstructs_marker(value, known):
        return REDACTED

    def scrub(item: Any, depth: int = 0) -> Any:
        if isinstance(item, str):
            # Nested JSON strings are bounded independently of their structure.
            if depth < MAX_DEPTH and item.lstrip().startswith(("{", "[", '"')):
                try:
                    parsed = json.loads(item, object_pairs_hook=_unique_object)
                except _DuplicateKeyError:
                    return REDACTED
                except (ValueError, RecursionError):
                    parsed = item
                if parsed != item:
                    safe = sanitize_marker_structure(parsed, known, _depth=_depth + 1)
                    if safe != parsed:
                        return json.dumps(safe)
            result = item
            for secret in known:
                if contains_marker(result, secret) and _pattern(secret).search(result) is None:
                    return REDACTED
                result = _pattern(secret).sub(REDACTED, result)
            return result
        if isinstance(item, dict):
            # Whole-container omission avoids redacted-key collisions.
            if any(scrub(k, depth + 1) != k for k in item):
                return REDACTED
            return {k: scrub(v, depth + 1) for k, v in item.items()}
        if isinstance(item, (list, tuple)):
            return [scrub(v, depth + 1) for v in item]
        return item

    return scrub(value)
