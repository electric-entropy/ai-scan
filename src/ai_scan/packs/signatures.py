"""Content digests for attack packs (fail-closed integrity).

A pack's ``digest`` is a SHA-256 over the canonical JSON of its content with the
``digest`` field itself removed. Canonicalization sorts keys and uses compact
separators so the digest is stable regardless of source formatting or key order.
Verification is constant-time and fails closed: a missing, malformed, or
mismatched digest means the pack content is not trusted.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_bytes(content: dict[str, Any]) -> bytes:
    body = {key: value for key, value in content.items() if key != "digest"}
    return json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def compute_digest(content: dict[str, Any]) -> str:
    """Return the SHA-256 hex digest of ``content`` (excluding its ``digest``)."""
    return hashlib.sha256(_canonical_bytes(content)).hexdigest()


def verify_digest(content: dict[str, Any]) -> bool:
    """Constant-time check that ``content['digest']`` matches the recomputed digest.

    Returns ``False`` (never raises) for a missing or non-string digest, so the
    caller fails closed.
    """
    declared = content.get("digest")
    if not isinstance(declared, str) or not _SHA256_HEX_RE.fullmatch(declared):
        return False
    return hmac.compare_digest(declared, compute_digest(content))
