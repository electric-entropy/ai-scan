"""Stable content IDs and unique attempt IDs.

``content_id`` is canonical over an **explicitly supported JSON domain** and
rejects anything outside it, so IDs are deterministic and collision-safe:

* containers: only ``dict`` (with ``str`` keys) and ``list`` — no tuples or sets
  (a set has no stable order; a tuple would alias a list);
* scalars: ``str``, ``bool``, ``int``, finite ``float``, ``None`` — no
  ``Decimal``/``bytes``/objects (which would otherwise alias a string via
  ``str()``), and no NaN/Infinity (``allow_nan=False``).

Unsupported content raises :class:`ValidationError` rather than being coerced.
Both helpers require a prefix from a narrow namespace grammar, rejecting path,
newline, or spoofing characters.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
from typing import Any

from ai_scan.core.errors import ValidationError

_DIGEST_LEN = 32
_PREFIX_RE = re.compile(r"^[a-z][a-z0-9_]{0,15}$")


def _validate_prefix(prefix: str) -> None:
    if not isinstance(prefix, str) or not _PREFIX_RE.fullmatch(prefix):
        raise ValidationError(
            f"Invalid ID prefix {prefix!r}: must match {_PREFIX_RE.pattern}."
        )


def _assert_json_domain(value: Any, path: str = "$") -> None:
    """Reject anything outside the supported canonical JSON domain."""
    # bool must be checked before int (bool is an int subclass); both are allowed.
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError(f"{path}: non-finite float is not allowed")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _assert_json_domain(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(
                    f"{path}: map keys must be strings, got {type(key).__name__}"
                )
            _assert_json_domain(item, f"{path}.{key}")
        return
    raise ValidationError(f"{path}: unsupported type {type(value).__name__} for content_id")


def content_id(content: Any, *, prefix: str = "cid") -> str:
    """Return a stable ID derived from the canonical form of ``content``.

    Raises:
        ValidationError: If ``prefix`` is not a valid namespace or ``content``
            contains a value outside the supported JSON domain.
    """
    _validate_prefix(prefix)
    _assert_json_domain(content)
    canonical = json.dumps(
        content,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:_DIGEST_LEN]
    return f"{prefix}-{digest}"


def attempt_id(*, prefix: str = "att") -> str:
    """Return a fresh, unique ID for a single physical attempt.

    Raises:
        ValidationError: If ``prefix`` is not a valid namespace.
    """
    _validate_prefix(prefix)
    return f"{prefix}-{secrets.token_hex(8)}"
