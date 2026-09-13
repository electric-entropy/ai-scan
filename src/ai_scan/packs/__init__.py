"""Declarative, versioned attack packs with trust-gated, offline resolution.

A pack is metadata-rich and self-describing (id/version, mode eligibility, risk,
required capabilities, case templates + controls, validator IDs, trial policy,
bounds, provenance, and a content digest). Packs are validated with a strict,
fail-closed schema and a content digest so a modified or malformed pack is
rejected before any case runs; the registry resolves packs deterministically and
entirely offline, gated by the run's trust set and mode.
"""

from __future__ import annotations

from ai_scan.packs.registry import (
    PackResolutionError,
    available_packs,
    load_builtin_pack,
    resolve_packs,
)
from ai_scan.packs.schema import (
    Pack,
    PackCase,
    PackError,
    TrialPolicy,
    load_pack,
    parse_pack_document,
)
from ai_scan.packs.signatures import compute_digest, verify_digest

__all__ = [
    "Pack",
    "PackCase",
    "PackError",
    "PackResolutionError",
    "TrialPolicy",
    "available_packs",
    "compute_digest",
    "load_builtin_pack",
    "load_pack",
    "parse_pack_document",
    "resolve_packs",
    "verify_digest",
]
