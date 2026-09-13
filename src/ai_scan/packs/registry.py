"""Offline, trust-gated, deterministic pack resolution.

Only an explicit allowlist of built-in packs can be loaded (no path, traversal,
or external file), each validated and digest-checked on load. Resolution for a
run is deterministic (sorted by pack id) and entirely offline: a pack is
selected only when it is eligible for the run's mode, its trust is within the
run's allowed trust set, and its required capabilities are a subset of those
available (capability intersection). Nothing here performs network I/O.
"""

from __future__ import annotations

from importlib import resources

from ai_scan.core.models import PackTrust
from ai_scan.packs.schema import Pack, PackError, parse_pack_document
from ai_scan.transport import scrub_text

# Allowlisted built-in packs: id → packaged filename. Membership here is the
# only way a pack loads, so no untrusted id can reach the filesystem.
_BUILTIN: dict[str, str] = {
    "direct-injection-reliable": "direct-injection-reliable-v1.json",
    "direct-injection-kitchen": "direct-injection-kitchen-v1.json",
    "indirect-injection-reliable": "indirect-injection-reliable-v1.json",
    "indirect-injection-kitchen": "indirect-injection-kitchen-v1.json",
    "rag-isolation-reliable": "rag-isolation-reliable-v1.json",
    "rag-isolation-kitchen": "rag-isolation-kitchen-v1.json",
    "tool-abuse-reliable": "tool-abuse-reliable-v1.json",
    "tool-abuse-kitchen": "tool-abuse-kitchen-v1.json",
}

_VALID_MODES = frozenset({"reliable", "kitchen-sink"})


class PackResolutionError(Exception):
    """Raised when packs cannot be resolved (unknown id, digest/validation, mode)."""


def available_packs() -> list[str]:
    """All built-in pack ids (offline discovery, sorted)."""
    return sorted(_BUILTIN)


def load_builtin_pack(pack_id: str) -> Pack:
    """Load, validate, and digest-verify a single built-in pack (fail closed)."""
    if pack_id not in _BUILTIN:
        raise PackResolutionError(f"unknown built-in pack {scrub_text(str(pack_id))!r}")
    resource = resources.files("ai_scan.packs.builtin").joinpath(_BUILTIN[pack_id])
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        raise PackResolutionError(f"built-in pack {pack_id!r} is missing") from exc
    try:
        pack = parse_pack_document(text, verify=True)
    except PackError as exc:
        raise PackResolutionError(f"built-in pack {pack_id!r} failed validation: {exc}") from exc
    if pack.trust is not PackTrust.BUILTIN:
        raise PackResolutionError(f"built-in pack {pack_id!r} must declare builtin trust")
    if pack.id != pack_id:
        raise PackResolutionError(f"built-in pack {pack_id!r} declares a mismatched id")
    return pack


def resolve_packs(
    mode: str,
    *,
    trust: frozenset[PackTrust] = frozenset({PackTrust.BUILTIN}),
    capabilities: frozenset[str] = frozenset(),
) -> list[Pack]:
    """Resolve the ordered list of packs eligible for ``mode`` under ``trust``.

    Selection is deterministic (by pack id) and offline. A pack qualifies when it
    is eligible for ``mode``, its trust is in ``trust``, and its required
    capabilities are a subset of ``capabilities``.

    Raises:
        PackResolutionError: For an invalid mode or when nothing resolves.
    """
    if mode not in _VALID_MODES:
        raise PackResolutionError(f"unknown mode {scrub_text(str(mode))!r}")
    resolved: list[Pack] = []
    for pack_id in available_packs():
        pack = load_builtin_pack(pack_id)
        if mode not in pack.modes:
            continue
        if pack.trust not in trust:
            continue
        if not pack.required_capabilities <= capabilities:
            continue
        resolved.append(pack)
    if not resolved:
        raise PackResolutionError(f"no packs resolve for mode {scrub_text(str(mode))!r}")
    return resolved
