"""Strict, fail-closed schema for declarative attack packs.

:func:`load_pack` validates a pack document against an explicit allowed-field set
and rejects anything ambiguous or unsafe: unknown fields, duplicate JSON keys,
unsupported schema versions, invalid mode/trust/risk/validator enums, malformed
payload shapes, unbounded case counts, missing controls, duplicate family names,
path-traversal-ish ids, and (via the closed field set) arbitrary executable
fields. When ``verify`` is set, the content digest must match or the pack is
rejected — modified pack content is never trusted.

Untrusted pack values are scrubbed through the central redactor before entering
any error message, consistent with the redaction boundary invariant.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ai_scan.core.models import DeterminismClass, PackTrust, Severity
from ai_scan.packs.signatures import verify_digest
from ai_scan.transport import scrub_text

SCHEMA_VERSION = 1
CANARY_MARKER = "{canary}"
_VALID_MODES = frozenset({"reliable", "kitchen-sink"})

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,99}$")
_MAX_FAMILIES = 256
_MAX_TEMPLATES_PER_FAMILY = 64
_MAX_PHYSICAL_REQUESTS_CEILING = 100_000

_ALLOWED_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "id",
        "version",
        "description",
        "trust",
        "modes",
        "risk",
        "required_capabilities",
        "max_physical_requests",
        "validators",
        "trial_policy",
        "side_effects",
        "cleanup",
        "mappings",
        "provenance",
        "families",
        "digest",
    }
)
_REQUIRED_TOP_LEVEL = frozenset(
    {
        "schema_version",
        "id",
        "version",
        "trust",
        "modes",
        "risk",
        "required_capabilities",
        "max_physical_requests",
        "validators",
        "trial_policy",
        "families",
        "digest",
    }
)
_ALLOWED_FAMILY = frozenset({"name", "description", "templates", "controls"})
_ALLOWED_TRIAL = frozenset({"min_attack_trials", "min_successes", "min_control_trials"})
_CAP_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")


class PackError(Exception):
    """Raised when a pack document is malformed, unsafe, or fails digest check."""


@dataclass(frozen=True)
class TrialPolicy:
    """Per-pack trial minima (mirrors the mode policy minima)."""

    min_attack_trials: int
    min_successes: int
    min_control_trials: int


@dataclass(frozen=True)
class PackCase:
    """One attack family: attack templates plus benign control baselines."""

    name: str
    description: str
    templates: tuple[str, ...]
    controls: tuple[str, ...]


@dataclass(frozen=True)
class Pack:
    """A validated, versioned attack pack."""

    schema_version: int
    id: str
    version: str
    description: str
    trust: PackTrust
    modes: frozenset[str]
    risk: Severity
    required_capabilities: frozenset[str]
    max_physical_requests: int
    validators: frozenset[DeterminismClass]
    trial_policy: TrialPolicy
    side_effects: bool
    cleanup: str | None
    mappings: Mapping[str, tuple[str, ...]]
    provenance: Mapping[str, str]
    families: tuple[PackCase, ...]
    digest: str

    def total_attack_cases(self) -> int:
        return sum(len(fam.templates) for fam in self.families)


def _q(value: object) -> str:
    """Scrub an untrusted value for safe inclusion in an error message."""
    raw = str(value)
    scrubbed = scrub_text(raw)
    return "'<redacted>'" if scrubbed != raw else repr(raw)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise PackError(f"duplicate key {_q(key)} in pack document")
        out[key] = value
    return out


def parse_pack_document(text: str, *, verify: bool = True) -> Pack:
    """Parse pack JSON ``text`` (rejecting duplicate keys) and validate it."""
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise PackError(f"pack is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise PackError("pack document must be a JSON object")
    return load_pack(data, verify=verify)


def load_pack(data: dict[str, Any], *, verify: bool = True) -> Pack:
    """Validate a parsed pack ``data`` mapping into a :class:`Pack` (fail closed)."""
    if not isinstance(data, dict):
        raise PackError("pack document must be a JSON object")

    unknown = set(data) - _ALLOWED_TOP_LEVEL
    if unknown:
        # Never echo untrusted field names (they may carry secret-like strings in
        # any format the central scrubber would not catch); report the count only.
        raise PackError(f"unknown pack field(s) not permitted ({len(unknown)} present)")
    missing = _REQUIRED_TOP_LEVEL - set(data)
    if missing:
        raise PackError(f"missing required pack field(s): {', '.join(sorted(missing))}")

    if data["schema_version"] != SCHEMA_VERSION:
        raise PackError(f"unsupported schema_version {_q(data['schema_version'])}")

    pack_id = _require_str(data, "id")
    if not _ID_RE.match(pack_id):
        raise PackError(f"invalid pack id {_q(pack_id)} (lowercase slug, no path separators)")

    trust = _as_enum(data["trust"], PackTrust, "trust")
    risk = _as_enum(data["risk"], Severity, "risk")
    modes = _as_modes(data["modes"])
    validators = _as_validators(data["validators"])
    capabilities = _as_capabilities(data["required_capabilities"])
    trial_policy = _as_trial_policy(data["trial_policy"])
    max_requests = _as_bounded_int(
        data["max_physical_requests"], "max_physical_requests", _MAX_PHYSICAL_REQUESTS_CEILING
    )
    side_effects = _as_bool(data.get("side_effects", False), "side_effects")
    cleanup = _as_opt_str(data.get("cleanup"), "cleanup")
    if side_effects and not cleanup:
        raise PackError("a pack with side_effects must declare a cleanup procedure")
    mappings = _as_mappings(data.get("mappings", {}))
    provenance = _as_provenance(data.get("provenance", {}))
    families = _as_families(data["families"], mappings)

    pack = Pack(
        schema_version=SCHEMA_VERSION,
        id=pack_id,
        version=_require_str(data, "version"),
        description=_as_opt_str(data.get("description"), "description") or "",
        trust=trust,
        modes=modes,
        risk=risk,
        required_capabilities=capabilities,
        max_physical_requests=max_requests,
        validators=validators,
        trial_policy=trial_policy,
        side_effects=side_effects,
        cleanup=cleanup,
        mappings=mappings,
        provenance=provenance,
        families=families,
        digest=_require_str(data, "digest"),
    )

    if pack.total_attack_cases() > pack.max_physical_requests:
        raise PackError(
            "pack declares more attack cases than its max_physical_requests bound"
        )
    if verify and not verify_digest(data):
        raise PackError(f"pack {_q(pack_id)} digest does not match its content")
    return pack


# -- field coercions (each fails closed with a scrubbed message) ----------------

def _require_str(data: Mapping[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise PackError(f"pack field {key!r} must be a non-empty string")
    return value


def _as_opt_str(value: Any, key: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise PackError(f"pack field {key!r} must be a string")
    return value


def _as_bool(value: Any, key: str) -> bool:
    if not isinstance(value, bool):
        raise PackError(f"pack field {key!r} must be a boolean")
    return value


def _as_bounded_int(value: Any, key: str, ceiling: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PackError(f"pack field {key!r} must be an integer")
    if value <= 0:
        raise PackError(f"pack field {key!r} must be positive")
    if value > ceiling:
        raise PackError(f"pack field {key!r} exceeds the maximum of {ceiling}")
    return value


def _as_enum(value: Any, enum_cls: type, key: str) -> Any:
    try:
        return enum_cls(value)
    except (TypeError, ValueError) as exc:
        raise PackError(f"invalid {key} {_q(value)}") from exc


def _as_modes(value: Any) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise PackError("pack field 'modes' must be a non-empty list")
    modes: set[str] = set()
    for item in value:
        if not isinstance(item, str) or item not in _VALID_MODES:
            raise PackError(f"invalid mode {_q(item)}")
        modes.add(item)
    return frozenset(modes)


def _as_validators(value: Any) -> frozenset[DeterminismClass]:
    if not isinstance(value, list) or not value:
        raise PackError("pack field 'validators' must be a non-empty list")
    return frozenset(_as_enum(item, DeterminismClass, "validator") for item in value)


def _as_capabilities(value: Any) -> frozenset[str]:
    if not isinstance(value, list):
        raise PackError("pack field 'required_capabilities' must be a list")
    caps: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not _CAP_RE.match(item):
            raise PackError(f"invalid capability {_q(item)}")
        caps.add(item)
    return frozenset(caps)


def _as_trial_policy(value: Any) -> TrialPolicy:
    if not isinstance(value, dict):
        raise PackError("pack field 'trial_policy' must be an object")
    unknown = set(value) - _ALLOWED_TRIAL
    if unknown:
        raise PackError(
            f"unknown trial_policy field(s) not permitted ({len(unknown)} present)"
        )
    attack = _as_bounded_int(value.get("min_attack_trials"), "min_attack_trials", 10_000)
    successes = _as_bounded_int(value.get("min_successes"), "min_successes", 10_000)
    controls = _as_bounded_int(value.get("min_control_trials"), "min_control_trials", 10_000)
    if successes > attack:
        raise PackError("trial_policy min_successes cannot exceed min_attack_trials")
    return TrialPolicy(
        min_attack_trials=attack, min_successes=successes, min_control_trials=controls
    )


def _as_mappings(value: Any) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise PackError("pack field 'mappings' must be an object")
    out: dict[str, tuple[str, ...]] = {}
    for key, items in value.items():
        if not isinstance(key, str):
            raise PackError("mapping keys must be strings")
        if not isinstance(items, list) or not all(isinstance(i, str) for i in items):
            raise PackError(f"mapping {_q(key)} must be a list of strings")
        out[key] = tuple(items)
    return MappingProxyType(out)


def _as_provenance(value: Any) -> Mapping[str, str]:
    if not isinstance(value, dict):
        raise PackError("pack field 'provenance' must be an object")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise PackError("provenance keys and values must be strings")
        out[key] = item
    return MappingProxyType(out)


def _as_families(value: Any, mappings: Mapping[str, tuple[str, ...]]) -> tuple[PackCase, ...]:
    if not isinstance(value, list) or not value:
        raise PackError("pack field 'families' must be a non-empty list")
    if len(value) > _MAX_FAMILIES:
        raise PackError(f"pack declares more than {_MAX_FAMILIES} families")
    families: list[PackCase] = []
    seen: set[str] = set()
    for raw in value:
        family = _as_family(raw, mappings)
        if family.name in seen:
            raise PackError(f"duplicate family name {_q(family.name)}")
        seen.add(family.name)
        families.append(family)
    return tuple(families)


def _as_family(value: Any, mappings: Mapping[str, tuple[str, ...]]) -> PackCase:
    if not isinstance(value, dict):
        raise PackError("each family must be an object")
    unknown = set(value) - _ALLOWED_FAMILY
    if unknown:
        raise PackError(f"unknown family field(s) not permitted ({len(unknown)} present)")
    name = _require_str(value, "name")
    templates = _as_templates(value.get("templates"), mappings)
    controls = _as_controls(value.get("controls"))
    return PackCase(
        name=name,
        description=_as_opt_str(value.get("description"), "description") or "",
        templates=templates,
        controls=controls,
    )


def _as_templates(value: Any, mappings: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PackError("family 'templates' must be a non-empty list")
    if len(value) > _MAX_TEMPLATES_PER_FAMILY:
        raise PackError(f"family declares more than {_MAX_TEMPLATES_PER_FAMILY} templates")
    owasp = frozenset(mappings.get("owasp-llm", ()))
    disclosure_pack = "LLM02" in owasp and "LLM01" not in owasp
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PackError("each template must be a non-empty string")
        if disclosure_pack:
            if CANARY_MARKER in item:
                raise PackError(
                    "LLM02 disclosure attack templates must not contain the '{canary}' marker"
                )
        elif CANARY_MARKER not in item:
            raise PackError("each attack template must contain the '{canary}' marker")
        out.append(item)
    return tuple(out)


def _as_controls(value: Any) -> tuple[str, ...]:
    # Controls are mandatory: a pack without a benign baseline cannot measure
    # its own false-positive rate. A control must NOT request the canary.
    if not isinstance(value, list) or not value:
        raise PackError("family 'controls' must be a non-empty list (missing controls)")
    if len(value) > _MAX_TEMPLATES_PER_FAMILY:
        raise PackError(f"family declares more than {_MAX_TEMPLATES_PER_FAMILY} controls")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise PackError("each control must be a non-empty string")
        if CANARY_MARKER in item:
            raise PackError("a control must not request the canary marker")
        out.append(item)
    return tuple(out)
