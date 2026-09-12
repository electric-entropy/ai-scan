"""Shared core domain types: confidence status, severity, and finding skeleton.

These are the schema-v2 domain types used by the future `run` path. Confidence
(`FindingStatus`) and `Severity` are orthogonal axes — a suspected lead may be
critical without being a confirmed critical vulnerability. They are introduced
here without touching report v1 (see ``docs/architecture/migration-policy.md``).
"""

from __future__ import annotations

import enum
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from ai_scan.core.errors import ValidationError


class FindingStatus(enum.StrEnum):
    """Mode-independent confidence state of a finding (schema v2)."""

    CONFIRMED = "confirmed"
    LIKELY = "likely"
    SUSPECTED = "suspected"
    NOT_OBSERVED = "not_observed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    NOT_TESTED = "not_tested"


class Severity(enum.StrEnum):
    """Impact severity, independent of confidence/status."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class DeterminismClass(enum.StrEnum):
    """How a validator signal was produced (per plan §5.4)."""

    DETERMINISTIC = "deterministic"
    STATISTICAL = "statistical"
    HEURISTIC = "heuristic"
    JUDGE = "judge"


class PackTrust(enum.StrEnum):
    """Trust provenance required for an attack pack to run (safety invariant 12)."""

    BUILTIN = "builtin"
    SIGNED = "signed"
    LOCAL_APPROVED = "local_approved"


@dataclass(frozen=True)
class Finding:
    """A minimal, immutable finding skeleton for the schema-v2 surface.

    ``status`` (confidence) and ``severity`` (impact) are stored and serialized
    independently; neither constrains the other.
    """

    id: str
    attack_id: str
    title: str
    status: FindingStatus
    severity: Severity
    summary: str = ""
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for name in ("id", "attack_id", "title"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"Finding.{name} must be a non-empty string")
        if not isinstance(self.summary, str):
            raise ValidationError("Finding.summary must be a string")
        if not isinstance(self.status, FindingStatus):
            raise ValidationError("Finding.status must be a FindingStatus")
        if not isinstance(self.severity, Severity):
            raise ValidationError("Finding.severity must be a Severity")
        # Normalize any accepted iterable of IDs to an immutable, validated tuple.
        raw = self.evidence_ids
        if isinstance(raw, (str, bytes)) or not isinstance(raw, Iterable):
            raise ValidationError("Finding.evidence_ids must be an iterable of id strings")
        normalized = tuple(raw)
        for eid in normalized:
            if not isinstance(eid, str) or not eid.strip():
                raise ValidationError("Finding.evidence_ids entries must be non-empty strings")
        object.__setattr__(self, "evidence_ids", normalized)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "attack_id": self.attack_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "evidence_ids": list(self.evidence_ids),
        }
