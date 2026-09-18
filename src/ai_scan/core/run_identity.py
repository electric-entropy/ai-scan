"""One opaque run-identity contract for checkpoints, bundles, and evidence."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


class RunIdentityError(ValueError):
    """Run identity is malformed or does not match its persisted pseudonyms."""


_ABSENT = b"absent"
_PRESENT = b"present\0"


def _commit(plan_digest: str, domain: str, value: str | None) -> str:
    if not isinstance(plan_digest, str) or not plan_digest:
        raise RunIdentityError("run identity requires a plan digest")
    if value is not None and (not isinstance(value, str) or not value):
        raise RunIdentityError("present run identity values must be non-empty strings")
    state = _ABSENT if value is None else _PRESENT + value.encode("utf-8")
    payload = b"ai-scan-run-identity-v1\0" + domain.encode("ascii") + b"\0"
    payload += plan_digest.encode("ascii") + b"\0" + state
    return hashlib.sha256(payload).hexdigest()


def canary_commitment(plan_digest: str, canary: str) -> str:
    return _commit(plan_digest, "canary", canary)


def disclosure_marker_commitment(plan_digest: str, marker: str | None) -> str:
    return _commit(plan_digest, "disclosure-marker", marker)


def evidence_canary(commitment: str) -> str:
    _validate_digest(commitment)
    return f"AISCAN-EVIDENCE-{commitment[:32].upper()}"


def evidence_marker(commitment: str, *, present: bool) -> str | None:
    _validate_digest(commitment)
    return f"AISCAN-DISCLOSURE-{commitment[:32].upper()}" if present else None


def is_evidence_marker(value: str | None) -> bool:
    return isinstance(value, str) and value.startswith("AISCAN-DISCLOSURE-") and len(value) == 50


def _validate_digest(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise RunIdentityError("run identity commitment is malformed")
    return value


@dataclass(frozen=True)
class RunIdentity:
    plan_digest: str
    canary_commitment: str
    disclosure_marker_commitment: str
    canary: str
    disclosure_marker: str | None

    @classmethod
    def create(cls, plan_digest: str, canary: str, marker: str | None) -> RunIdentity:
        canary_binding = canary_commitment(plan_digest, canary)
        marker_binding = disclosure_marker_commitment(plan_digest, marker)
        return cls(
            plan_digest,
            canary_binding,
            marker_binding,
            evidence_canary(canary_binding),
            evidence_marker(marker_binding, present=marker is not None),
        )

    @classmethod
    def verify_persisted(
        cls,
        plan_digest: str,
        canary_binding: object,
        marker_binding: object,
        canary: object,
        marker: object,
    ) -> RunIdentity:
        c = _validate_digest(canary_binding)
        m = _validate_digest(marker_binding)
        if canary != evidence_canary(c):
            raise RunIdentityError("run identity canary pseudonym does not match its commitment")
        if marker is not None and not isinstance(marker, str):
            raise RunIdentityError("run identity disclosure-marker pseudonym is malformed")
        present = marker is not None
        absent_commitment = disclosure_marker_commitment(plan_digest, None)
        if (not present and m != absent_commitment) or (present and m == absent_commitment):
            raise RunIdentityError("run identity disclosure-marker state contradicts commitment")
        if marker != evidence_marker(m, present=present):
            raise RunIdentityError(
                "run identity disclosure-marker pseudonym does not match its commitment"
            )
        return cls(plan_digest, c, m, canary, marker)

    def commitment_fields(self) -> dict[str, str]:
        return {
            "canary_commitment": self.canary_commitment,
            "disclosure_marker_commitment": self.disclosure_marker_commitment,
        }
