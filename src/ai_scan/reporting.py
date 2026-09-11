"""Report assembly, atomic persistence, and exit-code mapping.

A :class:`Report` correlates fingerprint and injection results with target and
authorization metadata into a stable, machine-readable JSON document. The
report records *authorization metadata* (client, engagement, mode) but never
the operator's confirmation input. Reports are written atomically so a crash
never leaves a partial file, and the console summary contains no secrets.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from ai_scan.injection import InjectionResult, InjectionStatus
from ai_scan.models import FingerprintResult
from ai_scan.targets import Target

SCHEMA_VERSION = "1.0"
TOOL_NAME = "ai-scan"

EXIT_OK = 0
EXIT_CONFIRMED_FINDING = 3
EXIT_INCONCLUSIVE = 4


@dataclass
class Report:
    """A complete, serializable assessment report."""

    target_origin: str
    authorization: dict[str, Any]
    fingerprint: FingerprintResult | None
    injection: InjectionResult | None
    request_budget: dict[str, Any]
    evidence: list[dict[str, Any]]
    created_at: str

    @classmethod
    def build(
        cls,
        *,
        target: Target,
        authorization: dict[str, Any],
        fingerprint: FingerprintResult | None,
        injection: InjectionResult | None,
        request_budget: dict[str, Any],
        evidence: list[dict[str, Any]] | None = None,
        created_at: str | None = None,
    ) -> Report:
        """Assemble a report, sanitizing authorization metadata."""
        return cls(
            target_origin=target.origin,
            authorization=_safe_authorization(authorization),
            fingerprint=fingerprint,
            injection=injection,
            request_budget=request_budget,
            evidence=evidence or [],
            created_at=created_at or datetime.now(UTC).isoformat(),
        )

    def findings(self) -> list[dict[str, Any]]:
        """Confirmed/potential injection findings promoted to the top level."""
        if self.injection is None:
            return []
        return [
            f.to_dict()
            for f in self.injection.findings
            if f.status in (InjectionStatus.CONFIRMED, InjectionStatus.POTENTIAL)
        ]

    def to_dict(self) -> dict[str, Any]:
        """Return the stable, machine-readable report document."""
        return {
            "tool": TOOL_NAME,
            "schema_version": SCHEMA_VERSION,
            "target_origin": self.target_origin,
            "authorization": self.authorization,
            "created_at": self.created_at,
            "request_budget": self.request_budget,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "injection": self.injection.to_dict() if self.injection else None,
            "evidence": self.evidence,
            "findings": self.findings(),
        }

    def console_summary(self) -> str:
        """A short, secret-free human summary for the terminal."""
        lines = [
            f"target: {self.target_origin}",
            f"authorization: client={self.authorization.get('client', '?')} "
            f"engagement={self.authorization.get('engagement', '?')} "
            f"mode={self.authorization.get('mode', '?')}",
        ]
        if self.fingerprint is not None:
            if self.fingerprint.top is not None:
                lines.append(
                    f"fingerprint: {self.fingerprint.top.family} "
                    f"(score={self.fingerprint.top.score:.2f}, heuristic)"
                )
            else:
                lines.append("fingerprint: unknown (heuristic)")
        if self.injection is not None:
            confirmed = sum(
                1
                for f in self.injection.findings
                if f.status == InjectionStatus.CONFIRMED
            )
            lines.append(
                f"injection: status={self.injection.status.value} "
                f"confirmed={confirmed} requests={self.injection.request_count}"
            )
        return "\n".join(lines)


def _safe_authorization(auth: dict[str, Any]) -> dict[str, Any]:
    """Keep only non-sensitive authorization metadata; never the confirmation."""
    allowed = ("client", "engagement", "mode", "receipt_origin", "expires", "created_at")
    return {k: auth[k] for k in allowed if k in auth}


def exit_code_for(report: Report) -> int:
    """Map a report to the tool's process exit code.

    ``3`` if any injection finding is confirmed; ``4`` if the assessment was
    inconclusive (the injection run was inconclusive, or the fingerprint could
    not obtain a usable response); otherwise ``0``. A non-usable transport
    outcome therefore never silently produces a clean ``0``.
    """
    injection = report.injection
    fingerprint = report.fingerprint

    if injection is not None and injection.status == InjectionStatus.CONFIRMED:
        return EXIT_CONFIRMED_FINDING
    if injection is not None and injection.status == InjectionStatus.INCONCLUSIVE:
        return EXIT_INCONCLUSIVE
    if fingerprint is not None and fingerprint.inconclusive:
        return EXIT_INCONCLUSIVE
    return EXIT_OK


def write_report_atomic(report: Report, path: str) -> None:
    """Write ``report`` to ``path`` atomically (temp file + rename)."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    payload = json.dumps(report.to_dict(), indent=2, sort_keys=True)

    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".ai-scan-report-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
