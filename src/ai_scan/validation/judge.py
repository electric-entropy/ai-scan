"""Model-judge validation — a weak signal, capped at ``suspected``.

A judge verdict is advisory only: it can never, on its own, confirm a finding.
The verdict is injected (no model call happens here), and the model/config
provenance is recorded on the signal so a reviewer can see what produced it.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_scan.core.models import DeterminismClass, FindingStatus
from ai_scan.validation.base import Evidence, Signal


@dataclass
class JudgeValidator:
    """Wraps an externally supplied judge verdict (≤ suspected, with provenance)."""

    verdict: bool = False
    model: str = "none"
    config: str = ""
    id = "judge"
    method = DeterminismClass.JUDGE

    def validate(self, evidence: Evidence) -> Signal:
        return Signal(
            validator_id=self.id,
            method=self.method,
            fired=self.verdict,
            ceiling=FindingStatus.SUSPECTED,
            provenance={"model": self.model, "config": self.config},
            detail="judge flagged" if self.verdict else "judge did not flag",
        )
