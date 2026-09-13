"""State-change validation — fail-closed, no-op unless explicitly supported.

A state-change finding (the target performed a side-effecting action) can only
be confirmed with independent corroboration: a read-back that observes the
change *and* verified cleanup. Until an adapter/pack explicitly supports this,
the validator is a no-op that never fires, so nothing can be confirmed by a
side effect the tool cannot independently verify.
"""

from __future__ import annotations

from dataclasses import dataclass

from ai_scan.core.models import DeterminismClass, FindingStatus
from ai_scan.validation.base import Evidence, Signal


@dataclass
class StateChangeValidator:
    """Confirms a state change only with read-back + cleanup evidence."""

    enabled: bool = False
    id = "state_change"
    method = DeterminismClass.DETERMINISTIC

    def validate(self, evidence: Evidence) -> Signal:
        if not self.enabled:
            return Signal(
                validator_id=self.id,
                method=self.method,
                fired=False,
                ceiling=FindingStatus.NOT_OBSERVED,
                detail="state-change validation not supported for this run",
            )
        corroborated = evidence.readback_confirmed and evidence.cleanup_confirmed
        return Signal(
            validator_id=self.id,
            method=self.method,
            fired=corroborated,
            ceiling=FindingStatus.CONFIRMED,
            detail=(
                "read-back + cleanup corroborated"
                if corroborated
                else "no independent corroboration"
            ),
        )
