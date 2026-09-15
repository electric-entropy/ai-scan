"""Finding classification: one definition of confirmation.

Validators each inspect an :class:`~ai_scan.validation.base.Evidence` and emit a
:class:`~ai_scan.validation.base.Signal` with an explicit *ceiling* — the most
severe :class:`~ai_scan.core.models.FindingStatus` that signal alone can justify.
The :func:`~ai_scan.validation.confidence.classify` engine combines signals
through a documented rules table (never opaque scoring) and enforces the single
confirmation predicate: only a deterministic canary *execution* signal, with a
clean matched control, met repeatability thresholds, and (for state-change
packs) independent read-back + cleanup, reaches ``confirmed``. No reflection,
compliance phrase, self-identification, similarity score, or judge verdict can
confirm on its own.
"""

from __future__ import annotations

from ai_scan.validation.base import Evidence, Signal, Validator, status_rank
from ai_scan.validation.confidence import (
    ClassificationResult,
    GatingContext,
    classify,
)
from ai_scan.validation.controls import ControlValidator, control_blocks_confirmation
from ai_scan.validation.deterministic import ExactCanaryValidator
from ai_scan.validation.judge import JudgeValidator
from ai_scan.validation.reflection import (
    ComplianceHeuristicValidator,
    is_explanatory_mention,
    is_reflection,
)
from ai_scan.validation.state_change import StateChangeValidator
from ai_scan.validation.statistical import RepeatabilityCalculator, SimilarityValidator

__all__ = [
    "ClassificationResult",
    "ComplianceHeuristicValidator",
    "ControlValidator",
    "Evidence",
    "ExactCanaryValidator",
    "GatingContext",
    "JudgeValidator",
    "RepeatabilityCalculator",
    "Signal",
    "SimilarityValidator",
    "StateChangeValidator",
    "Validator",
    "classify",
    "control_blocks_confirmation",
    "is_explanatory_mention",
    "is_reflection",
    "status_rank",
]
