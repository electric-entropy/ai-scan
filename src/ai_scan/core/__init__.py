"""Shared core domain for the AI-Scan platform.

Milestone 1 introduces transport-free domain types (status/severity/finding),
immutable mode policies with tightening-only override resolution, a small error
hierarchy, and stable-ID helpers. No network or engine code lives here.
"""

from __future__ import annotations

from ai_scan.core.errors import AiScanError, PolicyError, ValidationError
from ai_scan.core.ids import attempt_id, content_id
from ai_scan.core.models import (
    DeterminismClass,
    Finding,
    FindingStatus,
    PackTrust,
    Severity,
)
from ai_scan.core.modes import (
    ModePolicy,
    PolicyOverrides,
    kitchen_sink_policy,
    reliable_policy,
    resolve_policy,
)

__all__ = [
    "AiScanError",
    "DeterminismClass",
    "Finding",
    "FindingStatus",
    "ModePolicy",
    "PackTrust",
    "PolicyError",
    "PolicyOverrides",
    "Severity",
    "ValidationError",
    "attempt_id",
    "content_id",
    "kitchen_sink_policy",
    "reliable_policy",
    "resolve_policy",
]
