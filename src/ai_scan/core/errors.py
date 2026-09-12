"""Core error hierarchy for the AI-Scan platform."""

from __future__ import annotations


class AiScanError(Exception):
    """Base class for all ai-scan core errors."""


class PolicyError(AiScanError):
    """Raised for an invalid mode selection or an invalid/inadmissible policy.

    Overrides may only tighten a resolved policy (a *looser* numeric limit is
    clamped to the base rather than raised). This is raised for an unknown mode
    or for a constructed :class:`~ai_scan.core.modes.ModePolicy` that violates a
    structural invariant (bad type, non-positive/non-finite limit, disabled
    deterministic confirmation, inconsistent minima, …).
    """


class ValidationError(AiScanError):
    """Raised when domain data fails validation (findings, IDs, content IDs)."""


class ConfigError(AiScanError):
    """Raised when a configuration/plan document fails strict loading or schema
    validation (unknown fields, duplicate keys, NaN/Infinity, unsupported schema
    version, invalid/unbounded limits, path traversal, or secret literals)."""
