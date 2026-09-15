"""Immutable mode policies and tightening-only override resolution.

A :class:`ModePolicy` captures the *entire* resolved policy for a run as explicit
fields, so the rest of the engine never needs ``if mode == ...`` checks — it
reads the resolved policy. Two base policies exist, ``reliable`` and
``kitchen-sink``; both share the same confirmation predicate (safety invariant 5:
Kitchen Sink broadens technique *selection*, never confirmation rigor or limits).

Overrides may only **tighten** a policy: lower budgets, higher confirmation
minimums, a narrower promoted-status set, capabilities turned off. A looser value
is clamped to the base — there is **no** mechanism to widen a mode's ceilings.
``ModePolicy`` validates its own invariants on construction, so an invalid policy
can never exist.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal, TypeVar

from ai_scan.core.errors import PolicyError
from ai_scan.core.models import FindingStatus, PackTrust

ModeName = Literal["reliable", "kitchen-sink"]
_VALID_MODES = ("reliable", "kitchen-sink")
_SetItem = TypeVar("_SetItem")


def _check_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise PolicyError(f"{name} must be positive, got {value!r}")


def _check_positive_rate(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PolicyError(f"{name} must be a number, got {type(value).__name__}")
    if not math.isfinite(value):
        raise PolicyError(f"{name} must be finite, got {value!r}")
    if value <= 0:
        raise PolicyError(f"{name} must be positive, got {value!r}")


def _check_frozenset(name: str, value: object, member_type: type) -> None:
    if type(value) is not frozenset:
        raise PolicyError(f"{name} must be a frozenset, got {type(value).__name__}")
    for item in value:
        if not isinstance(item, member_type):
            raise PolicyError(f"{name} members must be {member_type.__name__}")


@dataclass(frozen=True)
class ModePolicy:
    """The complete, immutable resolved policy for a run.

    Validates all structural invariants on construction (including via
    ``dataclasses.replace``), so no zero/negative/non-finite/fractional/bool
    limit, wrong-typed or mutable collection, disabled deterministic
    confirmation, or inconsistent minima can ever be represented.
    """

    name: ModeName
    pack_trust: frozenset[PackTrust]
    include_experimental: bool
    allow_adaptive_generation: bool
    minimum_attack_trials: int
    minimum_successes: int
    minimum_control_trials: int
    promote_statuses: frozenset[FindingStatus]
    requests_per_second: float
    max_physical_requests: int
    max_duration_seconds: int
    max_concurrency: int
    require_deterministic_confirmation: bool = True

    def __post_init__(self) -> None:
        if self.name not in _VALID_MODES:
            raise PolicyError(f"Unknown mode name {self.name!r}")
        # Deterministic confirmation is a non-disableable safety invariant.
        if self.require_deterministic_confirmation is not True:
            raise PolicyError("require_deterministic_confirmation must be True")
        for flag in ("include_experimental", "allow_adaptive_generation"):
            if getattr(self, flag) is not True and getattr(self, flag) is not False:
                raise PolicyError(f"{flag} must be a bool")
        _check_positive_rate("requests_per_second", self.requests_per_second)
        _check_positive_int("max_physical_requests", self.max_physical_requests)
        _check_positive_int("max_duration_seconds", self.max_duration_seconds)
        _check_positive_int("max_concurrency", self.max_concurrency)
        _check_positive_int("minimum_attack_trials", self.minimum_attack_trials)
        _check_positive_int("minimum_successes", self.minimum_successes)
        _check_positive_int("minimum_control_trials", self.minimum_control_trials)
        if self.minimum_successes > self.minimum_attack_trials:
            raise PolicyError(
                "minimum_successes cannot exceed minimum_attack_trials "
                f"({self.minimum_successes} > {self.minimum_attack_trials})"
            )
        _check_frozenset("pack_trust", self.pack_trust, PackTrust)
        _check_frozenset("promote_statuses", self.promote_statuses, FindingStatus)


@dataclass(frozen=True)
class PolicyOverrides:
    """Operator-supplied overrides. ``None`` means "leave at the policy default".

    Overrides can only make a policy stricter. Looser numeric values are clamped
    to the base during resolution; a set override is intersected with the base;
    a capability can only be turned off. Nothing here can loosen a policy.
    """

    requests_per_second: float | None = None
    max_physical_requests: int | None = None
    max_duration_seconds: int | None = None
    max_concurrency: int | None = None
    include_experimental: bool | None = None
    allow_adaptive_generation: bool | None = None
    minimum_attack_trials: int | None = None
    minimum_successes: int | None = None
    minimum_control_trials: int | None = None
    promote_statuses: frozenset[FindingStatus] | None = None
    require_deterministic_confirmation: bool | None = None
    pack_trust: frozenset[PackTrust] | None = None


def reliable_policy() -> ModePolicy:
    """Conservative, low-false-positive defaults for consulting/CI use."""
    return ModePolicy(
        name="reliable",
        pack_trust=frozenset({PackTrust.BUILTIN}),
        include_experimental=False,
        allow_adaptive_generation=False,
        minimum_attack_trials=3,
        minimum_successes=2,
        minimum_control_trials=2,
        promote_statuses=frozenset({FindingStatus.CONFIRMED}),
        requests_per_second=2.0,
        max_physical_requests=256,
        max_duration_seconds=1800,
        max_concurrency=1,
        require_deterministic_confirmation=True,
    )


def kitchen_sink_policy() -> ModePolicy:
    """Broad technique coverage; identical confirmation rigor to reliable."""
    return ModePolicy(
        name="kitchen-sink",
        pack_trust=frozenset({PackTrust.BUILTIN}),
        include_experimental=True,
        allow_adaptive_generation=True,
        # Same confirmation predicate as reliable — only selection broadens.
        minimum_attack_trials=3,
        minimum_successes=2,
        minimum_control_trials=2,
        promote_statuses=frozenset({FindingStatus.CONFIRMED}),
        requests_per_second=5.0,
        max_physical_requests=2000,
        max_duration_seconds=7200,
        max_concurrency=4,
        require_deterministic_confirmation=True,
    )


_BASE_POLICIES = {
    "reliable": reliable_policy,
    "kitchen-sink": kitchen_sink_policy,
}


def resolve_policy(mode: str, overrides: PolicyOverrides | None = None) -> ModePolicy:
    """Resolve the effective policy for ``mode`` under tightening-only overrides.

    Raises:
        PolicyError: If ``mode`` is unknown, or an override would produce an
            invalid policy (caught by :class:`ModePolicy` construction).
    """
    if mode not in _BASE_POLICIES:
        raise PolicyError(f"Unknown mode {mode!r}; expected one of {sorted(_BASE_POLICIES)}.")
    base = _BASE_POLICIES[mode]()
    ov = overrides or PolicyOverrides()
    _validate_overrides(ov)

    return ModePolicy(
        name=base.name,
        pack_trust=_narrow_set(base.pack_trust, ov.pack_trust),
        include_experimental=_capability_off_only(
            base.include_experimental, ov.include_experimental
        ),
        allow_adaptive_generation=_capability_off_only(
            base.allow_adaptive_generation, ov.allow_adaptive_generation
        ),
        minimum_attack_trials=_raise_only(base.minimum_attack_trials, ov.minimum_attack_trials),
        minimum_successes=_raise_only(base.minimum_successes, ov.minimum_successes),
        minimum_control_trials=_raise_only(base.minimum_control_trials, ov.minimum_control_trials),
        promote_statuses=_narrow_set(base.promote_statuses, ov.promote_statuses),
        requests_per_second=_clamp(base.requests_per_second, ov.requests_per_second),
        max_physical_requests=_clamp(base.max_physical_requests, ov.max_physical_requests),
        max_duration_seconds=_clamp(base.max_duration_seconds, ov.max_duration_seconds),
        max_concurrency=_clamp(base.max_concurrency, ov.max_concurrency),
        # Never disableable, by any override.
        require_deterministic_confirmation=True,
    )


def _validate_overrides(ov: PolicyOverrides) -> None:
    """Reject a provided override value that is itself invalid, before clamping.

    A too-large (but valid, finite, positive) budget is left for the clamp to
    pull down to the base; but a non-positive, non-finite, bool, or fractional
    value is rejected outright so rejection is consistent regardless of the base.
    """
    if ov.requests_per_second is not None:
        _check_positive_rate("override requests_per_second", ov.requests_per_second)
    if ov.max_physical_requests is not None:
        _check_positive_int("override max_physical_requests", ov.max_physical_requests)
    if ov.max_duration_seconds is not None:
        _check_positive_int("override max_duration_seconds", ov.max_duration_seconds)
    if ov.max_concurrency is not None:
        _check_positive_int("override max_concurrency", ov.max_concurrency)
    for name in ("minimum_attack_trials", "minimum_successes", "minimum_control_trials"):
        value = getattr(ov, name)
        if value is not None:
            _check_positive_int(f"override {name}", value)
    for name in (
        "include_experimental",
        "allow_adaptive_generation",
        "require_deterministic_confirmation",
    ):
        value = getattr(ov, name)
        if value is not None and not isinstance(value, bool):
            raise PolicyError(
                f"override {name} must be a bool or None, got {type(value).__name__}"
            )
    if ov.promote_statuses is not None:
        _check_frozenset("override promote_statuses", ov.promote_statuses, FindingStatus)
    if ov.pack_trust is not None:
        _check_frozenset("override pack_trust", ov.pack_trust, PackTrust)


_Num = TypeVar("_Num", int, float)


def _clamp(base_value: _Num, override: _Num | None) -> _Num:
    """Resolve a budget: default to base; a looser override clamps to base.

    Type is preserved so that a fractional/bool override survives to
    :class:`ModePolicy` validation and is rejected there rather than silently
    coerced.
    """
    if override is None:
        return base_value
    try:
        return min(override, base_value)
    except TypeError:
        # Wrong-typed override (e.g. a str); surface it through policy validation.
        return override


def _raise_only(base_value: int, override: int | None) -> int:
    """Resolve a confirmation minimum: overrides may only raise it."""
    if override is None:
        return base_value
    try:
        return max(base_value, override)
    except TypeError:
        return override


def _capability_off_only(base_on: bool, override: bool | None) -> bool:
    """Resolve a boolean capability: it can be turned off but never on."""
    requested = base_on if override is None else override
    return bool(requested) and base_on


def _narrow_set(
    base: frozenset[_SetItem], override: frozenset[_SetItem] | None
) -> frozenset[_SetItem]:
    """Resolve a set field: an override may only narrow it (intersection)."""
    if override is None:
        return base
    return frozenset(override) & base
