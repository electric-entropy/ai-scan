"""Milestone 1: immutable ModePolicy resolution with tightening-only overrides.

Overrides may only tighten; there is no grant-based widening. ModePolicy
validates all structural invariants on construction.
"""

from __future__ import annotations

import dataclasses
import math

import pytest

from ai_scan.core.errors import PolicyError
from ai_scan.core.models import FindingStatus, PackTrust, Severity
from ai_scan.core.modes import (
    ModePolicy,
    PolicyOverrides,
    reliable_policy,
    resolve_policy,
)


def test_reliable_defaults_are_conservative() -> None:
    p = resolve_policy("reliable")
    assert p.name == "reliable"
    assert p.requests_per_second == 2.0
    assert p.max_physical_requests == 256
    assert p.max_duration_seconds == 1800
    assert p.max_concurrency == 1
    assert p.include_experimental is False
    assert p.allow_adaptive_generation is False
    assert p.minimum_attack_trials == 3
    assert p.minimum_successes == 2
    assert p.minimum_control_trials == 2
    assert p.promote_statuses == frozenset({FindingStatus.CONFIRMED})
    assert p.pack_trust == frozenset({PackTrust.BUILTIN})
    assert p.require_deterministic_confirmation is True


def test_kitchen_sink_broadens_but_keeps_deterministic_confirmation() -> None:
    p = resolve_policy("kitchen-sink")
    assert p.name == "kitchen-sink"
    assert p.include_experimental is True
    assert p.allow_adaptive_generation is True
    assert p.max_physical_requests == 2000
    assert p.requests_per_second == 5.0
    assert p.max_duration_seconds == 7200
    assert p.require_deterministic_confirmation is True


def test_both_modes_share_the_same_confirmation_predicate() -> None:
    r = resolve_policy("reliable")
    k = resolve_policy("kitchen-sink")
    predicate = ("require_deterministic_confirmation", "minimum_attack_trials",
                 "minimum_successes", "minimum_control_trials", "promote_statuses")
    assert all(getattr(r, f) == getattr(k, f) for f in predicate)


def test_policy_is_immutable() -> None:
    p = resolve_policy("reliable")
    assert isinstance(p, ModePolicy)
    with pytest.raises(dataclasses.FrozenInstanceError):
        p.max_physical_requests = 9999  # type: ignore[misc]


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(PolicyError):
        resolve_policy("yolo")


# --- tightening-only overrides ------------------------------------------------


def test_override_may_tighten_budget() -> None:
    p = resolve_policy("reliable", PolicyOverrides(max_physical_requests=100))
    assert p.max_physical_requests == 100


def test_unauthorized_override_cannot_increase_budget() -> None:
    p = resolve_policy("reliable", PolicyOverrides(max_physical_requests=100_000))
    assert p.max_physical_requests == 256  # clamped to base


def test_unauthorized_override_cannot_raise_rate_duration_concurrency() -> None:
    p = resolve_policy(
        "reliable",
        PolicyOverrides(
            requests_per_second=1000.0, max_duration_seconds=10**9, max_concurrency=999
        ),
    )
    assert p.requests_per_second == 2.0
    assert p.max_duration_seconds == 1800
    assert p.max_concurrency == 1


def test_unauthorized_override_cannot_enable_experimental() -> None:
    p = resolve_policy("reliable", PolicyOverrides(include_experimental=True))
    assert p.include_experimental is False


def test_override_can_disable_kitchen_sink_experimental() -> None:
    # Turning a capability off is tightening and is allowed.
    p = resolve_policy("kitchen-sink", PolicyOverrides(include_experimental=False))
    assert p.include_experimental is False


def test_unauthorized_override_cannot_disable_deterministic_confirmation() -> None:
    p = resolve_policy("reliable", PolicyOverrides(require_deterministic_confirmation=False))
    assert p.require_deterministic_confirmation is True


def test_unauthorized_override_cannot_add_promoted_status() -> None:
    requested = frozenset({FindingStatus.CONFIRMED, FindingStatus.LIKELY})
    p = resolve_policy("reliable", PolicyOverrides(promote_statuses=requested))
    assert p.promote_statuses == frozenset({FindingStatus.CONFIRMED})


def test_override_may_narrow_promoted_statuses() -> None:
    p = resolve_policy("reliable", PolicyOverrides(promote_statuses=frozenset()))
    assert p.promote_statuses == frozenset()


def test_override_minimums_can_only_increase() -> None:
    raised = resolve_policy("reliable", PolicyOverrides(minimum_attack_trials=10))
    assert raised.minimum_attack_trials == 10
    lowered = resolve_policy("reliable", PolicyOverrides(minimum_attack_trials=1))
    assert lowered.minimum_attack_trials == 3


@pytest.mark.parametrize(
    "field_name",
    ["minimum_attack_trials", "minimum_successes", "minimum_control_trials"],
)
def test_zero_confirmation_minimum_override_is_rejected(field_name: str) -> None:
    with pytest.raises(PolicyError):
        resolve_policy(
            "reliable", PolicyOverrides(**{field_name: 0})  # type: ignore[arg-type]
        )


# --- invalid numeric override inputs are rejected ----------------------------


@pytest.mark.parametrize("bad", [0, -1, -1000])
@pytest.mark.parametrize(
    "field_name", ["max_physical_requests", "max_duration_seconds", "max_concurrency"]
)
def test_nonpositive_int_override_is_rejected(field_name: str, bad: int) -> None:
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(**{field_name: bad}))


@pytest.mark.parametrize("bad", [0.0, -1.0, math.nan, math.inf, -math.inf])
def test_invalid_rps_override_is_rejected(bad: float) -> None:
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(requests_per_second=bad))


@pytest.mark.parametrize(
    "field_name", ["max_physical_requests", "max_duration_seconds", "max_concurrency"]
)
def test_fractional_int_override_is_rejected(field_name: str) -> None:
    # A float for an integer budget must be rejected, never silently truncated.
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(**{field_name: 2.5}))


def test_resolved_policy_always_has_positive_budgets() -> None:
    p = resolve_policy(
        "reliable",
        PolicyOverrides(
            max_physical_requests=1,
            requests_per_second=0.1,
            max_duration_seconds=1,
            max_concurrency=1,
        ),
    )
    assert p.max_physical_requests == 1
    assert p.requests_per_second == 0.1
    assert p.max_duration_seconds == 1
    assert p.max_concurrency == 1


# --- invalid override types are rejected, not coerced/intersected-away -------


@pytest.mark.parametrize(
    "field_name", ["include_experimental", "allow_adaptive_generation",
                   "require_deterministic_confirmation"],
)
@pytest.mark.parametrize("bad", ["no", "", 1, 0, [], object()])
def test_non_bool_capability_override_is_rejected(field_name: str, bad: object) -> None:
    with pytest.raises(PolicyError):
        resolve_policy("kitchen-sink", PolicyOverrides(**{field_name: bad}))


@pytest.mark.parametrize("field_name", ["promote_statuses", "pack_trust"])
def test_mutable_set_override_is_rejected(field_name: str) -> None:
    member = FindingStatus.CONFIRMED if field_name == "promote_statuses" else PackTrust.BUILTIN
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(**{field_name: {member}}))  # plain set
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(**{field_name: [member]}))  # list


def test_promote_statuses_override_with_wrong_enum_is_rejected() -> None:
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(promote_statuses=frozenset({Severity.HIGH})))


def test_pack_trust_override_with_wrong_member_is_rejected() -> None:
    with pytest.raises(PolicyError):
        resolve_policy("reliable", PolicyOverrides(pack_trust=frozenset({"builtin"})))


def test_valid_bool_and_frozenset_overrides_still_work() -> None:
    p = resolve_policy(
        "kitchen-sink",
        PolicyOverrides(
            include_experimental=False,
            promote_statuses=frozenset({FindingStatus.CONFIRMED}),
            pack_trust=frozenset({PackTrust.BUILTIN}),
        ),
    )
    assert p.include_experimental is False
    assert p.promote_statuses == frozenset({FindingStatus.CONFIRMED})
    assert p.pack_trust == frozenset({PackTrust.BUILTIN})


# --- ModePolicy construction invariants (backstop) ---------------------------


def _valid_kwargs() -> dict:
    base = reliable_policy()
    return {f.name: getattr(base, f.name) for f in dataclasses.fields(base)}


def test_direct_construction_rejects_disabled_deterministic_confirmation() -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "require_deterministic_confirmation": False})


def test_direct_construction_rejects_zero_negative_limits() -> None:
    for name in ("max_physical_requests", "max_duration_seconds", "max_concurrency"):
        with pytest.raises(PolicyError):
            ModePolicy(**{**_valid_kwargs(), name: 0})
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "requests_per_second": -1.0})


@pytest.mark.parametrize("bad", [math.nan, math.inf])
def test_direct_construction_rejects_nonfinite_rate(bad: float) -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "requests_per_second": bad})


def test_direct_construction_rejects_bool_for_int_limit() -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "max_physical_requests": True})


def test_direct_construction_rejects_fractional_int_limit() -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "max_concurrency": 2.5})


def test_direct_construction_rejects_mutable_set_collections() -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "pack_trust": {PackTrust.BUILTIN}})  # plain set
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "promote_statuses": {FindingStatus.CONFIRMED}})


def test_direct_construction_rejects_wrong_enum_members() -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "promote_statuses": frozenset({Severity.HIGH})})
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "pack_trust": frozenset({"builtin"})})


def test_direct_construction_rejects_successes_exceeding_attack_trials() -> None:
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), "minimum_attack_trials": 2, "minimum_successes": 3})


@pytest.mark.parametrize(
    "field_name",
    ["minimum_attack_trials", "minimum_successes", "minimum_control_trials"],
)
def test_direct_construction_rejects_zero_confirmation_minima(field_name: str) -> None:
    # A zero minimum would permit confirmation without an attack success or
    # matched control, contradicting the shared Reliable confirmation predicate.
    with pytest.raises(PolicyError):
        ModePolicy(**{**_valid_kwargs(), field_name: 0})


def test_replace_revalidates() -> None:
    base = resolve_policy("reliable")
    with pytest.raises(PolicyError):
        dataclasses.replace(base, max_physical_requests=0)
    with pytest.raises(PolicyError):
        dataclasses.replace(base, requests_per_second=math.inf)
