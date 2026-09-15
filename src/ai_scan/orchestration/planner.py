"""Compile a target + mode into an inspectable, content-digested plan.

:func:`compile_plan` is entirely offline: it resolves the run's policy limits
(:func:`~ai_scan.core.modes.resolve_policy`), the eligible packs (digest-verified
built-ins), and the concrete attack/control cases — constructing no transport
and touching no network. The resulting :class:`Plan` carries a content digest so
a runner can refuse a plan that does not match the plan it was handed, and
:func:`load_plan` rejects a malformed or tampered plan document fail-closed.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ai_scan.core.modes import resolve_policy
from ai_scan.packs import Pack, resolve_packs
from ai_scan.packs.signatures import compute_digest, verify_digest
from ai_scan.targets import Target, TargetError, normalize_target

PLAN_VERSION = 1
_VALID_KINDS = frozenset({"attack", "control"})
_CANARY_MARKER = "{canary}"
_ALLOWED_TOP_LEVEL = frozenset(
    {
        "plan_version",
        "mode",
        "origin",
        "target",
        "adapter",
        "seed",
        "packs",
        "cases",
        "limits",
        "trial_policy",
        "digest",
    }
)


def _canonical_origin(origin: str) -> str:
    """Validate ``origin`` through the target normalizer; it must be canonical."""
    try:
        normalized = normalize_target(origin)
    except TargetError as exc:
        raise PlanError("plan origin is not a valid target origin") from exc
    if normalized.origin != origin or normalized.path or normalized.query:
        raise PlanError("plan origin is not a bare canonical origin")
    return origin


def _canonical_target(url: str, origin: str) -> str:
    """Validate the exact target URL: canonical, and sharing ``origin``.

    The plan binds the *exact* target (scheme/host/port/path/query), not only
    the origin, so a plan compiled for one path cannot be run against another
    path on the same origin.
    """
    try:
        normalized = normalize_target(url)
    except TargetError as exc:
        raise PlanError("plan target is not a valid target URL") from exc
    if normalized.url != url or normalized.origin != origin:
        raise PlanError("plan target is not canonical or does not match the plan origin")
    return url


class PlanError(Exception):
    """Raised when a plan cannot be compiled or is malformed/tampered."""


@dataclass(frozen=True)
class PlanLimits:
    """The budget ceilings compiled from the resolved mode policy."""

    max_physical_requests: int
    max_concurrency: int
    requests_per_second: float
    max_duration_seconds: int

    def __post_init__(self) -> None:
        _require_int(self.max_physical_requests, "max_physical_requests")
        _require_int(self.max_concurrency, "max_concurrency")
        _require_rate(self.requests_per_second, "requests_per_second")
        _require_int(self.max_duration_seconds, "max_duration_seconds")


@dataclass(frozen=True)
class PlannedCase:
    """One concrete unit of work, with a stable, deterministic id."""

    case_id: str
    pack_id: str
    family: str
    index: int
    kind: str  # "attack" | "control"
    template: str

    def __post_init__(self) -> None:
        _require_str(self.case_id, "case_id")
        _require_str(self.pack_id, "pack_id")
        _require_str(self.family, "family")
        _require_int(self.index, "case index", positive=False)
        if self.kind not in _VALID_KINDS:
            raise PlanError("invalid case kind")
        _require_str(self.template, "template")


@dataclass(frozen=True)
class Plan:
    """An inspectable, content-digested execution plan (no secrets)."""

    plan_version: int
    mode: str
    origin: str
    target: str
    adapter: str
    seed: int
    packs: tuple[tuple[str, str, str], ...]  # (id, version, digest)
    cases: tuple[PlannedCase, ...]
    limits: PlanLimits
    trial_policy: tuple[int, int, int]  # (attack, successes, control)
    digest: str

    def __post_init__(self) -> None:
        if self.plan_version != PLAN_VERSION:
            raise PlanError("unsupported plan version")
        if self.mode not in {"reliable", "kitchen-sink"}:
            raise PlanError("invalid plan mode")
        _canonical_origin(_require_str(self.origin, "origin"))
        _canonical_target(_require_str(self.target, "target"), self.origin)
        _require_str(self.adapter, "adapter")
        _require_int(self.seed, "seed", positive=False)
        if not isinstance(self.packs, tuple):
            raise PlanError("packs must be a tuple")
        if not isinstance(self.cases, tuple):
            raise PlanError("cases must be a tuple")
        if not isinstance(self.trial_policy, tuple) or len(self.trial_policy) != 3:
            raise PlanError("trial_policy must be a 3-tuple")
        _require_int(self.trial_policy[0], "minimum_attack_trials")
        _require_int(self.trial_policy[1], "minimum_successes")
        _require_int(self.trial_policy[2], "minimum_control_trials")
        _require_str(self.digest, "digest")

    def attack_cases(self) -> tuple[PlannedCase, ...]:
        return tuple(c for c in self.cases if c.kind == "attack")

    def control_cases(self) -> tuple[PlannedCase, ...]:
        return tuple(c for c in self.cases if c.kind == "control")


def _case_rows(packs: list[Pack]) -> list[PlannedCase]:
    rows: list[PlannedCase] = []
    for pack in packs:
        for family in pack.families:
            for index, template in enumerate(family.templates):
                rows.append(
                    PlannedCase(
                        case_id=f"{pack.id}:{family.name}:attack:{index}",
                        pack_id=pack.id,
                        family=family.name,
                        index=index,
                        kind="attack",
                        template=template,
                    )
                )
            for index, template in enumerate(family.controls):
                rows.append(
                    PlannedCase(
                        case_id=f"{pack.id}:{family.name}:control:{index}",
                        pack_id=pack.id,
                        family=family.name,
                        index=index,
                        kind="control",
                        template=template,
                    )
                )
    return rows


def _plan_body(
    *, mode: str, origin: str, target: str, adapter: str, seed: int,
    packs: list[Pack], cases: list[PlannedCase], limits: PlanLimits,
    trial_policy: tuple[int, int, int],
) -> dict[str, Any]:
    return {
        "plan_version": PLAN_VERSION,
        "mode": mode,
        "origin": origin,
        "target": target,
        "adapter": adapter,
        "seed": seed,
        "packs": [[p.id, p.version, p.digest] for p in packs],
        "cases": [
            [c.case_id, c.pack_id, c.family, c.index, c.kind, c.template] for c in cases
        ],
        "limits": [
            limits.max_physical_requests, limits.max_concurrency,
            limits.requests_per_second, limits.max_duration_seconds,
        ],
        "trial_policy": list(trial_policy),
    }


def compile_plan(
    target: Target,
    mode: str,
    *,
    adapter: str = "generic_http",
    seed: int = 0,
) -> Plan:
    """Compile an offline, digested :class:`Plan` for ``target`` in ``mode``.

    Raises:
        PlanError: If the mode is unknown or packs cannot be resolved. No
            transport is constructed and no network access occurs.
    """
    try:
        policy = resolve_policy(mode)
        packs = resolve_packs(mode, trust=policy.pack_trust)
    except Exception as exc:  # PolicyError / PackResolutionError
        raise PlanError(f"cannot compile plan for mode {mode!r}: {exc}") from exc

    cases = _case_rows(packs)
    limits = PlanLimits(
        max_physical_requests=policy.max_physical_requests,
        max_concurrency=policy.max_concurrency,
        requests_per_second=policy.requests_per_second,
        max_duration_seconds=policy.max_duration_seconds,
    )
    trial_policy = (
        policy.minimum_attack_trials,
        policy.minimum_successes,
        policy.minimum_control_trials,
    )
    body = _plan_body(
        mode=mode, origin=target.origin, target=target.url, adapter=adapter, seed=seed,
        packs=packs, cases=cases, limits=limits, trial_policy=trial_policy,
    )
    digest = compute_digest(body)
    return Plan(
        plan_version=PLAN_VERSION,
        mode=mode,
        origin=target.origin,
        target=target.url,
        adapter=adapter,
        seed=seed,
        packs=tuple((p.id, p.version, p.digest) for p in packs),
        cases=tuple(cases),
        limits=limits,
        trial_policy=trial_policy,
        digest=digest,
    )


def verify_plan_integrity(plan: Plan) -> None:
    """Reject a re-digested plan that does not match its policy/registry values.

    A self-consistent digest only proves the plan has not been *corrupted*; it
    does not prove the plan is the canonical one policy would compile. Here the
    canonical plan for the plan's own ``(mode, origin, adapter, seed)`` is
    recompiled offline and its digest compared: any widened limit, altered case,
    swapped/added/removed pack, or changed trial policy changes the digest and
    is rejected. The adapter must also be a *registered* adapter identifier.
    """
    from ai_scan.adapters.registry import available_adapters

    if plan.adapter not in available_adapters():
        raise PlanError("plan references an unregistered adapter")
    try:
        target = normalize_target(plan.target)
    except TargetError as exc:
        raise PlanError("plan target is not a valid target") from exc
    canonical = compile_plan(target, plan.mode, adapter=plan.adapter, seed=plan.seed)
    if plan.digest != canonical.digest:
        raise PlanError(
            "plan does not match the canonical policy-derived plan for its mode "
            "(re-digested or tampered plan rejected)"
        )


def plan_to_dict(plan: Plan) -> dict[str, Any]:
    """Serialize a plan to a JSON-ready dict (digest included)."""
    body = _plan_body(
        mode=plan.mode, origin=plan.origin, target=plan.target, adapter=plan.adapter,
        seed=plan.seed, packs=[], cases=list(plan.cases), limits=plan.limits,
        trial_policy=plan.trial_policy,
    )
    body["packs"] = [list(p) for p in plan.packs]
    body["digest"] = plan.digest
    return body


def load_plan(data: Mapping[str, Any]) -> Plan:
    """Rebuild and verify a plan from a dict, failing closed on tamper/malformation."""
    if not isinstance(data, dict):
        raise PlanError("plan document must be a JSON object")
    if data.get("plan_version") != PLAN_VERSION:
        raise PlanError("unsupported or missing plan_version")
    # Closed field set: a re-digested document with extra/missing keys is still
    # rejected, so digest validity alone cannot smuggle an out-of-schema plan.
    extra = set(data) - _ALLOWED_TOP_LEVEL
    if extra:
        raise PlanError("plan document has unknown field(s)")
    missing = _ALLOWED_TOP_LEVEL - set(data)
    if missing:
        raise PlanError("plan document is missing required field(s)")
    if not verify_digest(dict(data)):
        raise PlanError("plan digest does not match its content (malformed or tampered)")
    try:
        mode = _require_str(data["mode"], "mode")
        if mode not in {"reliable", "kitchen-sink"}:
            raise PlanError("invalid plan mode")
        origin = _canonical_origin(_require_str(data["origin"], "origin"))
        target = _canonical_target(_require_str(data["target"], "target"), origin)
        adapter = _require_str(data["adapter"], "adapter")
        seed = _require_int(data["seed"], "seed", positive=False)
        limits_raw = _require_sequence(data["limits"], "limits", length=4)
        limits = PlanLimits(
            max_physical_requests=_require_int(limits_raw[0], "max_physical_requests"),
            max_concurrency=_require_int(limits_raw[1], "max_concurrency"),
            requests_per_second=_require_rate(limits_raw[2], "requests_per_second"),
            max_duration_seconds=_require_int(limits_raw[3], "max_duration_seconds"),
        )
        seen: set[str] = set()
        rows = _require_sequence(data["cases"], "cases")
        cases_list: list[PlannedCase] = []
        for raw_row in rows:
            row = _require_sequence(raw_row, "case", length=6)
            case_id = _require_str(row[0], "case_id")
            if case_id in seen:
                raise PlanError("duplicate case_id in plan")
            seen.add(case_id)
            kind = _require_str(row[4], "kind")
            if kind not in _VALID_KINDS:
                raise PlanError("invalid case kind in plan")
            pack_id = _require_str(row[1], "pack_id")
            family = _require_str(row[2], "family")
            index = _require_int(row[3], "case index", positive=False)
            template = _require_str(row[5], "template")
            # case_id must be the canonical compiled shape, so a row cannot be
            # re-pointed at a different pack/family/kind/index than its id claims.
            if case_id != f"{pack_id}:{family}:{kind}:{index}":
                raise PlanError("case_id is inconsistent with its pack/family/kind/index")
            # Attack templates must carry the prompt marker; controls must not.
            if kind == "attack" and _CANARY_MARKER not in template:
                raise PlanError("attack case template is missing the canary marker")
            if kind == "control" and _CANARY_MARKER in template:
                raise PlanError("control case template must not contain the canary marker")
            cases_list.append(
                PlannedCase(
                    case_id=case_id,
                    pack_id=pack_id,
                    family=family,
                    index=index,
                    kind=kind,
                    template=template,
                )
            )
        cases = tuple(cases_list)
        tp = _require_sequence(data["trial_policy"], "trial_policy", length=3)
        packs_list: list[tuple[str, str, str]] = []
        seen_packs: set[str] = set()
        for p in _require_sequence(data["packs"], "packs"):
            prow = _require_sequence(p, "pack", length=3)
            pack_identity = (
                _require_str(prow[0], "pack id"),
                _require_str(prow[1], "pack version"),
                _require_str(prow[2], "pack digest"),
            )
            if pack_identity[0] in seen_packs:
                raise PlanError("duplicate pack identity in plan")
            seen_packs.add(pack_identity[0])
            packs_list.append(pack_identity)
        packs = tuple(packs_list)
        return Plan(
            plan_version=PLAN_VERSION,
            mode=mode,
            origin=origin,
            target=target,
            adapter=adapter,
            seed=seed,
            packs=packs,
            cases=cases,
            limits=limits,
            trial_policy=(
                _require_int(tp[0], "minimum_attack_trials"),
                _require_int(tp[1], "minimum_successes"),
                _require_int(tp[2], "minimum_control_trials"),
            ),
            digest=_require_str(data["digest"], "digest"),
        )
    except (KeyError, IndexError, TypeError, ValueError, PlanError) as exc:
        raise PlanError("malformed plan document") from exc


def plan_to_json(plan: Plan) -> str:
    """Deterministic JSON rendering of a plan (stable key order)."""
    return json.dumps(plan_to_dict(plan), indent=2, sort_keys=True)


def _require_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise PlanError(f"{name} must be a non-empty string")
    return value


def _require_int(value: object, name: str, *, positive: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanError(f"{name} must be an integer")
    if positive and value <= 0:
        raise PlanError(f"{name} must be positive")
    if not positive and value < 0:
        raise PlanError(f"{name} must be non-negative")
    return value


def _require_rate(value: object, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PlanError(f"{name} must be a number")
    out = float(value)
    if not math.isfinite(out) or out <= 0:
        raise PlanError(f"{name} must be positive and finite")
    return out


def _require_sequence(value: object, name: str, *, length: int | None = None) -> list[Any]:
    if not isinstance(value, list):
        raise PlanError(f"{name} must be a list")
    if length is not None and len(value) != length:
        raise PlanError(f"{name} must have {length} item(s)")
    return value
