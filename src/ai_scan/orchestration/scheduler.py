"""Deterministic case scheduling.

Reliable mode schedules attack cases serially in a stable, sorted order. Kitchen
Sink mode uses a *seeded* permutation (so a given plan always yields the same
order) and carries the bounded concurrency limit from the plan. Scheduling is
pure and offline — it only reorders the plan's already-compiled cases.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from ai_scan.orchestration.planner import Plan, PlannedCase


@dataclass(frozen=True)
class Schedule:
    """An ordered set of attack cases plus the concurrency bound to honor."""

    order: tuple[PlannedCase, ...]
    max_concurrency: int


def schedule(plan: Plan) -> Schedule:
    """Return the deterministic execution order of ``plan``'s attack cases."""
    attacks = list(plan.attack_cases())
    if plan.mode == "kitchen-sink":
        # Seeded permutation: deterministic for a given plan, but broader/varied
        # coverage ordering than the strict Reliable sort.
        rng = random.Random(plan.seed)
        ordered = sorted(attacks, key=lambda c: c.case_id)
        rng.shuffle(ordered)
        concurrency = max(1, plan.limits.max_concurrency)
    else:
        # Reliable: strict, serial, fully deterministic ordering.
        ordered = sorted(attacks, key=lambda c: c.case_id)
        concurrency = 1
    return Schedule(order=tuple(ordered), max_concurrency=concurrency)
