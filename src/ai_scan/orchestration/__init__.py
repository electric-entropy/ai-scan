"""Offline planning and resumable, deterministic execution.

The planner compiles a target + mode into an inspectable, content-digested
:class:`~ai_scan.orchestration.planner.Plan` — resolving adapter, packs, cases,
controls, and limits entirely offline (no transport). The scheduler orders cases
deterministically (serial for Reliable, seeded/bounded for Kitchen Sink). The
runner executes the plan as a resumable state machine, checkpointing atomically
(secret-free, tamper-rejecting) so a killed run resumes without repeating a
completed physical attempt, records budget exhaustion as structured coverage
gaps, and runs authorized cleanup on cancellation.
"""

from __future__ import annotations

from ai_scan.orchestration.checkpoint import (
    Checkpoint,
    CheckpointError,
    load_checkpoint,
    write_checkpoint_atomic,
)
from ai_scan.orchestration.planner import (
    Plan,
    PlanError,
    PlanLimits,
    PlannedCase,
    compile_plan,
    load_plan,
    plan_to_dict,
    plan_to_json,
)
from ai_scan.orchestration.runner import RunResult, RunState, run_plan
from ai_scan.orchestration.scheduler import Schedule, schedule

__all__ = [
    "Checkpoint",
    "CheckpointError",
    "Plan",
    "PlanError",
    "PlanLimits",
    "PlannedCase",
    "RunResult",
    "RunState",
    "Schedule",
    "compile_plan",
    "load_plan",
    "plan_to_dict",
    "plan_to_json",
    "load_checkpoint",
    "run_plan",
    "schedule",
    "write_checkpoint_atomic",
]
