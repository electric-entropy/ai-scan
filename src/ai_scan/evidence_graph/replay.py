"""Offline replay: verify a bundle, then reproduce the M7 classification.

:func:`replay_bundle` accepts bundle JSON text, UTF-8 bytes, or an in-memory
:class:`~ai_scan.evidence_graph.bundle.Bundle`. Every form is reduced to the same
immutable JSON snapshot and passes the same full verification (all digests, the
canonical target-bound plan, graph invariants, closed record schema, secret-free
boundary). It then re-derives every record from its persisted per-trial evidence
through the shared evidence contract
(:func:`~ai_scan.orchestration.evidence.verify_records`) — the same derivation a
live run and a resumed checkpoint use — constructing no transport, adapter, or
network call. Any inconsistency fails closed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ai_scan.core.run_identity import RunIdentity
from ai_scan.evidence_graph.bundle import Bundle, BundleError, bundle_snapshot, load_bundle
from ai_scan.orchestration.evidence import (
    CaseEvidence,
    EvidenceError,
    resolve_plan_packs,
    verify_records,
)


class ReplayError(Exception):
    """Raised when a bundle cannot be verified or its findings do not reproduce."""


@dataclass(frozen=True)
class ReplayResult:
    """The outcome of a successful replay."""

    verified: bool
    findings: Mapping[str, str] = field(default_factory=dict)
    coverage_gaps: tuple[str, ...] = field(default_factory=tuple)
    canary: str = ""


def _snapshot_text(source: object) -> str:
    """Reduce any supported input form to immutable bundle JSON text."""
    if isinstance(source, Bundle):
        try:
            return bundle_snapshot(source)
        except BundleError as exc:
            raise ReplayError(str(exc)) from exc
    if isinstance(source, (bytes, bytearray)):
        try:
            return bytes(source).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReplayError("bundle bytes are not valid UTF-8") from exc
    if isinstance(source, str):
        return source
    raise ReplayError("unsupported bundle source: expected JSON text, bytes, or a Bundle")


def replay_bundle(source: str | bytes | Bundle) -> ReplayResult:
    """Verify ``source`` and reproduce its classification offline."""
    text = _snapshot_text(source)
    try:
        bundle = load_bundle(text)
        plan = bundle.plan()
    except BundleError as exc:
        raise ReplayError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - load_bundle already validated
        raise ReplayError("bundle plan is unusable") from exc

    content = bundle.content
    canary = str(content["canary"])
    disclosure_marker = content.get("disclosure_marker")
    identity = RunIdentity.verify_persisted(
        plan.digest,
        content["canary_commitment"],
        content["disclosure_marker_commitment"],
        canary,
        disclosure_marker,
    )
    records = content["records"]
    try:
        verified = verify_records(
            plan,
            resolve_plan_packs(plan),
            canary,
            [
                CaseEvidence(
                    case_id=r["case_id"],
                    kind=r["kind"],
                    status=r["finding"]["status"],
                    proof=r["finding"]["proof"],
                    attack_trials=r["finding"]["attack_trials"],
                    successes=r["finding"]["successes"],
                    trials=r["trials"],
                    pack_id=r["pack_id"],
                    family=r["family"],
                    prompt=r["prompt"],
                )
                for r in records
            ],
            str(disclosure_marker) if disclosure_marker is not None else None,
            identity,
        )
    except EvidenceError as exc:
        raise ReplayError(f"replayed evidence does not match the bundle: {exc}") from exc

    reproduced = {
        str(r["case_id"]): verified.findings[str(r["case_id"])].status.value
        for r in records
        if r["kind"] == "attack"
    }
    return ReplayResult(
        verified=True,
        findings=reproduced,
        coverage_gaps=tuple(str(g) for g in content["coverage_gaps"]),
        canary=canary,
    )
