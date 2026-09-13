"""Portable, replayable, tamper-evident evidence.

The :mod:`graph` module builds a deterministic, closed-schema provenance DAG
from a plan and per-case observations. :mod:`bundle` packages the plan, redacted
records, findings, and graph into a secret-free, content-digested bundle that
fails closed on any tamper. :mod:`replay` verifies every digest and graph
invariant offline, then reproduces the M7 classification from the stored
redacted evidence — constructing no transport and making no network call.
"""

from __future__ import annotations

from ai_scan.evidence_graph.bundle import (
    Bundle,
    BundleCollector,
    BundleError,
    CaseRecord,
    build_bundle,
    dump_bundle,
    load_bundle,
)
from ai_scan.evidence_graph.graph import (
    EvidenceGraph,
    GraphError,
    Observation,
    build_graph,
    validate_graph,
)
from ai_scan.evidence_graph.replay import ReplayError, ReplayResult, replay_bundle
from ai_scan.evidence_graph.store import ArtifactRef, ArtifactStore, StoreError

__all__ = [
    "Bundle",
    "BundleCollector",
    "BundleError",
    "CaseRecord",
    "EvidenceGraph",
    "GraphError",
    "Observation",
    "ReplayError",
    "ReplayResult",
    "ArtifactRef",
    "ArtifactStore",
    "StoreError",
    "build_bundle",
    "build_graph",
    "dump_bundle",
    "load_bundle",
    "replay_bundle",
    "validate_graph",
]
