"""Portable, content-digested, secret-free evidence bundle.

A bundle packages the plan document + digest, optional checkpoint digest/state,
the redacted per-case records (prompt + response evidence + finding), the run
canary and control outcomes, and the evidence graph + its digest — all under a
single content-bound bundle digest. Before export the whole structure is passed
through the central recursive value scrubber, so no raw secret can cross the
boundary. :func:`load_bundle` is fully offline (constructs no transport) and
fails closed on duplicate JSON keys, non-finite numbers, digest mismatch, a
malformed/tampered plan or graph, or any unredacted secret-like value.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ai_scan.evidence_graph.graph import (
    EvidenceGraph,
    GraphError,
    Observation,
    build_graph,
    validate_graph,
)
from ai_scan.orchestration.planner import Plan, PlanError, load_plan, plan_to_dict
from ai_scan.packs.signatures import compute_digest, verify_digest
from ai_scan.transport import scrub_structure

BUNDLE_VERSION = 1
_TOOL = "ai-scan"
_TOP_LEVEL_KEYS = frozenset(
    {
        "bundle_version",
        "metadata",
        "plan",
        "plan_digest",
        "checkpoint",
        "canary",
        "control_results",
        "coverage_gaps",
        "records",
        "graph",
        "graph_digest",
        "digest",
    }
)
class BundleError(Exception):
    """Raised when a bundle is malformed, tampered, or not secret-free."""


@dataclass(frozen=True)
class CaseRecord:
    """One completed case's redacted evidence (prompt + response + finding)."""

    case_id: str
    pack_id: str
    family: str
    kind: str
    prompt: str
    body: str
    status: int
    redirected: bool
    truncated: bool
    transport_ok: bool
    finding_status: str
    proof: str | None = None
    attack_trials: int = 1
    successes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "pack_id": self.pack_id,
            "family": self.family,
            "kind": self.kind,
            "prompt": self.prompt,
            "response": {
                "body": self.body,
                "status": self.status,
                "redirected": self.redirected,
                "truncated": self.truncated,
                "transport_ok": self.transport_ok,
            },
            # Trial metadata lets replay re-verify confirmation at the real plan
            # thresholds (never inferred as 1/1).
            "finding": {
                "status": self.finding_status,
                "proof": self.proof,
                "attack_trials": self.attack_trials,
                "successes": self.successes,
            },
        }


@dataclass(frozen=True)
class Bundle:
    """An immutable, verified evidence bundle."""

    content: Mapping[str, Any]

    @property
    def digest(self) -> str:
        return str(self.content["digest"])

    @property
    def records(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.content["records"]]

    @property
    def canary(self) -> str:
        return str(self.content["canary"])

    @property
    def control_results(self) -> dict[str, bool]:
        return {str(k): bool(v) for k, v in self.content["control_results"].items()}

    def plan(self) -> Plan:
        return load_plan(self.content["plan"])


def _family_key(pack_id: str, family: str) -> str:
    return f"{pack_id}:{family}"


def build_bundle(
    *,
    plan: Plan,
    records: Sequence[CaseRecord],
    canary: str,
    control_results: Mapping[str, bool],
    run_id: str,
    checkpoint_digest: str | None = None,
    checkpoint_state: str | None = None,
    tool_version: str = "0.1.0",
    provenance: Mapping[str, str] | None = None,
    coverage_gaps: Sequence[str] = (),
    known_secrets: frozenset[str] = frozenset(),
) -> Bundle:
    """Assemble a secret-free, digested bundle from a completed run's evidence.

    ``known_secrets`` are the transport-known secret literals observed during the
    run (e.g. ``ExchangeOutcome.known_secrets``). They are threaded into the final
    recursive scrub so a secret that is not globally pattern-shaped still cannot
    cross the export boundary.
    """
    observations = [
        Observation(
            case_id=r.case_id,
            status=r.finding_status,
            proof=r.proof,
            control_succeeded=control_results.get(_family_key(r.pack_id, r.family), False),
        )
        for r in records
    ]
    graph = build_graph(plan=plan, run_id=run_id, observations=observations)

    content: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "metadata": {
            "tool": _TOOL,
            "version": tool_version,
            "run_id": run_id,
            "provenance": dict(provenance or {}),
        },
        "plan": plan_to_dict(plan),
        "plan_digest": plan.digest,
        "checkpoint": (
            {"digest": checkpoint_digest, "state": checkpoint_state}
            if checkpoint_digest is not None
            else None
        ),
        "canary": canary,
        "control_results": dict(control_results),
        "coverage_gaps": list(coverage_gaps),
        "records": [r.to_dict() for r in records],
        "graph": graph.to_canonical(),
        "graph_digest": graph.digest(),
    }
    # Final recursive value scrub before the content is sealed/exported. The
    # run's transport-known secrets are passed alongside the global patterns so
    # non-pattern-shaped secrets are redacted too. Scrub happens BEFORE the
    # digest is computed, so the digest seals the redacted content.
    scrubbed = scrub_structure(content, known_secrets)
    scrubbed["digest"] = compute_digest(scrubbed)
    return Bundle(content=scrubbed)


class BundleCollector:
    """Accumulates per-case evidence as a run's ``observer``, then builds a bundle.

    Usable directly as ``run_plan(..., observer=collector.observe)``; it imports
    nothing from the runner, so there is no cycle. Control outcomes are derived
    from the collected control evidence itself.
    """

    def __init__(self) -> None:
        self._records: list[CaseRecord] = []
        self._known_secrets: set[str] = set()

    def observe(self, case: Any, outcome: Any, finding: Any) -> None:
        status = finding.status
        # Aggregate every outcome's transport-known secrets (control and attack
        # alike) so they can be scrubbed at export. Missing/empty is a no-op.
        self._known_secrets.update(getattr(outcome, "known_secrets", None) or ())
        self._records.append(
            CaseRecord(
                case_id=case.case_id,
                pack_id=case.pack_id,
                family=case.family,
                kind=case.kind,
                prompt=finding.prompt,
                body=outcome.body,
                status=outcome.status,
                redirected=outcome.redirected,
                truncated=outcome.truncated,
                transport_ok=outcome.transport_ok,
                finding_status=status.value if hasattr(status, "value") else str(status),
                proof=finding.proof,
                attack_trials=int(getattr(finding, "attack_trials", 1)),
                successes=int(getattr(finding, "successes", 0)),
            )
        )

    def build(
        self,
        *,
        plan: Plan,
        canary: str,
        run_id: str,
        coverage_gaps: Sequence[str] = (),
        provenance: Mapping[str, str] | None = None,
        known_secrets: frozenset[str] = frozenset(),
    ) -> Bundle:
        control_results: dict[str, bool] = {}
        for record in self._records:
            if record.kind != "control":
                continue
            key = _family_key(record.pack_id, record.family)
            usable = (
                record.transport_ok
                and not record.redirected
                and record.status < 400
                and not record.truncated
            )
            control_results[key] = control_results.get(key, False) or (
                usable and canary in record.body
            )
        return build_bundle(
            plan=plan,
            records=self._records,
            canary=canary,
            control_results=control_results,
            run_id=run_id,
            coverage_gaps=coverage_gaps,
            provenance=provenance,
            # Union the transport-observed secrets with any the caller supplies
            # (e.g. a secret embedded in provenance metadata).
            known_secrets=frozenset(self._known_secrets | set(known_secrets)),
        )


def dump_bundle(bundle: Bundle) -> str:
    """Deterministic JSON rendering of a bundle (stable key order)."""
    return json.dumps(bundle.content, indent=2, sort_keys=True)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise BundleError("duplicate key in bundle document")
        out[key] = value
    return out


def _reject_non_finite(_constant: str) -> float:
    raise BundleError("bundle contains a non-finite number")


def load_bundle(text: str) -> Bundle:
    """Parse and fully verify a bundle offline (no transport), failing closed."""
    try:
        data = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_non_finite
        )
    except json.JSONDecodeError as exc:
        raise BundleError("bundle is not valid JSON") from exc
    if not isinstance(data, dict):
        raise BundleError("bundle must be a JSON object")
    if set(data) != _TOP_LEVEL_KEYS:
        raise BundleError("bundle has unknown or missing top-level fields")
    if data.get("bundle_version") != BUNDLE_VERSION:
        raise BundleError("unsupported or missing bundle_version")
    _validate_metadata(data.get("metadata"))
    _reject_non_finite_numbers(data)

    if not verify_digest(data):
        raise BundleError("bundle digest does not match its content (tampered)")

    # Plan document must itself be valid and its digest must match the field.
    try:
        plan = load_plan(data["plan"])
    except (PlanError, KeyError, TypeError) as exc:
        raise BundleError("bundle carries a malformed plan") from exc
    if data.get("plan_digest") != plan.digest:
        raise BundleError("bundle plan_digest does not match the plan document")

    # Graph must be valid, digest-consistent, AND exactly what a fresh build
    # from the verified plan + records/control observations produces — so a
    # bundle cannot drop graph nodes/edges or a control record and still pass.
    graph = _graph_from_canonical(data.get("graph"))
    try:
        validate_graph(graph)
    except GraphError as exc:
        raise BundleError("bundle graph violates a schema invariant") from exc
    if data.get("graph_digest") != graph.digest():
        raise BundleError("bundle graph_digest does not match the graph")
    records = _validate_records(data.get("records"))
    rebuilt = build_graph(
        plan=plan,
        run_id=_metadata_run_id(data.get("metadata")),
        observations=[
            Observation(
                case_id=str(r["case_id"]),
                status=str(r["finding"]["status"]),
                proof=r["finding"].get("proof"),
                control_succeeded=bool(data["control_results"].get(_record_family_key(r), False)),
            )
            for r in records
        ],
    )
    if rebuilt.to_canonical() != graph.to_canonical() or rebuilt.digest() != graph.digest():
        raise BundleError("bundle graph does not match plan and records")

    # Secret-free boundary: a properly exported bundle is scrub-idempotent.
    if scrub_structure({k: v for k, v in data.items() if k != "digest"}) != {
        k: v for k, v in data.items() if k != "digest"
    }:
        raise BundleError("bundle contains an unredacted secret-like value")

    return Bundle(content=data)


_METADATA_KEYS = frozenset({"tool", "version", "run_id", "provenance"})


def _validate_metadata(raw: Any) -> None:
    """Enforce a closed metadata schema and bind the tool identity/version.

    A tampered bundle cannot smuggle unknown metadata fields, forge a different
    producing tool, or drop the version — each fails closed here (the whole
    document is already digest-bound, so this also rejects a re-digested forge).
    """
    if not isinstance(raw, dict) or set(raw) != _METADATA_KEYS:
        raise BundleError("bundle metadata has unknown or missing fields")
    if raw.get("tool") != _TOOL:
        raise BundleError("bundle metadata names an unexpected tool")
    version = raw.get("version")
    if not isinstance(version, str) or not version:
        raise BundleError("bundle metadata is missing a tool version")
    run_id = raw.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise BundleError("bundle metadata is malformed")
    provenance = raw.get("provenance")
    if not isinstance(provenance, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in provenance.items()
    ):
        raise BundleError("bundle metadata provenance is malformed")


def _metadata_run_id(raw: Any) -> str:
    if not isinstance(raw, dict):
        raise BundleError("bundle metadata is malformed")
    run_id = raw.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        raise BundleError("bundle metadata is malformed")
    return run_id


def _record_family_key(record: Mapping[str, Any]) -> str:
    return _family_key(str(record["pack_id"]), str(record["family"]))


def _validate_records(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise BundleError("bundle records must be a list")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise BundleError("bundle record is malformed")
        required = {"case_id", "pack_id", "family", "kind", "prompt", "response", "finding"}
        if set(item) != required:
            raise BundleError("bundle record has unknown or missing fields")
        string_fields = ("case_id", "pack_id", "family", "kind", "prompt")
        if not all(isinstance(item[k], str) for k in string_fields):
            raise BundleError("bundle record has invalid field types")
        if item["case_id"] in seen:
            raise BundleError("duplicate record id in bundle")
        seen.add(item["case_id"])
        response = item["response"]
        response_fields = {"body", "status", "redirected", "truncated", "transport_ok"}
        if not isinstance(response, dict) or set(response) != response_fields:
            raise BundleError("bundle response record is malformed")
        if (
            not isinstance(response["body"], str)
            or not isinstance(response["status"], int)
            or isinstance(response["status"], bool)
            or not isinstance(response["redirected"], bool)
            or not isinstance(response["truncated"], bool)
            or not isinstance(response["transport_ok"], bool)
        ):
            raise BundleError("bundle response record has invalid field types")
        finding = item["finding"]
        if not isinstance(finding, dict) or set(finding) != {
            "status", "proof", "attack_trials", "successes"
        }:
            raise BundleError("bundle finding record is malformed")
        if not isinstance(finding["status"], str) or not (
            finding["proof"] is None or isinstance(finding["proof"], str)
        ):
            raise BundleError("bundle finding record has invalid field types")
        for count_field in ("attack_trials", "successes"):
            value = finding[count_field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise BundleError("bundle finding trial metadata is invalid")
        records.append(item)
    return records


def _reject_non_finite_numbers(value: Any) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise BundleError("bundle contains a non-finite number")
    if isinstance(value, dict):
        for item in value.values():
            _reject_non_finite_numbers(item)
    elif isinstance(value, list):
        for item in value:
            _reject_non_finite_numbers(item)


def _graph_from_canonical(raw: Any) -> EvidenceGraph:
    from ai_scan.evidence_graph.graph import Edge, Node

    if not isinstance(raw, dict) or "nodes" not in raw or "edges" not in raw:
        raise BundleError("bundle graph is malformed")
    if (
        set(raw) != {"nodes", "edges"}
        or not isinstance(raw["nodes"], list)
        or not isinstance(raw["edges"], list)
    ):
        raise BundleError("bundle graph is malformed")
    nodes_list = []
    edges_list = []
    for n in raw["nodes"]:
        if not isinstance(n, dict) or set(n) != {"id", "type", "attrs"}:
            raise BundleError("bundle graph has malformed nodes")
        if (
            not isinstance(n["id"], str)
            or not isinstance(n["type"], str)
            or not isinstance(n["attrs"], dict)
        ):
            raise BundleError("bundle graph has malformed nodes")
        nodes_list.append(Node(id=n["id"], type=n["type"], attrs=dict(n["attrs"])))
    for e in raw["edges"]:
        if not isinstance(e, dict) or set(e) != {"type", "src", "dst"}:
            raise BundleError("bundle graph has malformed edges")
        if (
            not isinstance(e["type"], str)
            or not isinstance(e["src"], str)
            or not isinstance(e["dst"], str)
        ):
            raise BundleError("bundle graph has malformed edges")
        edges_list.append(Edge(type=e["type"], src=e["src"], dst=e["dst"]))
    nodes = tuple(nodes_list)
    edges = tuple(edges_list)
    return EvidenceGraph(nodes=nodes, edges=edges)
