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
from dataclasses import dataclass, field
from typing import Any

from ai_scan.evidence_graph.graph import (
    EvidenceGraph,
    GraphError,
    Observation,
    build_graph,
    validate_graph,
)
from ai_scan.injection import CONTROL_EMITTED, ExchangeOutcome, InjectionStatus
from ai_scan.orchestration.evidence import (
    CaseEvidence,
    EvidenceError,
    VerifiedEvidence,
    derive_records,
    resolve_plan_packs,
    trial_to_dict,
    verify_records,
)
from ai_scan.orchestration.planner import (
    Plan,
    PlanError,
    load_plan,
    plan_to_dict,
    verify_plan_integrity,
)
from ai_scan.packs.signatures import compute_digest, verify_digest
from ai_scan.transport import scrub_structure

# v2: every record persists all of its physical trials, control coverage is the
# tri-state derived result, and the physical request count is bound. v1 bundles
# (one representative response per case) cannot substantiate repeatability.
BUNDLE_VERSION = 2
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
        "request_count",
        "records",
        "graph",
        "graph_digest",
        "digest",
    }
)
_RECORD_KEYS = frozenset({"case_id", "pack_id", "family", "kind", "prompt", "trials", "finding"})
_FINDING_KEYS = frozenset({"status", "proof", "attack_trials", "successes"})


class BundleError(Exception):
    """Raised when a bundle is malformed, tampered, or not secret-free."""


@dataclass(frozen=True)
class CaseRecord:
    """One completed case's redacted evidence (prompt + every trial + finding)."""

    case_id: str
    pack_id: str
    family: str
    kind: str
    prompt: str
    trials: tuple[ExchangeOutcome, ...]
    finding_status: str
    proof: str | None = None
    attack_trials: int = 0
    successes: int = 0
    known_secrets: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "pack_id": self.pack_id,
            "family": self.family,
            "kind": self.kind,
            "prompt": self.prompt,
            # Every physical trial is persisted so replay re-derives status,
            # repeatability, controls and physical counts (never inferred).
            "trials": [trial_to_dict(t) for t in self.trials],
            "finding": {
                "status": self.finding_status,
                "proof": self.proof,
                "attack_trials": self.attack_trials,
                "successes": self.successes,
            },
        }


class Bundle:
    """An immutable snapshot of a bundle document.

    The content is serialized once, at construction, into canonical JSON; every
    accessor returns a fresh copy. Mutating the source mapping or a returned
    value can never change the bundle, and :func:`replay_bundle` always re-parses
    and fully re-verifies the snapshot (a ``Bundle`` is not proof of validity).
    """

    __slots__ = ("_text",)

    def __init__(self, content: Mapping[str, Any]) -> None:
        try:
            text = json.dumps(content, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise BundleError("bundle content is not a finite JSON document") from exc
        object.__setattr__(self, "_text", text)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Bundle is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Bundle is immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Bundle):
            return NotImplemented
        return bundle_snapshot(self) == bundle_snapshot(other)

    def __hash__(self) -> int:
        return hash(bundle_snapshot(self))

    def __repr__(self) -> str:
        return f"Bundle(digest={self.digest!r})"

    def _data(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(bundle_snapshot(self))
        return data

    @property
    def content(self) -> dict[str, Any]:
        return self._data()

    @property
    def digest(self) -> str:
        return str(self._data().get("digest"))

    @property
    def records(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._data()["records"]]

    @property
    def canary(self) -> str:
        return str(self._data()["canary"])

    @property
    def control_results(self) -> dict[str, str]:
        return {str(k): str(v) for k, v in self._data()["control_results"].items()}

    def plan(self) -> Plan:
        return load_plan(self._data()["plan"])


_TEXT_SLOT = Bundle.__dict__["_text"]


def bundle_snapshot(bundle: Bundle) -> str:
    """The immutable canonical JSON a :class:`Bundle` was constructed from.

    Read through the base-class slot, so a subclass cannot substitute content by
    overriding accessors.
    """
    text = _TEXT_SLOT.__get__(bundle, Bundle)
    if not isinstance(text, str):
        raise BundleError("bundle snapshot is unavailable")
    return text


def _family_key(pack_id: str, family: str) -> str:
    return f"{pack_id}:{family}"


def _case_evidence(records: Sequence[Mapping[str, Any]]) -> list[CaseEvidence]:
    return [
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
    ]


def _graph_for(
    plan: Plan, run_id: str, records: Sequence[Mapping[str, Any]], verified: VerifiedEvidence
) -> EvidenceGraph:
    return build_graph(
        plan=plan,
        run_id=run_id,
        observations=[
            Observation(
                case_id=str(r["case_id"]),
                status=str(r["finding"]["status"]),
                proof=r["finding"]["proof"],
                control_succeeded=verified.control_results.get(
                    _family_key(str(r["pack_id"]), str(r["family"]))
                ) == CONTROL_EMITTED,
            )
            for r in records
        ],
    )


def build_bundle(
    *,
    plan: Plan,
    records: Sequence[CaseRecord],
    canary: str,
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
    cross the export boundary. The redacted evidence is then classified through
    the shared evidence contract: control coverage and the physical request count
    are derived, each proof is re-derived from the redacted trials, and a run
    whose recorded statuses do not re-derive from its own evidence is refused.
    """
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
        "coverage_gaps": list(coverage_gaps),
        "records": [r.to_dict() for r in records],
    }
    secrets = frozenset(known_secrets).union(*(r.known_secrets for r in records))
    # Scrub BEFORE deriving and digesting, so the digest seals — and replay
    # re-derives from — exactly the redacted evidence that is exported.
    scrubbed: dict[str, Any] = scrub_structure(content, secrets)
    try:
        packs = resolve_plan_packs(plan)
        evidence = _case_evidence(scrubbed["records"])
        verified = derive_records(plan, packs, scrubbed["canary"], evidence)
    except (EvidenceError, KeyError, TypeError) as exc:
        raise BundleError(f"run evidence does not satisfy the evidence contract: {exc}") from exc
    for record in scrubbed["records"]:
        derived = verified.findings[record["case_id"]]
        finding = record["finding"]
        if (
            finding["status"] != derived.status.value
            or finding["attack_trials"] != derived.attack_trials
            or finding["successes"] != derived.successes
        ):
            raise BundleError("recorded finding does not re-derive from its trial evidence")
        finding["proof"] = derived.proof
    scrubbed["control_results"] = dict(sorted(verified.control_results.items()))
    scrubbed["request_count"] = verified.physical_request_count
    graph = _graph_for(plan, run_id, scrubbed["records"], verified)
    scrubbed["graph"] = graph.to_canonical()
    scrubbed["graph_digest"] = graph.digest()
    sealed: dict[str, Any] = scrub_structure(scrubbed, secrets)
    sealed["digest"] = compute_digest(sealed)
    return Bundle(content=sealed)


class BundleCollector:
    """Accumulates per-case evidence as a run's ``observer``, then builds a bundle.

    Usable directly as ``run_plan(..., observer=collector.observe)``; it imports
    nothing from the runner, so there is no cycle. Each record persists every
    physical trial carried on the finding; control coverage and physical counts
    are derived from that evidence at build time.
    """

    def __init__(self) -> None:
        self._records: list[CaseRecord] = []
        self._known_secrets: set[str] = set()

    def observe(self, case: Any, outcome: Any, finding: Any) -> None:
        status = finding.status
        trials = tuple(getattr(finding, "evidence", ()) or (outcome,))
        # Aggregate every trial's transport-known secrets (control and attack
        # alike) so they can be scrubbed at export. Missing/empty is a no-op.
        for trial in (*trials, outcome):
            self._known_secrets.update(getattr(trial, "known_secrets", None) or ())
        self._records.append(
            CaseRecord(
                case_id=case.case_id,
                pack_id=case.pack_id,
                family=case.family,
                kind=case.kind,
                prompt=finding.prompt,
                trials=trials,
                finding_status=status.value if isinstance(status, InjectionStatus) else str(status),
                proof=finding.proof,
                attack_trials=int(getattr(finding, "attack_trials", 0)),
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
        return build_bundle(
            plan=plan,
            records=self._records,
            canary=canary,
            run_id=run_id,
            coverage_gaps=coverage_gaps,
            provenance=provenance,
            # Union the transport-observed secrets with any the caller supplies
            # (e.g. a secret embedded in provenance metadata).
            known_secrets=frozenset(self._known_secrets | set(known_secrets)),
        )


def dump_bundle(bundle: Bundle) -> str:
    """Deterministic JSON rendering of a bundle (stable key order)."""
    return json.dumps(json.loads(bundle_snapshot(bundle)), indent=2, sort_keys=True)


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
    if not isinstance(text, str):
        raise BundleError("bundle document must be JSON text")
    try:
        data = json.loads(
            text, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_non_finite
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise BundleError("bundle is not valid JSON") from exc
    if not isinstance(data, dict):
        raise BundleError("bundle must be a JSON object")
    if data.get("bundle_version") != BUNDLE_VERSION:
        raise BundleError("unsupported or missing bundle_version")
    if set(data) != _TOP_LEVEL_KEYS:
        raise BundleError("bundle has unknown or missing top-level fields")
    _validate_metadata(data.get("metadata"))
    _reject_non_finite_numbers(data)

    if not verify_digest(data):
        raise BundleError("bundle digest does not match its content (tampered)")

    # Plan document must be valid, digest-consistent, AND the canonical plan
    # policy compiles for its exact target/mode/adapter/seed — a re-digested plan
    # with weakened trial thresholds or altered cases is rejected.
    try:
        plan = load_plan(data["plan"])
        verify_plan_integrity(plan)
    except (PlanError, KeyError, TypeError) as exc:
        raise BundleError("bundle carries a malformed or non-canonical plan") from exc
    if data.get("plan_digest") != plan.digest:
        raise BundleError("bundle plan_digest does not match the plan document")
    canary = data.get("canary")
    if not isinstance(canary, str) or not canary:
        raise BundleError("bundle canary is malformed")
    _validate_coverage_gaps(data.get("coverage_gaps"))
    _validate_checkpoint_ref(data.get("checkpoint"))

    # Every record must re-derive from its own persisted trials under the shared
    # evidence contract (plan binding, repeatability, matched clean controls).
    records = _validate_records(data.get("records"))
    try:
        verified = verify_records(
            plan, resolve_plan_packs(plan), canary, _case_evidence(records)
        )
    except EvidenceError as exc:
        raise BundleError(f"bundle evidence is invalid: {exc}") from exc
    if data.get("control_results") != dict(verified.control_results):
        raise BundleError("bundle control_results do not match the control evidence")
    request_count = data.get("request_count")
    if (
        isinstance(request_count, bool)
        or not isinstance(request_count, int)
        or request_count != verified.physical_request_count
        or request_count > plan.limits.max_physical_requests
    ):
        raise BundleError("bundle request_count does not match the persisted trial attempts")

    # Graph must be valid, digest-consistent, AND exactly what a fresh build
    # from the verified plan + records/derived controls produces — so a bundle
    # cannot drop graph nodes/edges or a control record and still pass.
    graph = _graph_from_canonical(data.get("graph"))
    try:
        validate_graph(graph)
    except GraphError as exc:
        raise BundleError("bundle graph violates a schema invariant") from exc
    if data.get("graph_digest") != graph.digest():
        raise BundleError("bundle graph_digest does not match the graph")
    try:
        rebuilt = _graph_for(plan, _metadata_run_id(data.get("metadata")), records, verified)
    except GraphError as exc:
        raise BundleError("bundle graph cannot be rebuilt from plan and records") from exc
    if rebuilt.to_canonical() != graph.to_canonical() or rebuilt.digest() != graph.digest():
        raise BundleError("bundle graph does not match plan and records")

    # Secret-free boundary: a properly exported bundle is scrub-idempotent.
    if scrub_structure({k: v for k, v in data.items() if k != "digest"}) != {
        k: v for k, v in data.items() if k != "digest"
    }:
        raise BundleError("bundle contains an unredacted secret-like value")

    return Bundle(content=data)


def _validate_coverage_gaps(raw: Any) -> None:
    if not isinstance(raw, list) or not all(isinstance(g, str) for g in raw):
        raise BundleError("bundle coverage_gaps must be a list of strings")


def _validate_checkpoint_ref(raw: Any) -> None:
    if raw is None:
        return
    if (
        not isinstance(raw, dict)
        or set(raw) != {"digest", "state"}
        or not isinstance(raw["digest"], str)
        or not (raw["state"] is None or isinstance(raw["state"], str))
    ):
        raise BundleError("bundle checkpoint reference is malformed")


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


def _validate_records(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise BundleError("bundle records must be a list")
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) != _RECORD_KEYS:
            raise BundleError("bundle record has unknown or missing fields")
        string_fields = ("case_id", "pack_id", "family", "kind", "prompt")
        if not all(isinstance(item[k], str) for k in string_fields):
            raise BundleError("bundle record has invalid field types")
        if item["case_id"] in seen:
            raise BundleError("duplicate record id in bundle")
        seen.add(item["case_id"])
        if not isinstance(item["trials"], list):
            raise BundleError("bundle record trials must be a list")
        finding = item["finding"]
        if not isinstance(finding, dict) or set(finding) != _FINDING_KEYS:
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
