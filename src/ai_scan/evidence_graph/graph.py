"""Deterministic, closed-schema evidence provenance graph.

Nodes and edges use stable, content-derived ids so the same inputs always
serialize to byte-identical canonical JSON and the same digest. The graph is a
DAG; :func:`validate_graph` fails closed on unknown node/edge types, duplicate
ids, dangling edges, cycles, or invalid enum attributes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ai_scan.core.models import Severity
from ai_scan.injection import InjectionStatus
from ai_scan.orchestration.planner import Plan
from ai_scan.packs.signatures import compute_digest

NODE_TYPES = frozenset(
    {"target", "plan", "run", "pack", "case", "request", "response", "finding", "control"}
)
EDGE_TYPES = frozenset(
    {
        "target_plan",
        "plan_pack",
        "pack_case",
        "case_request",
        "case_response",
        "response_finding",
        "control_gate",
        "run_case",
    }
)
_VALID_MODES = frozenset({"reliable", "kitchen-sink"})
_VALID_STATUSES = frozenset(s.value for s in InjectionStatus)
_VALID_SEVERITIES = frozenset(s.value for s in Severity)
_VALID_KINDS = frozenset({"attack", "control"})


class GraphError(Exception):
    """Raised when a graph is malformed or violates a closed-schema invariant."""


@dataclass(frozen=True)
class Observation:
    """A completed case's classification result (no raw response here)."""

    case_id: str
    status: str
    proof: str | None = None
    control_succeeded: bool = False


@dataclass(frozen=True)
class Node:
    id: str
    type: str
    attrs: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Edge:
    type: str
    src: str
    dst: str


@dataclass(frozen=True)
class EvidenceGraph:
    """An immutable provenance graph with a deterministic canonical form."""

    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]

    def to_canonical(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"id": n.id, "type": n.type, "attrs": dict(n.attrs)}
                for n in sorted(self.nodes, key=lambda n: n.id)
            ],
            "edges": [
                {"type": e.type, "src": e.src, "dst": e.dst}
                for e in sorted(self.edges, key=lambda e: (e.type, e.src, e.dst))
            ],
        }

    def digest(self) -> str:
        return compute_digest(self.to_canonical())


def build_graph(
    *,
    plan: Plan,
    run_id: str,
    observations: Sequence[Observation],
) -> EvidenceGraph:
    """Build the provenance graph for the completed ``observations`` of ``plan``."""
    by_case = {o.case_id: o for o in observations}
    if len(by_case) != len(observations):
        raise GraphError("duplicate case_id in observations")
    case_index = {c.case_id: c for c in plan.cases}
    control_families = {
        (c.pack_id, c.family) for c in plan.cases if c.kind == "control"
    }

    nodes: dict[str, Node] = {}
    edges: list[Edge] = []

    target_id = f"target:{plan.origin}"
    plan_id = f"plan:{plan.digest}"
    run_node = f"run:{run_id}"
    nodes[target_id] = Node(target_id, "target", {"origin": plan.origin})
    nodes[plan_id] = Node(plan_id, "plan", {"mode": plan.mode, "digest": plan.digest})
    nodes[run_node] = Node(run_node, "run", {"run_id": run_id})
    edges.append(Edge("target_plan", target_id, plan_id))

    for pack_id, version, pdigest in plan.packs:
        pack_node = f"pack:{pack_id}"
        nodes[pack_node] = Node(pack_node, "pack", {"version": version, "digest": pdigest})
        edges.append(Edge("plan_pack", plan_id, pack_node))

    for case_id, obs in sorted(by_case.items()):
        case = case_index.get(case_id)
        if case is None:
            raise GraphError("observation references a case not in the plan")
        pack_node = f"pack:{case.pack_id}"
        if pack_node not in nodes:
            raise GraphError("case references a pack not in the plan")
        case_node = f"case:{case_id}"
        nodes[case_node] = Node(case_node, "case", {"kind": case.kind, "family": case.family})
        edges.append(Edge("pack_case", pack_node, case_node))
        edges.append(Edge("run_case", run_node, case_node))

        request_node = f"request:{case_id}"
        response_node = f"response:{case_id}"
        nodes[request_node] = Node(request_node, "request", {})
        nodes[response_node] = Node(response_node, "response", {})
        edges.append(Edge("case_request", case_node, request_node))
        edges.append(Edge("case_response", case_node, response_node))

        if case.kind == "control":
            control_node = f"control:{case.pack_id}:{case.family}"
            nodes.setdefault(
                control_node,
                Node(control_node, "control", {"succeeded": obs.control_succeeded}),
            )
            continue

        finding_node = f"finding:{case_id}"
        nodes[finding_node] = Node(finding_node, "finding", {"status": obs.status})
        edges.append(Edge("response_finding", response_node, finding_node))
        # If the family has a control, record the gating edge control → finding
        # regardless of case iteration order or whether that control succeeded.
        control_node = f"control:{case.pack_id}:{case.family}"
        if obs.control_succeeded or (case.pack_id, case.family) in control_families:
            nodes.setdefault(
                control_node,
                Node(control_node, "control", {"succeeded": obs.control_succeeded}),
            )
            edges.append(Edge("control_gate", control_node, finding_node))

    graph = EvidenceGraph(nodes=tuple(nodes.values()), edges=tuple(edges))
    validate_graph(graph)
    return graph


def validate_graph(graph: EvidenceGraph) -> None:
    """Enforce the closed-schema, acyclic invariants (fail closed)."""
    ids: set[str] = set()
    for node in graph.nodes:
        if node.type not in NODE_TYPES:
            raise GraphError(f"unknown node type {node.type!r}")
        if node.id in ids:
            raise GraphError("duplicate node id")
        ids.add(node.id)
        _validate_attrs(node)

    adjacency: dict[str, list[str]] = {node_id: [] for node_id in ids}
    for edge in graph.edges:
        if edge.type not in EDGE_TYPES:
            raise GraphError(f"unknown edge type {edge.type!r}")
        if edge.src not in ids or edge.dst not in ids:
            raise GraphError("edge references a missing node (dangling edge)")
        adjacency[edge.src].append(edge.dst)

    _require_acyclic(adjacency)


def _validate_attrs(node: Node) -> None:
    if node.type == "plan" and node.attrs.get("mode") not in _VALID_MODES:
        raise GraphError("invalid mode on plan node")
    if node.type == "case" and node.attrs.get("kind") not in _VALID_KINDS:
        raise GraphError("invalid kind on case node")
    if node.type == "finding":
        if node.attrs.get("status") not in _VALID_STATUSES:
            raise GraphError("invalid status on finding node")
        severity = node.attrs.get("severity")
        if severity is not None and severity not in _VALID_SEVERITIES:
            raise GraphError("invalid severity on finding node")


def _require_acyclic(adjacency: dict[str, list[str]]) -> None:
    visiting, done = set(), set()

    def walk(node_id: str) -> None:
        if node_id in done:
            return
        if node_id in visiting:
            raise GraphError("graph contains a cycle")
        visiting.add(node_id)
        for nxt in adjacency[node_id]:
            walk(nxt)
        visiting.discard(node_id)
        done.add(node_id)

    for node_id in adjacency:
        walk(node_id)
