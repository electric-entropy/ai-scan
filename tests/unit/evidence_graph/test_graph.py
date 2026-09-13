"""Evidence graph: determinism + closed-schema invariants."""

from __future__ import annotations

import pytest

from ai_scan.evidence_graph.graph import (
    Edge,
    EvidenceGraph,
    GraphError,
    Node,
    Observation,
    build_graph,
    validate_graph,
)
from tests.unit.evidence_graph._sample import sample_plan


def _observations(plan) -> list[Observation]:  # type: ignore[no-untyped-def]
    obs = []
    for case in plan.cases:
        status = "confirmed" if case.kind == "attack" else "not_observed"
        obs.append(Observation(case_id=case.case_id, status=status))
    return obs


def test_graph_is_deterministic_and_digest_stable() -> None:
    plan = sample_plan()
    g1 = build_graph(plan=plan, run_id="r1", observations=_observations(plan))
    g2 = build_graph(plan=plan, run_id="r1", observations=_observations(plan))
    assert g1.to_canonical() == g2.to_canonical()
    assert g1.digest() == g2.digest()


def test_graph_has_expected_provenance_edges() -> None:
    plan = sample_plan()
    g = build_graph(plan=plan, run_id="r1", observations=_observations(plan))
    types = {e.type for e in g.edges}
    assert {
        "target_plan",
        "plan_pack",
        "pack_case",
        "case_request",
        "case_response",
        "response_finding",
        "run_case",
    } <= types
    attack_cases = [c for c in plan.cases if c.kind == "attack"]
    control_edges = [e for e in g.edges if e.type == "control_gate"]
    assert len(control_edges) == len(attack_cases)


def test_duplicate_observation_ids_rejected() -> None:
    plan = sample_plan()
    first = plan.cases[0]
    with pytest.raises(GraphError):
        build_graph(
            plan=plan, run_id="r1",
            observations=[Observation(first.case_id, "confirmed"),
                          Observation(first.case_id, "confirmed")],
        )


def test_validate_graph_rejects_unknown_types_dangling_and_cycles() -> None:
    ok = EvidenceGraph(nodes=(Node("a", "target"), Node("b", "plan", {"mode": "reliable"})),
                       edges=(Edge("target_plan", "a", "b"),))
    validate_graph(ok)

    with pytest.raises(GraphError):  # unknown node type
        validate_graph(EvidenceGraph(nodes=(Node("a", "bogus"),), edges=()))
    with pytest.raises(GraphError):  # dangling edge
        validate_graph(EvidenceGraph(nodes=(Node("a", "target"),),
                                     edges=(Edge("target_plan", "a", "missing"),)))
    with pytest.raises(GraphError):  # unknown edge type
        validate_graph(EvidenceGraph(nodes=(Node("a", "target"), Node("b", "plan",
                       {"mode": "reliable"})), edges=(Edge("bogus", "a", "b"),)))
    with pytest.raises(GraphError):  # cycle
        validate_graph(EvidenceGraph(
            nodes=(Node("a", "target"), Node("b", "plan", {"mode": "reliable"})),
            edges=(Edge("target_plan", "a", "b"), Edge("plan_pack", "b", "a")),
        ))


def test_validate_graph_rejects_invalid_enum_attrs() -> None:
    with pytest.raises(GraphError):  # bad finding status
        validate_graph(EvidenceGraph(nodes=(Node("f", "finding", {"status": "totally_owned"}),),
                                     edges=()))
    with pytest.raises(GraphError):  # bad case kind
        validate_graph(EvidenceGraph(nodes=(Node("c", "case", {"kind": "sideways"}),), edges=()))
    with pytest.raises(GraphError):  # bad mode
        validate_graph(EvidenceGraph(nodes=(Node("p", "plan", {"mode": "turbo"}),), edges=()))
