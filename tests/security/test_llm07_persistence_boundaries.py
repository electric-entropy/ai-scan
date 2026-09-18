"""Live marker records cannot cross any persistence boundary, even resealed."""
import copy
import json

import pytest

from ai_scan.core.run_identity import RunIdentity
from ai_scan.evidence_graph import (
    BundleCollector,
    BundleError,
    ReplayError,
    dump_bundle,
    load_bundle,
    replay_bundle,
)
from ai_scan.evidence_graph.bundle import Bundle
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import compile_plan
from ai_scan.orchestration.checkpoint import CheckpointError, load_checkpoint
from ai_scan.orchestration.evidence import is_marker_dependent_case
from ai_scan.packs import load_builtin_pack
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

MARKER = "AISCAN-1234ABCD5678EF901234ABCD5678EF90"
CANARY = "AISCAN-ABCDEF0123456789"


def seal(doc):
    doc["digest"] = compute_digest({k: v for k, v in doc.items() if k != "digest"})
    return doc


@pytest.fixture
def substrate(tmp_path):
    plan = compile_plan(normalize_target("http://127.0.0.1:8765/chat"), "reliable")
    attacks = {c.template for c in plan.attack_cases()
               if is_marker_dependent_case(load_builtin_pack(c.pack_id), c)}
    live = BundleCollector()
    def responder(c):
        return ExchangeOutcome(body=MARKER if c.template in attacks else "benign")
    result = run_plan(plan, responder, canary=CANARY, disclosure_marker=MARKER,
                      observer=live.observe)
    assert sum(f.status.value == "confirmed" for f in result.findings) == 4
    checkpoint = tmp_path / "checkpoint.json"
    persisted = BundleCollector()
    run_plan(plan, responder, canary=CANARY, disclosure_marker=MARKER,
             observer=persisted.observe, checkpoint_path=str(checkpoint))
    records = [r.to_dict(plan, CANARY, RunIdentity.create(plan.digest, CANARY, MARKER),
                        frozenset({MARKER})) for r in live._records
               if r.kind == "attack" and r.prompt in attacks]
    return plan, checkpoint, records, persisted


@pytest.mark.parametrize("category", ["LLM02", "LLM07"])
@pytest.mark.parametrize("state", ["completed", "duplicate", "progress", "in_flight"])
@pytest.mark.parametrize("marker", [None, MARKER, "AISCAN-9999999999999999"])
def test_marker_checkpoint_injections(substrate, category, state, marker):
    plan, path, records, _ = substrate
    record = copy.deepcopy(next(r for r in records
                                if category in load_builtin_pack(r["pack_id"])
                                .mappings["owasp-llm"]))
    doc = json.loads(path.read_text())
    if state == "duplicate":
        record["trials"][1] = copy.deepcopy(record["trials"][0])
    if state in {"completed", "duplicate"}:
        doc["completed"][record["case_id"]] = {
            **{k: record[k] for k in ("family", "kind", "prompt", "trials")},
            **record["finding"],
        }
    elif state == "progress":
        doc["progress"][record["case_id"]] = {
            k: record[k] for k in ("family", "kind", "prompt", "trials")}
    else:
        doc["in_flight"] = {k: record[k] for k in ("case_id", "family", "kind", "prompt")}
        doc["in_flight"]["attempts"] = 1
    doc["request_count"] += 1 if state == "in_flight" else sum(
        t["attempts"] for t in record["trials"])
    path.write_text(json.dumps(seal(doc)))
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan,
                        disclosure_marker=marker)


@pytest.mark.parametrize("category", ["LLM02", "LLM07"])
@pytest.mark.parametrize("boundary", ["dump", "load", "replay"])
def test_bundle_boundary_parity(substrate, category, boundary):
    plan, _, records, collector = substrate
    bundle = collector.build(plan=plan, canary=CANARY, disclosure_marker=MARKER, run_id="test")
    doc = json.loads(dump_bundle(bundle))
    doc["records"].append(next(r for r in records
                               if category in load_builtin_pack(r["pack_id"])
                               .mappings["owasp-llm"]))
    seal(doc)
    with pytest.raises((BundleError, ReplayError)):
        if boundary == "dump":
            dump_bundle(Bundle(content=doc))
        elif boundary == "load":
            load_bundle(json.dumps(doc))
        else:
            replay_bundle(json.dumps(doc))
