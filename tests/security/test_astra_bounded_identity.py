"""Marker state must agree with its domain-separated identity commitment."""
import json

import pytest

from ai_scan.core.run_identity import evidence_marker
from ai_scan.evidence_graph import build_bundle, dump_bundle, load_bundle, replay_bundle
from ai_scan.evidence_graph.bundle import Bundle, BundleCollector, BundleError
from ai_scan.evidence_graph.replay import ReplayError
from ai_scan.injection import ExchangeOutcome, generate_canary
from ai_scan.orchestration import compile_plan, run_plan
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target


@pytest.mark.parametrize("populated", [False, True])
@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("form", ["mapping", "object", "text", "bytes", "export", "load"])
def test_marker_state_mutations_reject_at_evidence_boundaries(populated, present, form):
    plan = compile_plan(normalize_target("http://127.0.0.1:18981/chat"), "reliable")
    canary, marker = generate_canary(), generate_canary()
    collector = BundleCollector()

    class Counter:
        count = 0

    counter = Counter()

    def responder(case):
        counter.count += 1
        return ExchangeOutcome(body="benign")

    if populated:
        run_plan(plan, responder, canary=canary, observer=collector.observe,
                 physical_request_count=counter)
    kwargs = dict(plan=plan, canary=canary, disclosure_marker=marker if present else None,
                  run_id="bounded-identity")
    bundle = collector.build(**kwargs) if populated else build_bundle(records=[], **kwargs)
    assert bool(bundle.records) is populated

    def consume(document):
        if form == "export":
            return replay_bundle(dump_bundle(Bundle(document))).verified
        if form == "load":
            return replay_bundle(load_bundle(json.dumps(document))).verified
        source = (Bundle(document) if form in {"mapping", "object"} else
                  json.dumps(document).encode() if form == "bytes" else json.dumps(document))
        return replay_bundle(source).verified

    assert consume(bundle.content)
    document = bundle.content
    document["disclosure_marker"] = (
        None if present else evidence_marker(document["disclosure_marker_commitment"], present=True)
    )
    document.pop("digest")
    document["digest"] = compute_digest(document)
    with pytest.raises((BundleError, ReplayError), match="identity|commitment"):
        consume(document)


def test_export_rejects_marker_state_before_serializing_evidence():
    plan = compile_plan(normalize_target("http://127.0.0.1:18981/chat"), "reliable")
    bundle = build_bundle(plan=plan, records=[], canary=generate_canary(),
                          disclosure_marker=generate_canary(), run_id="export-state")
    document = bundle.content
    document["disclosure_marker"] = None
    document.pop("digest")
    document["digest"] = compute_digest(document)
    with pytest.raises(BundleError, match="identity|commitment"):
        dump_bundle(Bundle(document))
