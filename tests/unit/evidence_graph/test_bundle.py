"""Evidence bundle: integrity, tamper rejection, secret-free, offline load."""

from __future__ import annotations

import json

import pytest

from ai_scan.evidence_graph import BundleError, load_bundle
from tests.unit.evidence_graph._sample import redigest, sample_bundle_text


def test_valid_bundle_round_trips() -> None:
    bundle = load_bundle(sample_bundle_text())
    assert bundle.records
    assert bundle.plan().mode == "reliable"


def test_naive_tamper_without_redigest_is_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    doc["canary"] = "AISCAN-OTHER"
    with pytest.raises(BundleError, match="digest"):
        load_bundle(json.dumps(doc))


def test_duplicate_json_keys_rejected() -> None:
    text = sample_bundle_text()
    # Inject a duplicate top-level key textually.
    injected = text.rstrip().rstrip("}") + ', "canary": "AISCAN-DUP"}'
    with pytest.raises(BundleError, match="duplicate key"):
        load_bundle(injected)


def test_non_finite_number_rejected() -> None:
    doc = redigest({**json.loads(sample_bundle_text()), "extra": 0})
    # Force a non-finite into the JSON text (Infinity is invalid strict JSON but
    # Python's json emits/accepts it via constants).
    text = json.dumps(doc).replace('"extra": 0', '"extra": Infinity')
    with pytest.raises(BundleError):
        load_bundle(text)


def test_redigested_plan_tamper_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    doc["plan"]["origin"] = "not a url"  # malformed plan, then re-digest bundle
    with pytest.raises(BundleError):
        load_bundle(json.dumps(redigest(doc)))


def test_redigested_graph_tamper_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    doc["graph"]["edges"].append({"type": "run_case", "src": "run:run-1", "dst": "nope"})
    with pytest.raises(BundleError):
        load_bundle(json.dumps(redigest(doc)))


def test_unredacted_secret_in_bundle_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    # Slip a credential-format secret into a record body, then re-digest.
    leak = "leak ghp_abcdefghijklmnopqrstuvwxyz0123"  # pragma: allowlist secret
    doc["records"][0]["trials"][0]["body"] = leak
    with pytest.raises(BundleError):
        load_bundle(json.dumps(redigest(doc)))


def test_extra_top_level_field_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    doc["extra_top"] = "x"
    with pytest.raises(BundleError, match="top-level"):
        load_bundle(json.dumps(redigest(doc)))


def test_missing_top_level_field_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    del doc["metadata"]
    with pytest.raises(BundleError, match="top-level"):
        load_bundle(json.dumps(redigest(doc)))


def test_redigested_graph_node_edge_removal_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    doc["graph"]["edges"] = doc["graph"]["edges"][:-1]  # drop an edge
    doc["graph_digest"] = __import__(
        "ai_scan.packs.signatures", fromlist=["compute_digest"]
    ).compute_digest(doc["graph"])
    with pytest.raises(BundleError):
        load_bundle(json.dumps(redigest(doc)))


def test_missing_control_record_for_attack_family_rejected() -> None:
    doc = json.loads(sample_bundle_text())
    # Drop all control records, re-derive graph digest to match the shrunken
    # graph, then re-digest the bundle — must still reject (graph ≠ plan+records).
    doc["records"] = [r for r in doc["records"] if r["kind"] != "control"]
    with pytest.raises(BundleError):
        load_bundle(json.dumps(redigest(doc)))
