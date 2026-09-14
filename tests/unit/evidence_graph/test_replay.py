"""Replay: offline reproduction of M7 classification + fail-closed matrix."""

from __future__ import annotations

import json

import pytest

from ai_scan.evidence_graph import (
    BundleCollector,
    BundleError,
    ReplayError,
    dump_bundle,
    replay_bundle,
)
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import run_plan
from tests.unit.evidence_graph._sample import CANARY, redigest, sample_bundle_text, sample_plan


def test_replay_reproduces_confirmed_findings() -> None:
    result = replay_bundle(sample_bundle_text())
    assert result.verified
    assert result.findings
    assert all(status == "confirmed" for status in result.findings.values())
    assert result.canary == CANARY


def test_single_trial_confirmed_record_cannot_replay_verify() -> None:
    # A confirmed attack record that shows only ONE trial must not replay-verify
    # as confirmed under the plan's 3/2/2 thresholds (no 1/1 inference).
    doc = json.loads(sample_bundle_text())
    tampered = False
    for record in doc["records"]:
        if record["kind"] == "attack" and record["finding"]["status"] == "confirmed":
            record["finding"]["attack_trials"] = 1
            record["finding"]["successes"] = 1
            tampered = True
            break
    assert tampered  # the sample must contain a confirmed attack record
    with pytest.raises((BundleError, ReplayError)):
        replay_bundle(json.dumps(redigest(doc)))


def test_sufficient_trial_metadata_replay_verifies_confirmed() -> None:
    # The GREEN path: the sample's confirmed records carry enough trials/successes
    # (>= 3/2) to replay-verify as confirmed at the real plan thresholds.
    doc = json.loads(sample_bundle_text())
    confirmed = [
        r for r in doc["records"]
        if r["kind"] == "attack" and r["finding"]["status"] == "confirmed"
    ]
    assert confirmed
    for record in confirmed:
        assert record["finding"]["attack_trials"] >= 3
        assert record["finding"]["successes"] >= 2
    result = replay_bundle(sample_bundle_text())
    assert all(status == "confirmed" for status in result.findings.values())


def test_replay_constructs_no_transport(monkeypatch) -> None:
    # Replay must never build a Transport; if ai_scan.transport.Transport were
    # instantiated this would blow up.
    import ai_scan.transport as transport

    def boom(*_a, **_k):
        raise AssertionError("replay must not construct Transport")

    monkeypatch.setattr(transport, "Transport", boom)
    assert replay_bundle(sample_bundle_text()).verified


def test_replay_rejects_redigested_finding_tamper() -> None:
    # Changing a finding status contradicts the embedded graph, so this now
    # fails closed at load (graph≠records) before reaching replay.
    doc = json.loads(sample_bundle_text())
    for record in doc["records"]:
        if record["kind"] == "attack":
            record["finding"]["status"] = "not_observed"
            break
    with pytest.raises((BundleError, ReplayError)):
        replay_bundle(json.dumps(redigest(doc)))


def test_replay_rejects_missing_response_for_finding() -> None:
    doc = json.loads(sample_bundle_text())
    for record in doc["records"]:
        if record["kind"] == "attack":
            del record["response"]["body"]
            break
    with pytest.raises((BundleError, ReplayError)):
        replay_bundle(json.dumps(redigest(doc)))


def test_replay_rejects_duplicate_record_ids() -> None:
    doc = json.loads(sample_bundle_text())
    doc["records"].append(dict(doc["records"][0]))
    with pytest.raises((BundleError, ReplayError)):
        replay_bundle(json.dumps(redigest(doc)))


def test_replay_control_emission_downgrades_through_bundle() -> None:
    # A real bundle whose benign controls emitted the canary must preserve that
    # downgrade and replay as 'suspected' (7-state preserved, never confirmed).
    plan = sample_plan()

    def leaky_control_responder(case):  # type: ignore[no-untyped-def]
        body = f"benign {CANARY}" if "{canary}" not in case.template else CANARY
        return ExchangeOutcome(body=body)

    collector = BundleCollector()
    run_plan(plan, leaky_control_responder, canary=CANARY, goal="g", observer=collector.observe)
    bundle = collector.build(plan=plan, canary=CANARY, run_id="leaky-controls")
    result = replay_bundle(dump_bundle(bundle))
    assert result.findings
    assert all(status != "confirmed" for status in result.findings.values())
    assert any(status == "suspected" for status in result.findings.values())


def test_replay_rejects_redigested_proof_tamper() -> None:
    doc = json.loads(sample_bundle_text())
    for record in doc["records"]:
        if record["kind"] == "attack":
            record["finding"]["proof"] = "AISCAN-FORGEDPROOF"
            break
    with pytest.raises(ReplayError, match="proof"):
        replay_bundle(json.dumps(redigest(doc)))


def test_replay_rejects_proof_nulling() -> None:
    doc = json.loads(sample_bundle_text())
    for record in doc["records"]:
        if record["kind"] == "attack":
            record["finding"]["proof"] = None
            break
    with pytest.raises(ReplayError, match="proof"):
        replay_bundle(json.dumps(redigest(doc)))
