"""Closed numeric domain, semantic contradictions and identity bounds."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json

import pytest

from ai_scan import consumption as api
from tests.security.test_llm10_consumption import (
    CONTROLS,
    EVENTS,
    NUMBERS,
    RULES,
    audit,
    manifest,
    vulnerable,
)


def nodes(doc):
    scenario = doc["scenarios"][0]
    return [doc, scenario, *(scenario[k] for k in
                            ("ceilings", "observations", "controls", "events"))]


FIELDS = [(i, k) for i, obj in enumerate(nodes(manifest())) for k in obj]


@pytest.mark.parametrize("index,key", FIELDS)
def test_every_field_required_and_duplicate_rejected(index, key):
    doc = manifest()
    del nodes(doc)[index][key]
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)
    doc = manifest()
    obj = nodes(doc)[index]
    original = json.dumps(obj)
    text = json.dumps(doc).replace(original, original[:-1] + ', ' + json.dumps(key) + ': null}')
    assert text != json.dumps(doc)
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_text(text)


@pytest.mark.parametrize("index", range(6))
@pytest.mark.parametrize("key", ["extra", "status", "verdict", "finding", "risk", "url", "path"])
def test_closed_objects(index, key):
    doc = manifest()
    nodes(doc)[index][key] = "private.submitted"
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


@pytest.mark.parametrize("group", ["ceilings", "observations"])
@pytest.mark.parametrize("key", NUMBERS)
@pytest.mark.parametrize("value", [True, False, None, "1", [], {}, 1.0, -1, 1000000001,
                                  float("nan"), float("inf"), 1e300])
def test_every_numeric_field_exact_bounded_integer(group, key, value):
    doc = manifest()
    doc["scenarios"][0][group][key] = value
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


@pytest.mark.parametrize("group,key", [("controls", k) for k in CONTROLS] +
                         [("events", k) for k in EVENTS])
@pytest.mark.parametrize("value", [None, 0, 1, 1.0, "true", [], {}])
def test_every_boolean_field_exact(group, key, value):
    doc = manifest()
    doc["scenarios"][0][group][key] = value
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


@pytest.mark.parametrize("index,key", [(0, "context_ref"), (1, "scenario_ref")])
@pytest.mark.parametrize("value", ["a", "a.b\n", "a.b\r", "a.b\0", "a.b ", "a.b\u2028",
                                  "á.b", "A.b", "a..b", "../etc/passwd", "https://a.test",
                                  "%2561.b", "a.b/", "a." + "b" * 63, "a" + ".b" * 16,
                                  None, 3, {}, [], True])
def test_reference_rejects(index, key, value):
    doc = manifest()
    nodes(doc)[index][key] = value
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


@pytest.mark.parametrize("count,valid", [(0, False), (1, True), (32, True), (33, False)])
def test_scenario_count(count, valid):
    doc = manifest()
    doc["scenarios"] = [{**doc["scenarios"][0], "scenario_ref": f"scenario.n{i}"}
                        for i in range(count)]
    if valid:
        assert not audit(doc).findings
    else:
        with pytest.raises(api.ConsumptionManifestError):
            audit(doc)


@pytest.mark.parametrize("value", [None, {}, True, 1, 1.0, "private.submitted"])
@pytest.mark.parametrize("index,key", [(0, "scenarios"), (1, "ceilings"), (1, "observations"),
                                       (1, "controls"), (1, "events")])
def test_container_types(index, key, value):
    doc = manifest()
    nodes(doc)[index][key] = value
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


@pytest.mark.parametrize("kind", ["ceiling_tokens", "cancellation", "exhaustion", "cleanup"])
def test_contradictions_reject(kind):
    doc = manifest()
    s = doc["scenarios"][0]
    if kind == "ceiling_tokens":
        s["ceilings"]["total_tokens"] += 1
    else:
        field = {"cancellation": "work_after_cancellation",
                 "exhaustion": "work_after_exhaustion", "cleanup": "cleanup_observed"}[kind]
        s["events"][field] = True
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


def test_duplicate_scenario_identity_nonidentical():
    doc = manifest()
    doc["scenarios"].append(vulnerable("deadline")["scenarios"][0])
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


def test_aggregate_exact_limit_and_over():
    doc = manifest()
    s = doc["scenarios"][0]
    for group in ("ceilings", "observations"):
        s[group] = dict.fromkeys(NUMBERS, 0)
        for key in ("requests", "duration_ms", "queue_depth", "retries", "tool_steps"):
            s[group][key] = 1000000000
    assert not audit(doc).findings
    s["observations"]["response_bytes"] = 1
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)


@pytest.mark.parametrize("literal", ["null", "[]", "true", "0", '"text"', "NaN", "1e999"])
def test_nonobjects(literal):
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_text(literal)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999", "1.0", "1e0"])
def test_nested_numeric_lexemes(literal):
    text = json.dumps(manifest()).replace('"requests": 10', '"requests": ' + literal)
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_text(text)


def test_all_boolean_control_combinations_against_independent_oracle():
    for flags in itertools.product((False, True), repeat=len(CONTROLS)):
        doc = manifest()
        c = dict(zip(CONTROLS, flags, strict=True))
        doc["scenarios"][0]["controls"] = c
        expected = set()
        if not c["deadline_enforced"]:
            expected.add("deadline")
        if not c["backpressure"]:
            expected.add("concurrency")
        if not (c["cancellation_enforced"] and c["cleanup_enforced"] and
                c["fail_closed_on_exhaustion"]):
            expected.add("termination")
        if not (c["circuit_breaker"] and c["per_scope_limits"]):
            expected.add("isolation")
        assert {f.rule for f in audit(doc).findings} == expected


def test_all_event_combinations_and_negative_controls():
    for flags in itertools.product((False, True), repeat=len(EVENTS)):
        doc = manifest()
        e = dict(zip(EVENTS, flags, strict=True))
        doc["scenarios"][0]["events"] = e
        cancel, exhaust, cleanup, after_cancel, after_exhaust = flags
        if (after_cancel and not cancel or after_exhaust and not exhaust or
                cleanup and not (cancel or exhaust)):
            with pytest.raises(api.ConsumptionManifestError):
                audit(doc)
        else:
            expected = {"termination"} if ((cancel or exhaust) and not cleanup or
                                          after_cancel or after_exhaust) else set()
            assert {f.rule for f in audit(doc).findings} == expected


@pytest.mark.parametrize("field,rule", list(zip(NUMBERS,
    ("request_volume", "token_budget", "token_budget", "token_budget", "deadline",
     "concurrency", "concurrency", "retry_tool_budget", "retry_tool_budget",
     "byte_budget", "byte_budget"), strict=True)))
def test_every_counter_comparison_boundary(field, rule):
    doc = manifest()
    assert not audit(doc).findings
    doc["scenarios"][0]["observations"][field] += 1
    assert [f.rule for f in audit(doc).findings] == [rule]


def test_order_digest_and_coordinate_transplants():
    doc = vulnerable("request_volume")
    doc["scenarios"].append({**copy.deepcopy(doc["scenarios"][0]),
                             "scenario_ref": "scenario.other"})
    before = audit(doc)
    doc["scenarios"].reverse()
    after = audit(doc)
    assert before.findings == after.findings and before.scenario_refs == after.scenario_refs
    assert before.manifest_sha256 != after.manifest_sha256
    assert after.manifest_sha256 == hashlib.sha256(json.dumps(doc).encode()).hexdigest()
    doc["scenarios"][0]["observations"]["requests"] += 1
    changed_evidence = audit(doc)
    assert changed_evidence.findings == after.findings
    assert changed_evidence.manifest_sha256 != after.manifest_sha256
    doc["context_ref"] = "context.other"
    assert not ({f.finding_ref for f in after.findings} &
                {f.finding_ref for f in audit(doc).findings})


def test_maximum_output_and_identity_uniqueness():
    doc = manifest()
    s = doc["scenarios"][0]
    s["controls"] = dict.fromkeys(CONTROLS, False)
    s["observations"] = {k: v + 1 for k, v in s["observations"].items()}
    doc["scenarios"] = [{**s, "scenario_ref": f"scenario.n{i}"} for i in range(32)]
    result = audit(doc)
    assert len(result.findings) == 256
    assert len({f.finding_ref for f in result.findings}) == 256
    assert len(api.render_json(result).encode()) < 200000
    assert {f.rule for f in result.findings} == set(RULES)
    identities = set()
    for i in range(1024):
        single = vulnerable("request_volume")
        single["context_ref"] = f"context.n{i}"
        r = audit(single)
        added = {r.context_ref, *r.scenario_refs, r.findings[0].finding_ref}
        assert len(added) == 3 and not added & identities
        assert all(len(ref.rsplit("-", 1)[1]) == 64 for ref in added)
        identities.update(added)


def test_all_rule_combinations_and_rule_identity_transplants():
    for flags in itertools.product((False, True), repeat=len(RULES)):
        doc = manifest()
        s = doc["scenarios"][0]
        expected = set()
        for rule, active in zip(RULES, flags, strict=True):
            if not active:
                continue
            expected.add(rule)
            changed = vulnerable(rule)["scenarios"][0]
            for group in ("observations", "controls", "events"):
                for key, value in changed[group].items():
                    if value != manifest()["scenarios"][0][group][key]:
                        s[group][key] = value
        result = audit(doc)
        assert {f.rule for f in result.findings} == expected
        assert len({f.finding_ref for f in result.findings}) == len(expected)
        assert result == audit(doc)
        if result.findings:
            before = {f.finding_ref for f in result.findings}
            s["scenario_ref"] = "scenario.transplant"
            after = audit(doc)
            assert not before & {f.finding_ref for f in after.findings}
            assert result.context_ref == after.context_ref


@pytest.mark.parametrize("version", [None, 1, True, {}, [], "ai-scan-consumption-manifest-v2"])
def test_schema_version_exact(version):
    doc = manifest()
    doc["schema_version"] = version
    with pytest.raises(api.ConsumptionManifestError):
        audit(doc)
