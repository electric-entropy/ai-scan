"""Schema parity, identity binding, and exact bounded input domains."""
from __future__ import annotations

import copy
import json
from functools import cache
from importlib import resources

import pytest
from jsonschema import Draft202012Validator

from ai_scan import misinformation as api
from tests.security.test_llm09_misinformation import audit, manifest, vulnerable


@cache
def validator():
    text = resources.files("ai_scan.owasp").joinpath(
        "misinformation-manifest-v1.schema.json").read_text()
    schema = api.load_schema_text(text)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def parity(doc, valid):
    assert validator().is_valid(doc) is valid
    if valid:
        audit(doc)
    else:
        with pytest.raises(api.MisinformationManifestError):
            audit(doc)


def nodes(doc):
    case = doc["cases"][0]
    return [doc, case, case["expected_claims"][0], case["observed_claims"][0]]


FIELDS = [(i, k) for i, obj in enumerate(nodes(manifest())) for k in obj]


@pytest.mark.parametrize("index,key", FIELDS)
def test_every_field_required_typed_and_closed(index, key):
    doc = manifest()
    del nodes(doc)[index][key]
    parity(doc, False)
    doc = manifest()
    nodes(doc)[index]["extra"] = True
    parity(doc, False)
    for value in [None, {}, 1, 1.0, False]:
        if key == "citation_present" and value is False:
            continue
        doc = manifest()
        nodes(doc)[index][key] = value
        parity(doc, False)


REFS = [(i, k) for i, k in FIELDS if k.endswith("_ref")]


@pytest.mark.parametrize("index,key", REFS)
@pytest.mark.parametrize("value,valid", [
    ("a.b", True), ("a." + "b" * 62, True), ("a." + "b" * 63, False),
    ("a", False), ("a.b\n", False), ("a.b\r", False), ("a.b\x00", False),
    ("a.b ", False), ("a.b\u2028", False), ("A.b", False), ("á.b", False),
    ("a..b", False), ("../etc/passwd", False), ("https://example.test", False),
    ("%2561.b", False), ("a.b/", False), ("a" + ".b" * 15, True),
    ("a" + ".b" * 16, False),
])
def test_all_reference_lexical_boundaries(index, key, value, valid):
    doc = manifest()
    nodes(doc)[index][key] = value
    parity(doc, valid)


@pytest.mark.parametrize("index", [2, 3])
@pytest.mark.parametrize("value,valid", [
    ("0" * 64, True), ("abcdef0123456789" * 4, True), ("a" * 63, False),
    ("a" * 65, False), ("A" * 64, False), ("g" * 64, False), ("a" * 64 + "\n", False),
    ("", False), ([], False),
])
def test_digest_boundaries(index, value, valid):
    doc = manifest()
    nodes(doc)[index]["value_sha256"] = value
    parity(doc, valid)


@pytest.mark.parametrize("count,valid", [(0, False), (1, True), (32, True), (33, False)])
def test_case_count(count, valid):
    doc = manifest()
    case = doc["cases"][0]
    doc["cases"] = [{**case, "case_ref": f"case.n{i}"} for i in range(count)]
    parity(doc, valid)


@pytest.mark.parametrize("observed", [False, True])
@pytest.mark.parametrize("count", [0, 1, 64, 65])
def test_claim_count(observed, count):
    doc = manifest()
    key = "observed_claims" if observed else "expected_claims"
    case = doc["cases"][0]
    base = case[key][0]
    case[key] = [{**base, "claim_ref": f"claim.n{i}"} for i in range(count)]
    parity(doc, count <= 64 and (observed or count > 0))


@pytest.mark.parametrize("kind", ["case", "expected", "observed"])
@pytest.mark.parametrize("identical", [False, True])
def test_duplicate_identity_rejects_even_nonidentical_items(kind, identical):
    doc = manifest()
    case = doc["cases"][0]
    values = doc["cases"] if kind == "case" else case[kind + "_claims"]
    other = copy.deepcopy(values[0])
    if not identical:
        other["observed_snapshot_ref" if kind == "case" else "source_ref"] = "other.ref"
    values.append(other)
    assert validator().is_valid(doc) is not identical
    with pytest.raises(api.MisinformationManifestError):
        audit(doc)


def test_total_claim_bound_runtime_authority():
    doc = manifest()
    case = doc["cases"][0]
    for key in ("expected_claims", "observed_claims"):
        case[key] = [{**case[key][0], "claim_ref": f"claim.n{i}"} for i in range(64)]
    doc["cases"] = [{**copy.deepcopy(case), "case_ref": f"case.n{i}"} for i in range(8)]
    parity(doc, True)
    doc["cases"].append({**manifest()["cases"][0], "case_ref": "case.extra",
                          "observed_claims": []})
    assert validator().is_valid(doc)
    with pytest.raises(api.MisinformationManifestError):
        audit(doc)


@pytest.mark.parametrize("literal", ["null", "[]", "true", "0", '"text"',
                                     "NaN", "Infinity", "1e999"])
def test_nonobjects_reject(literal):
    with pytest.raises(api.MisinformationManifestError):
        api.audit_manifest_text(literal)


@pytest.mark.parametrize("index,key", FIELDS)
def test_duplicate_keys_reject(index, key):
    doc = manifest()
    obj = nodes(doc)[index]
    original = json.dumps(obj)
    ambiguous = original[:-1] + ', ' + json.dumps(key) + ': null}'
    text = json.dumps(doc).replace(original, ambiguous)
    assert text != json.dumps(doc)
    with pytest.raises(api.MisinformationManifestError):
        api.audit_manifest_text(text)


def test_output_order_independent_and_manifest_is_raw_digest():
    doc = vulnerable("unexpected_claim")
    case = doc["cases"][0]
    case["observed_claims"][0]["citation_present"] = False
    doc["cases"].append({**copy.deepcopy(case), "case_ref": "case.other"})
    before = audit(doc)
    doc["cases"].reverse()
    for case in doc["cases"]:
        case["expected_claims"].reverse()
        case["observed_claims"].reverse()
    doc = dict(reversed(list(doc.items())))
    after = audit(doc)
    assert before.findings == after.findings
    assert before.case_refs == after.case_refs
    assert before.context_ref == after.context_ref
    assert before.manifest_sha256 != after.manifest_sha256


@pytest.mark.parametrize("component", ["context_ref", "case_ref", "ground_truth_snapshot_ref",
                                        "observed_snapshot_ref", "claim_ref"])
def test_identity_transplant_changes_finding(component):
    doc = vulnerable("value_mismatch")
    before = audit(doc)
    if component == "context_ref":
        doc[component] = "other.identity"
    elif component == "claim_ref":
        for key in ("expected_claims", "observed_claims"):
            doc["cases"][0][key][0][component] = "other.identity"
    else:
        doc["cases"][0][component] = "other.identity"
    after = audit(doc)
    value_finding = next(f for f in after.findings if f.rule == "value_mismatch")
    assert before.findings[0].finding_ref != value_finding.finding_ref
    assert (before.context_ref == after.context_ref) is (component != "context_ref")


def test_high_cardinality_cross_domain_no_collisions():
    refs = set()
    for i in range(1024):
        doc = vulnerable("value_mismatch")
        doc["context_ref"] = f"context.n{i}"
        result = audit(doc)
        added = {result.context_ref, *result.case_refs, result.findings[0].finding_ref}
        assert len(added) == 3
        assert not refs & added
        refs.update(added)
    assert len(refs) == 3072


def test_claim_identity_and_rule_identity_do_not_collapse():
    doc = vulnerable("value_mismatch")
    case = doc["cases"][0]
    for key in ("expected_claims", "observed_claims"):
        case[key].append({**case[key][0], "claim_ref": "claim.other"})
    case["observed_claims"][0]["citation_present"] = False
    result = audit(doc)
    assert len({f.finding_ref for f in result.findings}) == 3
    assert len({f.case_ref for f in result.findings}) == 1


def test_schema_semantic_validation_rejects_drift():
    schema = copy.deepcopy(validator().schema)
    schema["additionalProperties"] = True
    with pytest.raises(api.MisinformationManifestError):
        api.load_schema_text(json.dumps(schema))


@pytest.mark.parametrize("field", ["status", "verdict", "finding", "judge", "url", "path"])
@pytest.mark.parametrize("index", range(4))
def test_input_never_selects_a_verdict_or_executable_reference(field, index):
    doc = manifest()
    nodes(doc)[index][field] = "private.submitted"
    parity(doc, False)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_values_at_nested_boundary(literal):
    text = json.dumps(manifest()).replace('"citation_present": true',
                                         '"citation_present": ' + literal)
    with pytest.raises(api.MisinformationManifestError):
        api.audit_manifest_text(text)
