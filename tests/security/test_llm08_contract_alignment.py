"""Structural preflight and opaque identity regressions for LLM08."""

from __future__ import annotations

import json
from functools import cache
from importlib import resources

import pytest
from jsonschema import Draft202012Validator

from ai_scan import vector
from tests.security.test_llm08_vector import audit, secure_manifest


@cache
def validator():
    text = resources.files("ai_scan.owasp").joinpath("vector-manifest-v1.schema.json").read_text()
    schema = json.loads(text)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@pytest.mark.parametrize(
    "section,updates,valid",
    [
        ("ingestion", {"source_refs": ["review.source"] * 2}, False),
        ("privacy", {"removed_classes": ["secrets", "secrets"]}, False),
        ("scope", {"tenant_ref": "review.tenant\n"}, False),
        ("operations", {"concurrency": 8.0}, True),
        ("embedding", {"distance": "dot", "normalization": "none"}, False),
        ("retrieval", {"threshold_policy": "disabled", "minimum_score": 1}, False),
        ("privacy", {"retention": "disabled", "retention_hours": 1}, False),
    ],
)
def test_review_structural_parity(section, updates, valid):
    doc = secure_manifest()
    doc[section].update(updates)
    assert validator().is_valid(doc) is valid
    if valid:
        assert audit(doc).status == "passed"
    else:
        with pytest.raises(vector.VectorManifestError):
            audit(doc)


@pytest.mark.parametrize("component", ["tenant_ref", "collection_ref"])
def test_review_context_tuple_identity(component):
    doc = secure_manifest()
    before = audit(doc).context_ref
    doc["scope"][component] = "other.identity"
    assert audit(doc).context_ref != before


def test_review_rule_identity_is_separate_from_shared_context():
    doc = secure_manifest()
    doc["scope"]["server_bound"] = False
    doc["ingestion"]["quarantine"] = False
    result = audit(doc)
    assert len(result.findings) == 2
    assert all(f.context_ref == result.context_ref for f in result.findings)
    refs = [f.finding_ref for f in result.findings]
    assert len(set(refs)) == 2
    assert result.context_ref not in refs
    assert result == audit(doc)
    for finding in result.findings:
        assert finding.to_dict()["finding_ref"] == finding.finding_ref
        assert finding.finding_ref in vector.render_text(result)
        assert finding.finding_ref.startswith("llm08-finding-")
        assert len(finding.finding_ref) == 78
    for value in ("tenant.primary", "ctx.primary", "collection.primary"):
        assert value not in vector.render_json(result)


@pytest.mark.parametrize("literal", ["8", "8.0", "8e0", "80e-1", "0.8e1"])
def test_integral_lexical_forms_are_canonicalized_before_rules(literal, monkeypatch):
    text = json.dumps(secure_manifest()).replace('"concurrency": 4', '"concurrency": ' + literal)
    original = vector._rules

    def checked(raw):
        assert type(raw["operations"]["concurrency"]) is int
        assert raw["operations"]["concurrency"] == 8
        return original(raw)

    monkeypatch.setattr(vector, "_rules", checked)
    assert validator().is_valid(json.loads(text))
    assert vector.audit_manifest_text(text).status == "passed"


@pytest.mark.parametrize(
    "literal",
    ["8.5", "8.000000000000000001", "1e-999", "true", "false", '"8"',
     "NaN", "Infinity", "-Infinity", "1e999", "0.0", "1025.0"],
)
def test_invalid_numeric_lexical_forms_reject(literal):
    text = json.dumps(secure_manifest()).replace('"concurrency": 4', '"concurrency": ' + literal)
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_text(text)


@pytest.mark.parametrize(
    "section,updates",
    [
        ("scope", {"tenant_ref": "ctx.primary"}),
        ("scope", {"collection_ref": "tenant.primary"}),
        ("scope", {"collection_ref": "ctx.primary"}),
        ("scope", {"query_context_ref": "ctx.other"}),
        ("embedding", {"index_dimensions": 768}),
        ("retrieval", {"candidates": 9}),
        ("retrieval", {"result_bytes": 4095}),
        ("lifecycle", {"backup_hours": 23}),
        ("poisoning", {"rate_per_minute": 101}),
    ],
)
def test_runtime_only_relations_are_not_claimed_by_schema(section, updates):
    doc = secure_manifest()
    doc[section].update(updates)
    assert validator().is_valid(doc)
    with pytest.raises(vector.VectorManifestError):
        audit(doc)


@pytest.mark.parametrize("distance", ["dot", "cosine", "euclidean"])
@pytest.mark.parametrize("normalization", ["unit", "none"])
def test_normalization_condition_parity(distance, normalization):
    doc = secure_manifest()
    doc["embedding"].update(distance=distance, normalization=normalization)
    expected = distance != "dot" or normalization == "unit"
    assert_parity(doc, expected)


@pytest.mark.parametrize(
    "section,policy,number,enabled",
    [("retrieval", "threshold_policy", "minimum_score", "minimum"),
     ("privacy", "retention", "retention_hours", "bounded")],
)
@pytest.mark.parametrize("disabled", [True, False])
@pytest.mark.parametrize("value", [0, 0.0, 1, 1.0])
def test_zero_policy_condition_parity(section, policy, number, enabled, disabled, value):
    doc = secure_manifest()
    doc[section].update({policy: "disabled" if disabled else enabled, number: value})
    assert_parity(doc, disabled == (value == 0))


def assert_parity(doc, expected):
    assert validator().is_valid(doc) is expected
    if expected:
        audit(doc)
    else:
        with pytest.raises(vector.VectorManifestError):
            audit(doc)


FIELDS = [
    (section, key, value)
    for section, fields in secure_manifest().items()
    if isinstance(fields, dict)
    for key, value in fields.items()
]


@pytest.mark.parametrize("section,key,value", FIELDS)
def test_every_required_field_type_and_closed_section(section, key, value):
    doc = secure_manifest()
    del doc[section][key]
    assert_parity(doc, False)
    doc = secure_manifest()
    doc[section]["extra"] = value
    assert_parity(doc, False)
    for invalid in [None, {}, True if type(value) is not bool else 1]:
        doc = secure_manifest()
        doc[section][key] = invalid
        assert_parity(doc, False)


@pytest.mark.parametrize(
    "section,key,value", [(s, k, v) for s, k, v in FIELDS if type(v) is int]
)
def test_every_integer_canonicalization_fractional_and_bounds(section, key, value, monkeypatch):
    doc = secure_manifest()
    doc[section][key] = float(value)
    original = vector._rules

    def checked(raw):
        assert type(raw[section][key]) is int
        return original(raw)

    monkeypatch.setattr(vector, "_rules", checked)
    assert_parity(doc, True)
    spec = validator().schema["properties"][section]["properties"][key]
    for invalid in [spec["minimum"] - 1, spec["maximum"] + 1, value + 0.5, str(value), False]:
        doc[section][key] = invalid
        assert_parity(doc, False)


@pytest.mark.parametrize(
    "section,key", [(s, k) for s, k, v in FIELDS if k.endswith("_ref")]
)
@pytest.mark.parametrize("suffix", ["\n", "\r", "\r\n", "\u2028", "\u0000", " "])
def test_all_references_require_whole_string(section, key, suffix):
    doc = secure_manifest()
    doc[section][key] += suffix
    assert_parity(doc, False)


@pytest.mark.parametrize("component", ["tenant_ref", "context_ref", "collection_ref"])
def test_all_identity_components_bind_every_rule(component):
    root = resources.files("ai_scan.owasp")
    doc = json.loads(root.joinpath("vector-vulnerable-v1.json").read_text())
    before = audit(doc)
    doc["scope"][component] = "other.component"
    if component == "context_ref":
        doc["scope"]["query_context_ref"] = "other.component"
    after = audit(doc)
    assert before.context_ref != after.context_ref
    assert len(before.findings) == len(after.findings) == 8
    assert len({f.finding_ref for f in before.findings + after.findings}) == 16
    for a, b in zip(before.findings, after.findings, strict=True):
        assert a.rule == b.rule
        assert a.finding_ref != b.finding_ref


def test_identity_is_canonical_not_manifest_order_or_unrelated_fields():
    doc = secure_manifest()
    doc["scope"]["server_bound"] = False
    before = audit(doc)
    reordered = {key: doc[key] for key in reversed(doc)}
    reordered["scope"] = dict(reversed(list(doc["scope"].items())))
    reordered["operations"]["storage_mb"] = 1025
    after = audit(reordered)
    assert before.context_ref == after.context_ref
    assert before.findings == after.findings


@pytest.mark.parametrize("kind", ["unique", "pattern", "condition"])
def test_doctor_rejects_structural_contract_drift(kind, monkeypatch, capsys):
    from ai_scan import cli

    original = vector.load_manifest_file

    def altered(path):
        text = original(path)
        if path.endswith("vector-manifest-v1.schema.json"):
            schema = json.loads(text)
            if kind == "unique":
                del schema["properties"]["ingestion"]["properties"]["source_refs"]["uniqueItems"]
            elif kind == "pattern":
                schema["properties"]["scope"]["properties"]["tenant_ref"]["pattern"] = ".*"
            else:
                schema["allOf"].pop()
            return json.dumps(schema)
        return text

    monkeypatch.setattr(vector, "load_manifest_file", altered)
    assert cli.main(["doctor", "--json"]) == 1
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert not next(c for c in checks if c["name"] == "owasp-llm08-vector-resources")["ok"]


@pytest.mark.parametrize(
    "section,key,value",
    [(s, k, v) for s, k, v in FIELDS if type(v) is bool or
     (type(v) is str and not k.endswith("_ref"))],
)
def test_enum_and_boolean_domain_parity(section, key, value):
    spec = validator().schema["properties"][section]["properties"][key]
    assert "enum" in spec or type(value) is bool
    values = spec.get("enum", [True, False])
    for candidate in values:
        doc = secure_manifest()
        doc[section][key] = candidate
        if key == "distance":
            doc[section]["normalization"] = "unit"
        if key == "threshold_policy":
            doc[section]["minimum_score"] = 0 if candidate == "disabled" else 50
        if key == "retention":
            doc[section]["retention_hours"] = 0 if candidate == "disabled" else 24
        assert_parity(doc, True)
    for candidate in ["unknown", 1, 1.0, [], None]:
        doc = secure_manifest()
        doc[section][key] = candidate
        assert_parity(doc, False)


@pytest.mark.parametrize(
    "section,key,values,valid",
    [
        ("ingestion", "source_refs", [], False),
        ("ingestion", "source_refs", ["a.b"], True),
        ("ingestion", "source_refs", [f"source.r{i}" for i in range(32)], True),
        ("ingestion", "source_refs", [f"source.r{i}" for i in range(33)], False),
        ("ingestion", "source_refs", ["a.b\n"], False),
        ("ingestion", "source_refs", [1], False),
        ("privacy", "removed_classes", [], True),
        ("privacy", "removed_classes", ["credentials", "pii", "secrets"], True),
        ("privacy", "removed_classes", ["credentials", "pii", "secrets", "other"], False),
        ("privacy", "removed_classes", ["other"], False),
        ("privacy", "removed_classes", [1], False),
    ],
)
def test_array_structural_parity(section, key, values, valid):
    doc = secure_manifest()
    doc[section][key] = values
    assert_parity(doc, valid)


def test_top_level_schema_and_runtime_are_closed():
    for section in secure_manifest():
        doc = secure_manifest()
        del doc[section]
        assert_parity(doc, False)
    doc = secure_manifest()
    doc["extra"] = True
    assert_parity(doc, False)
    doc = secure_manifest()
    doc["schema_version"] = "other.version"
    assert_parity(doc, False)
