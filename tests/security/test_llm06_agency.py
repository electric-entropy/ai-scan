"""Offline LLM06 declarations: independent behavior and hostile-input checks."""

from __future__ import annotations

import json
from importlib import resources

import pytest

from ai_scan import agency, cli


def tool(operation: str = "read", ident: str = "tool.primary") -> dict[str, object]:
    side_effect = operation != "read"
    return {
        "id": ident,
        "operation": operation,
        "side_effecting": side_effect,
        "resource_ref": "resource.primary",
        "destination_ref": "destination.primary",
        "object_ref": "object.primary",
        "least_functionality": True,
        "resource_scope": "fixed",
        "parameter_shape": "closed_typed",
        "destination_boundary": "fixed",
        "object_boundary": "fixed",
        "execution_identity": "dedicated_least_privilege",
        "isolation": "container",
        "max_calls": 2,
        "idempotency": "stable_operation_key" if side_effect else "none",
        "precondition": side_effect,
        "read_back": side_effect,
        "cleanup": "deterministic_compensation" if side_effect else "none",
        "cleanup_verified": side_effect,
        "unresolved_state": "halt_and_reconcile" if side_effect else "not_applicable",
        "response_schema": "closed_typed",
        "result_trust": "untrusted",
        "output_to_action": "separated",
        "error_isolation": True,
        "operation_commitment": True,
        "request_commitment": True,
        "result_commitment": True,
        "event_identity": "opaque_sequence",
    }


def manifest(*tools: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "ai-scan-agency-manifest-v1",
        "limits": {
            "steps": 16,
            "side_effects": 8,
            "concurrency": 1,
            "duration_seconds": 60,
            "recursion_depth": 1,
            "delegation_depth": 1,
            "retries": 1,
            "output_bytes": 8192,
        },
        "tools": list(tools),
    }


def test_public_secure_read_declaration(tmp_path, capsys) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest(tool())))
    assert "agency-audit" in cli.build_parser().format_help()
    assert cli.main(["agency-audit", "--manifest", str(path), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "passed"
    assert doc["message"] == "declaration checks passed"
    assert doc["owasp_category"] == "LLM06"
    assert doc["findings"] == []
    assert doc["executions"] == doc["network_requests"] == 0
    assert "tool.primary" not in repr(doc)


@pytest.mark.parametrize("operation", ["read", "update", "delete", "send"])
def test_operation_positive_controls(operation):
    assert agency.audit_manifest_text(json.dumps(manifest(tool(operation)))).status == "passed"


@pytest.mark.parametrize(
    "field,value",
    [
        ("unknown", "HOSTILE"),
        ("id", "bad\u202eidentity"),
        ("id", "e\u0301"),
        ("id", "x" * 129),
        ("operation", []),
        ("operation", "execute"),
        ("side_effecting", True),
        ("least_functionality", 1),
        ("max_calls", True),
        ("max_calls", 0),
        ("max_calls", 17),
        ("max_calls", 10**100),
        ("resource_ref", "https://user:secret@example.test"),  # pragma: allowlist secret
        ("execution_identity", "SECRET"),
        ("idempotency", "stable_operation_key"),
        ("precondition", True),
        ("read_back", True),
        ("cleanup_verified", True),
        ("cleanup", "deterministic_compensation"),
        ("unresolved_state", "halt_and_reconcile"),
    ],
)
def test_invalid_tool_shapes_reject_without_echo(field, value):
    item = tool()
    item[field] = value
    with pytest.raises(agency.AgencyManifestError, match="^llm06_manifest_invalid$"):
        agency.audit_manifest_text(json.dumps(manifest(item)))


@pytest.mark.parametrize(
    "field",
    [
        "steps",
        "side_effects",
        "concurrency",
        "duration_seconds",
        "recursion_depth",
        "delegation_depth",
        "retries",
        "output_bytes",
    ],
)
@pytest.mark.parametrize("value", [True, 0, -1, 1.5, None, 10**100])
def test_all_bounds_require_positive_bounded_exact_integers(field, value):
    doc = manifest(tool())
    doc["limits"][field] = value
    with pytest.raises(agency.AgencyManifestError):
        agency.audit_manifest_text(json.dumps(doc))


@pytest.mark.parametrize(
    "field,value",
    [
        ("concurrency", 17),
        ("recursion_depth", 17),
        ("delegation_depth", 17),
        ("retries", 16),
        ("side_effects", 33),
    ],
)
def test_cross_field_limit_contradictions_reject(field, value):
    doc = manifest(tool())
    doc["limits"][field] = value
    with pytest.raises(agency.AgencyManifestError):
        agency.audit_manifest_text(json.dumps(doc))


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_numbers_reject(literal):
    text = json.dumps(manifest(tool())).replace("8192", literal)
    with pytest.raises(agency.AgencyManifestError):
        agency.audit_manifest_text(text)


def test_closed_top_level_duplicate_keys_ids_and_excessive_depth_size():
    texts = [
        json.dumps(manifest(tool(), tool())),
        '{"secret":1,"secret":2}',
        "[" * 1000 + "0" + "]" * 1000,
        " " * (agency.MAX_MANIFEST_BYTES + 1),
    ]
    for field in ("schema_version", "limits", "tools"):
        doc = manifest(tool())
        del doc[field]
        texts.append(json.dumps(doc))
    doc = manifest(tool())
    doc["HOSTILE"] = "SECRET"
    texts.append(json.dumps(doc))
    for text in texts:
        with pytest.raises(agency.AgencyManifestError):
            agency.audit_manifest_text(text)


def test_empty_inventory_is_not_applicable():
    assert agency.audit_manifest_text(json.dumps(manifest())).status == "not_applicable"


@pytest.mark.parametrize(
    "field,value",
    [
        ("least_functionality", False),
        ("resource_scope", "dynamic"),
        ("parameter_shape", "open"),
        ("destination_boundary", "dynamic"),
        ("object_boundary", "dynamic"),
        ("execution_identity", "privileged"),
        ("isolation", "none"),
        ("idempotency", "per_attempt_key"),
        ("precondition", False),
        ("read_back", False),
        ("cleanup", "best_effort"),
        ("cleanup_verified", False),
        ("unresolved_state", "continue"),
        ("response_schema", "open"),
        ("result_trust", "trusted"),
        ("output_to_action", "direct"),
        ("error_isolation", False),
        ("operation_commitment", False),
        ("request_commitment", False),
        ("result_commitment", False),
        ("event_identity", "raw_content"),
    ],
)
def test_independent_rule_negatives(field, value):
    item = tool("delete")
    item[field] = value
    result = agency.audit_manifest_text(json.dumps(manifest(item)))
    assert result.status == "finding"
    assert {f.rule for f in result.findings} == {field}
    assert result.findings[0].to_dict()["field_path"] == "tools[]." + field


@pytest.mark.parametrize("operation", ["read", "update", "delete", "send"])
def test_risk_dependent_isolation_and_bounds(operation):
    item = tool(operation)
    item["isolation"] = "process"
    doc = manifest(item)
    doc["limits"].update(concurrency=2, recursion_depth=2, delegation_depth=2)
    result = agency.audit_manifest_text(json.dumps(doc))
    expected = {"isolation", "autonomy_bounds"} if operation in {"delete", "send"} else set()
    assert {f.rule for f in result.findings} == expected


@pytest.mark.parametrize(
    "field,value",
    [
        ("steps", 101),
        ("side_effects", 17),
        ("concurrency", 5),
        ("duration_seconds", 301),
        ("recursion_depth", 5),
        ("delegation_depth", 5),
        ("retries", 3),
        ("output_bytes", 1000001),
    ],
)
def test_finite_but_excessive_bounds_are_findings_not_echoed(field, value):
    doc = manifest(tool("update"))
    doc["limits"][field] = value
    result = agency.audit_manifest_text(json.dumps(doc))
    assert {f.rule for f in result.findings} == {"autonomy_bounds"}
    assert result.findings[0].to_dict()["field_path"] == "limits"


def test_packaged_schema_and_independent_fixtures():
    root = resources.files("ai_scan.owasp")
    schema = root.joinpath("agency-manifest-v1.schema.json")
    assert schema.is_file()
    agency.load_schema_text(schema.read_text())
    secure = agency.audit_manifest_file(str(root.joinpath("agency-secure-v1.json")))
    vulnerable = agency.audit_manifest_file(str(root.joinpath("agency-vulnerable-v1.json")))
    assert secure.status == "passed" and not secure.findings
    assert vulnerable.status == "finding"
    assert len(secure.tool_refs) == 4
    assert {f.rule for f in vulnerable.findings} == {
        "least_functionality",
        "parameter_shape",
        "execution_identity",
        "isolation",
        "read_back",
        "cleanup_verified",
        "result_trust",
        "request_commitment",
    }


@pytest.mark.parametrize("resource", ["schema", "secure", "vulnerable"])
def test_doctor_semantic_tamper_not_just_digest(resource, monkeypatch, capsys):
    assert cli.main(["doctor", "--json"]) == 0
    baseline = json.loads(capsys.readouterr().out)
    assert any(c["name"] == "owasp-llm06-agency-resources" for c in baseline["checks"])
    real = agency.load_manifest_file

    def tamper(path):
        text = real(path)
        if resource == "schema" and path.endswith("agency-manifest-v1.schema.json"):
            doc = json.loads(text)
            doc["properties"]["tools"]["maxItems"] = 1999
            return json.dumps(doc)
        if path.endswith("agency-" + resource + "-v1.json"):
            doc = json.loads(text)
            doc["tools"][0]["side_effecting"] = not doc["tools"][0]["side_effecting"]
            return json.dumps(doc)
        return text

    monkeypatch.setattr(agency, "load_manifest_file", tamper)
    assert cli.main(["doctor", "--json"]) == 1
    result = json.loads(capsys.readouterr().out)
    assert not next(c for c in result["checks"] if c["name"] == "owasp-llm06-agency-resources")[
        "ok"
    ]


def test_coverage_seven_partial_categories():
    from ai_scan.owasp_llm import coverage_summary, load_coverage_matrix

    matrix = load_coverage_matrix()
    assert coverage_summary(matrix)["active_end_to_end_categories"] == 7
    category = matrix.categories[5]
    assert category.current_active_cli_coverage and not category.scaffolding_only
    assert "agency-audit" in category.active_coverage_source
    assert "offline" in category.active_coverage_source
    assert not category.full_coverage_claim_allowed


@pytest.mark.parametrize("field", tuple(tool()))
def test_every_tool_field_required(field):
    item = tool()
    del item[field]
    with pytest.raises(agency.AgencyManifestError):
        agency.audit_manifest_text(json.dumps(manifest(item)))


@pytest.mark.parametrize("operation", ["update", "delete", "send"])
def test_side_effect_consistency_and_physical_ceiling(operation):
    for changes in (
        {"side_effecting": False},
        {"unresolved_state": "not_applicable"},
        {"cleanup": "none", "cleanup_verified": True},
        {"max_calls": 5},
    ):
        item = tool(operation)
        item.update(changes)
        with pytest.raises(agency.AgencyManifestError):
            agency.audit_manifest_text(json.dumps(manifest(item)))
    item = tool(operation)
    item["max_calls"] = 4
    assert agency.audit_manifest_text(json.dumps(manifest(item))).status == "passed"


def test_label_length_boundary_and_document_input_types():
    item = tool(ident="a." + "b" * 126)
    assert agency.audit_manifest_text(json.dumps(manifest(item))).status == "passed"
    item["id"] += "b"
    with pytest.raises(agency.AgencyManifestError):
        agency.audit_manifest_text(json.dumps(manifest(item)))
    for value in (None, b"{}", {}, [], True, 1, "\ufeff{}"):
        with pytest.raises(agency.AgencyManifestError):
            agency.audit_manifest_text(value)
