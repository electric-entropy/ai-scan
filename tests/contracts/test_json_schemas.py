"""Milestone 2: packaged versioned schemas load and accept valid documents."""

from __future__ import annotations

import json
from importlib import resources

import pytest

from ai_scan.core.config import SUPPORTED_SCHEMAS, load_document, load_schema

SCHEMA_FILES = {
    ("target", 1): "target-v1.schema.json",
    ("engagement", 1): "engagement-v1.schema.json",
    ("plan", 1): "plan-v1.schema.json",
    ("pack", 1): "pack-v1.schema.json",
    ("evidence", 2): "evidence-v2.schema.json",
    ("finding", 2): "finding-v2.schema.json",
    ("receipt", 2): "receipt-v2.schema.json",
}


def test_supported_schemas_cover_all_kinds() -> None:
    assert set(SUPPORTED_SCHEMAS) == {
        "target", "engagement", "plan", "pack", "evidence", "finding", "receipt"
    }


@pytest.mark.parametrize(("kind", "version"), sorted(SCHEMA_FILES))
def test_every_schema_is_packaged_and_parseable(kind: str, version: int) -> None:
    text = resources.files("ai_scan.schemas").joinpath(SCHEMA_FILES[(kind, version)]).read_text()
    schema = json.loads(text)
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert load_schema(kind, version)["title"] == f"{kind}-v{version}"


_DIGEST = "a" * 64
_TS = "2026-09-12T00:00:00Z"

VALID_DOCS = {
    "target": {
        "schema_version": 1, "kind": "target", "name": "app", "adapter": "generic_http",
        "endpoints": ["https://api.example.com/chat"],
        "request": {"method": "POST", "prompt_marker": "*", "body_template": "{\"input\": \"*\"}"},
        "response": {"extract": "json_path", "json_path": "reply"},
        "session": {"mode": "stateless"},
        "auth_refs": [{"header": "Authorization", "env": "API_TOKEN"}],
    },
    "engagement": {
        "schema_version": 1, "kind": "engagement", "engagement_id": "ENG-1", "client": "Acme",
        "approver": "Jo", "issued_at": _TS, "expires_at": _TS,
        "target_scopes": ["https://api.example.com"], "capabilities": ["read"],
        "limits": {
            "max_physical_requests": 256, "max_duration_seconds": 1800,
            "requests_per_second": 2.0, "max_concurrency": 1,
        },
        "signer_key_id": "key-1",
    },
    "pack": {
        "schema_version": 1, "kind": "pack", "id": "safe", "version": "safe-2026.09.1",
        "trust": "builtin", "digest": _DIGEST, "families": ["instruction_conflict"],
    },
    "evidence": {
        "schema_version": 2, "kind": "evidence", "id": "e-1", "node_type": "response",
        "digest": _DIGEST, "redaction_state": "redaction_complete", "created_at": _TS,
    },
    "finding": {
        "schema_version": 2, "kind": "finding", "id": "f-1", "attack_id": "a",
        "title": "t", "status": "confirmed", "severity": "high", "evidence_ids": ["e-1"],
    },
    "receipt": {
        "schema_version": 2, "kind": "receipt", "receipt_id": "rcpt-0001",
        "engagement_digest": _DIGEST, "target_scopes": ["https://api.example.com"],
        "capabilities": ["read"],
        "budgets": {
            "max_physical_requests": 256, "max_duration_seconds": 1800,
            "requests_per_second": 2.0, "max_concurrency": 1,
        },
        "valid_from": _TS, "valid_until": _TS, "key_id": "key-1", "signature": "sig",
    },
}


@pytest.mark.parametrize("kind", sorted(VALID_DOCS))
def test_valid_documents_pass(kind: str) -> None:
    doc = load_document(json.dumps(VALID_DOCS[kind]), kind)
    assert doc["kind"] == kind


def test_runtime_plan_document_validates() -> None:
    # A plan is the canonical runtime artifact (plan_version, no schema_version/kind
    # envelope); validate-config accepts exactly what the runner runs.
    from ai_scan.orchestration import compile_plan, plan_to_dict
    from ai_scan.targets import normalize_target

    target = normalize_target("https://api.example.com/chat")
    plan_doc = plan_to_dict(compile_plan(target, "reliable"))
    validated = load_document(json.dumps(plan_doc), "plan")
    assert validated["mode"] == "reliable"
    assert validated["digest"] == plan_doc["digest"]
