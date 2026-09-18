"""Offline LLM08 vector/embedding declaration audit contract."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
import sys
from importlib import resources
from pathlib import Path

import pytest

from ai_scan import cli, vector

REF = "ctx.primary"


def secure_manifest() -> dict[str, object]:
    return {
        "schema_version": "ai-scan-vector-manifest-v1",
        "scope": {
            "tenant_ref": "tenant.primary",
            "context_ref": REF,
            "collection_ref": "collection.primary",
            "query_context_ref": REF,
            "server_bound": True,
            "cross_context_fallback": False,
            "global_search": False,
        },
        "ingestion": {
            "source_refs": ["source.primary"],
            "lineage": "digest",
            "quarantine": True,
            "duplicate_policy": "reject",
            "atomic_promotion": True,
        },
        "embedding": {
            "model_ref": "model.primary",
            "version_ref": "version.primary",
            "index_version_ref": "index.primary",
            "rollback_ref": "rollback.primary",
            "pinned": True,
            "dimensions": 1536,
            "index_dimensions": 1536,
            "normalization": "unit",
            "distance": "cosine",
            "migration": "reindex",
            "reject_incompatible": True,
            "rollback_metadata": True,
        },
        "retrieval": {
            "top_k": 10,
            "candidates": 100,
            "threshold_policy": "minimum",
            "minimum_score": 75,
            "metadata_filters": "exact",
            "empty_filter": "reject",
            "query_bytes": 4096,
            "result_bytes": 65536,
        },
        "privacy": {
            "removed_classes": ["credentials", "pii", "secrets"],
            "retention": "disabled",
            "retention_hours": 0,
            "vector_export": False,
            "debug_dumps": False,
            "log_bodies": False,
        },
        "lifecycle": {
            "index_hours": 24,
            "cache_hours": 24,
            "replica_hours": 24,
            "backup_hours": 168,
            "tombstones": True,
            "orphan_detection": True,
            "rebuild": "accepted_lineage",
            "restore_namespace": True,
        },
        "poisoning": {
            "trust_tiers": "enforced",
            "anomaly": True,
            "near_duplicate": True,
            "contributions_per_source": 100,
            "rate_per_minute": 60,
            "chunk_provenance": True,
            "recovery": "accepted_lineage",
        },
        "operations": {
            "storage_partition": True,
            "cache_partition": True,
            "cache_scope": True,
            "cache_model": True,
            "cache_index": True,
            "concurrency": 4,
            "storage_mb": 1024,
            "timeout_seconds": 30,
            "audit_events": "opaque",
            "failure_scope": "closed",
        },
    }


def dumped(doc: dict[str, object]) -> str:
    return json.dumps(doc, sort_keys=True, allow_nan=False)


def audit(doc: dict[str, object]) -> vector.VectorAuditResult:
    return vector.audit_manifest_text(dumped(doc))


def test_cli_secure_json_and_text_outputs_are_scrubbed(tmp_path: Path, capsys) -> None:
    path = tmp_path / "vector.json"
    path.write_text(dumped(secure_manifest()), encoding="utf-8")
    assert "vector-audit" in cli.build_parser().format_help()
    assert cli.main(["vector-audit", "--manifest", str(path), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["owasp_category"] == "LLM08"
    assert doc["status"] == "passed"
    assert doc["message"] == "declaration checks passed"
    assert doc["findings"] == []
    assert doc["network_requests"] == doc["executions"] == 0
    assert REF not in repr(doc)
    assert str(path) not in repr(doc)
    assert cli.main(["vector-audit", "--manifest", str(path), "--format", "text"]) == 0
    text = capsys.readouterr().out
    assert "LLM08 Vector and Embedding Weaknesses offline declaration assessment" in text
    assert "declaration checks passed" in text
    assert REF not in text


def test_cli_vulnerable_fixture_exits_three_in_both_formats(capsys) -> None:
    root = resources.files("ai_scan.owasp")
    path = str(root.joinpath("vector-vulnerable-v1.json"))
    assert cli.main(["vector-audit", "--manifest", path, "--format", "json"]) == 3
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "finding"
    assert {item["rule_id"] for item in doc["findings"]} == {
        "llm08.scope_partitioning",
        "llm08.ingestion_provenance",
        "llm08.embedding_lineage",
        "llm08.retrieval_controls",
        "llm08.data_minimization",
        "llm08.lifecycle",
        "llm08.poisoning_resistance",
        "llm08.isolation_operations",
    }
    assert cli.main(["vector-audit", "--manifest", path, "--format", "text"]) == 3
    assert "llm08.scope_partitioning" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("section", "field", "value", "rule"),
    [
        ("scope", "server_bound", False, "scope_partitioning"),
        ("ingestion", "lineage", "none", "ingestion_provenance"),
        ("embedding", "pinned", False, "embedding_lineage"),
        ("retrieval", "top_k", 21, "retrieval_controls"),
        ("privacy", "removed_classes", ["credentials", "pii"], "data_minimization"),
        ("lifecycle", "index_hours", 25, "lifecycle"),
        ("poisoning", "trust_tiers", "uniform", "poisoning_resistance"),
        ("operations", "cache_index", False, "isolation_operations"),
    ],
)
def test_each_required_domain_has_isolated_deterministic_rule(section, field, value, rule) -> None:
    doc = secure_manifest()
    doc[section][field] = value  # type: ignore[index]
    result = audit(doc)
    assert result.status == "finding"
    assert [finding.rule for finding in result.findings] == [rule]
    assert REF not in repr(result.to_dict())


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("scope", "tenant_ref", "../tenant"),
        ("scope", "tenant_ref", "/absolute"),
        ("scope", "tenant_ref", "https://user:secret@example.test"),  # pragma: allowlist secret
        ("scope", "server_bound", 1),
        ("ingestion", "source_refs", []),
        ("ingestion", "source_refs", ["source.primary", "source.primary"]),
        ("ingestion", "lineage", "sha256"),
        ("embedding", "dimensions", True),
        ("embedding", "dimensions", 0),
        ("embedding", "dimensions", 65537),
        ("retrieval", "threshold_policy", "soft"),
        ("retrieval", "minimum_score", -1),
        ("privacy", "removed_classes", ["credentials", "credentials"]),
        ("privacy", "retention_hours", 8761),
        ("lifecycle", "backup_hours", 0),
        ("poisoning", "rate_per_minute", 0),
        ("operations", "concurrency", 1025),
    ],
)
def test_field_type_enum_bound_and_reference_errors_are_invalid(section, field, value) -> None:
    doc = secure_manifest()
    doc[section][field] = value  # type: ignore[index]
    with pytest.raises(vector.VectorManifestError, match="^llm08_manifest_invalid$"):
        audit(doc)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.__setitem__("extra", True),
        lambda d: d.pop("scope"),
        lambda d: d["scope"].__setitem__("extra", True),
        lambda d: d["scope"].pop("tenant_ref"),
        lambda d: d["scope"].__setitem__("collection_ref", d["scope"]["tenant_ref"]),
        lambda d: d["scope"].__setitem__("query_context_ref", "ctx.other"),
        lambda d: d["embedding"].__setitem__("index_dimensions", 768),
        lambda d: d["embedding"].update({"distance": "dot", "normalization": "none"}),
        lambda d: d["retrieval"].update({"threshold_policy": "disabled", "minimum_score": 1}),
        lambda d: d["retrieval"].update({"candidates": 1, "top_k": 2}),
        lambda d: d["retrieval"].update({"query_bytes": 100, "result_bytes": 99}),
        lambda d: d["privacy"].update({"retention": "disabled", "retention_hours": 1}),
        lambda d: d["lifecycle"].update({"index_hours": 24, "backup_hours": 1}),
        lambda d: d["poisoning"].update({"contributions_per_source": 10, "rate_per_minute": 11}),
    ],
)
def test_closed_shapes_and_cross_field_contradictions_are_invalid(mutate) -> None:
    doc = secure_manifest()
    mutate(doc)
    with pytest.raises(vector.VectorManifestError):
        audit(doc)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_nonfinite_numbers_and_duplicate_keys_reject(literal: str) -> None:
    text = dumped(secure_manifest()).replace("1536", literal, 1)
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_text(text)
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_text('{"schema_version":1,"schema_version":2}')


def test_input_size_depth_document_types_and_invalid_utf8(tmp_path: Path) -> None:
    for value in (None, b"{}", {}, [], True, 1, "\ufeff{}", "[" * 1000 + "0" + "]" * 1000):
        with pytest.raises(vector.VectorManifestError):
            vector.audit_manifest_text(value)  # type: ignore[arg-type]
    too_large = " " * (vector.MAX_MANIFEST_BYTES + 1)
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_text(too_large)
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff")
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_file(str(bad))


def test_safe_file_edges_and_cli_errors_do_not_echo(tmp_path: Path, capsys) -> None:
    submitted_name = "submitted-ref-path.json"
    missing = tmp_path / submitted_name
    assert cli.main(["vector-audit", "--manifest", str(missing)]) == 1
    out = capsys.readouterr().out
    assert out.strip() == "invalid: llm08_manifest_invalid"
    assert submitted_name not in out
    target = tmp_path / "manifest.json"
    target.write_text(dumped(secure_manifest()), encoding="utf-8")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_file(str(link))
    with pytest.raises(vector.VectorManifestError):
        vector.audit_manifest_file(str(tmp_path))


def test_exception_graph_drops_submitted_content() -> None:
    submitted = dumped(secure_manifest()).replace("tenant.primary", "leak/ref")
    try:
        vector.audit_manifest_text(submitted)
    except vector.VectorManifestError as exc:
        stack = [exc]
        seen: list[BaseException] = []
        while stack:
            current = stack.pop()
            seen.append(current)
            if current.__cause__:
                stack.append(current.__cause__)
            if current.__context__:
                stack.append(current.__context__)
        assert all("leak/ref" not in repr(item) for item in seen)
        assert all("tenant.primary" not in repr(item) for item in seen)
    else:  # pragma: no cover
        pytest.fail("expected invalid manifest")


def test_packaged_schema_fixtures_doctor_and_coverage_contract(capsys) -> None:
    root = resources.files("ai_scan.owasp")
    vector.load_schema_text(root.joinpath("vector-manifest-v1.schema.json").read_text())
    secure = vector.audit_manifest_file(str(root.joinpath("vector-secure-v1.json")))
    vulnerable = vector.audit_manifest_file(str(root.joinpath("vector-vulnerable-v1.json")))
    assert secure.status == "passed"
    assert vulnerable.status == "finding"
    assert cli.main(["doctor", "--json"]) == 0
    doctor = json.loads(capsys.readouterr().out)
    assert any(c["name"] == "owasp-llm08-vector-resources" for c in doctor["checks"])
    from ai_scan.owasp_llm import coverage_summary, load_coverage_matrix

    matrix = load_coverage_matrix()
    assert coverage_summary(matrix)["active_end_to_end_categories"] == 9
    llm08 = next(c for c in matrix.categories if c.id == "LLM08")
    assert llm08.current_active_cli_coverage is True
    assert "vector-audit" in llm08.active_coverage_source
    assert "declaration" in llm08.active_coverage_source
    assert not llm08.full_coverage_claim_allowed


def test_doctor_semantic_tamper_not_digest_only(monkeypatch, capsys) -> None:
    real = vector.load_manifest_file

    def tamper(path: str) -> str:
        text = real(path)
        if path.endswith("vector-secure-v1.json"):
            doc = json.loads(text)
            doc["scope"]["server_bound"] = False
            return json.dumps(doc)
        return text

    monkeypatch.setattr(vector, "load_manifest_file", tamper)
    assert cli.main(["doctor", "--json"]) == 1
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert not next(c for c in checks if c["name"] == "owasp-llm08-vector-resources")["ok"]


def test_no_execution_network_stdin_or_reference_loads(monkeypatch, tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(dumped(secure_manifest()), encoding="utf-8")
    original_open = builtins.open
    allowed = {str(path), os.fspath(path)}

    def guarded_open(file, *args, **kwargs):  # type: ignore[no-untyped-def]
        if isinstance(file, (str, os.PathLike)) and os.fspath(file) not in allowed:
            raise AssertionError(f"unexpected open {file!r}")
        return original_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    monkeypatch.setattr(
        subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(AssertionError("subprocess"))
    )
    monkeypatch.setattr(
        socket.socket, "connect", lambda *a, **k: (_ for _ in ()).throw(AssertionError("connect"))
    )
    monkeypatch.setattr(
        sys.stdin, "read", lambda *a, **k: (_ for _ in ()).throw(AssertionError("stdin"))
    )
    assert vector.audit_manifest_file(str(path)).status == "passed"


def test_installed_style_syscall_trace_observes_no_connect_or_exec(tmp_path: Path) -> None:
    trace = tmp_path / "trace.log"
    manifest = resources.files("ai_scan.owasp").joinpath("vector-secure-v1.json")
    result = subprocess.run(
        [
            "strace",
            "-f",
            "-e",
            "trace=connect,execve",
            "-o",
            str(trace),
            sys.executable,
            "-m",
            "ai_scan.cli",
            "vector-audit",
            "--manifest",
            str(manifest),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 127 or "No such file" in result.stderr:
        pytest.skip("strace unavailable")
    assert result.returncode == 0, result.stdout + result.stderr
    lines = trace.read_text(encoding="utf-8").splitlines()
    assert not any("connect(" in line for line in lines)
    exec_lines = [line for line in lines if "execve(" in line]
    assert len(exec_lines) == 1
