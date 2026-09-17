"""LLM05 offline output-handling declaration audit coverage."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import sys
import time
from importlib import resources
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.output_handling import (
    OutputHandlingManifestError,
    audit_manifest_text,
    load_manifest_file,
    load_schema_text,
)


def _sink(
    sink_id: str = "web.primary",
    sink_type: str = "html_dom",
    context: str = "html_text",
    encoding: str = "html_escape",
) -> dict[str, object]:
    return {
        "id": sink_id,
        "type": sink_type,
        "context": context,
        "implementation_ref": "src/render/output.py#render_model_output",
        "trust_boundary": "untrusted_model_output",
        "encoding": encoding,
        "parameterized": True,
        "string_concatenation": False,
        "schema_validation": True,
        "allowlist_validation": True,
        "active_content": "disabled",
        "interpreter_behavior": "disabled",
        "error_isolation": True,
        "output_isolation": True,
        "max_output_chars": 8192,
    }


def _manifest(sinks: list[dict[str, object]]) -> dict[str, object]:
    return {"schema_version": "ai-scan-output-handling-manifest-v1", "sinks": sinks}


def _credential_url(secret: str) -> str:
    return "https://user:" + secret + "@example.test/secret?api_key=VALUE"


@pytest.mark.parametrize(
    ("sink_type", "context", "encoding", "interpreter_behavior"),
    [
        ("html_dom", "html_text", "html_escape", "disabled"),
        ("html_dom", "html_attribute", "html_attribute_escape", "disabled"),
        ("markdown", "markdown", "markdown_escape", "disabled"),
        ("sql", "query", "parameterized_query", "disabled"),
        ("shell_process", "argv", "argv_array", "disabled"),
        ("code_template", "template", "sandboxed_template", "sandboxed"),
        ("logging", "log_record", "structured_log", "disabled"),
        ("structured_api", "json", "schema_serializer", "disabled"),
    ],
)
def test_secure_sink_contexts_pass_declaration_checks(
    sink_type: str, context: str, encoding: str, interpreter_behavior: str
) -> None:
    sink = _sink("sink.secure", sink_type, context, encoding)
    sink["interpreter_behavior"] = interpreter_behavior

    result = audit_manifest_text(json.dumps(_manifest([sink]), sort_keys=True))

    assert result.status == "passed"
    assert result.applicability == "applicable"
    assert result.summary == {"sinks": 1, "findings": 0}
    assert len(result.sinks) == 1
    assert re.fullmatch(r"llm05-sink-[0-9a-f]{64}", str(result.sinks[0]["sink_ref"]))
    assert result.sinks[0] == {
        "sink_ref": result.sinks[0]["sink_ref"],
        "manifest_sha256": result.manifest_sha256,
        "applicability": "applicable",
    }


def test_vulnerable_declarations_emit_fixed_deterministic_findings() -> None:
    sink = _sink("sink.vulnerable", "sql", "query", "raw")
    sink.update(
        {
            "trust_boundary": "trusted_internal",
            "parameterized": False,
            "string_concatenation": True,
            "schema_validation": False,
            "allowlist_validation": False,
            "active_content": "allowed",
            "interpreter_behavior": "direct",
            "error_isolation": False,
            "output_isolation": False,
            "max_output_chars": 1000001,
        }
    )

    result = audit_manifest_text(json.dumps(_manifest([sink]), sort_keys=True))

    assert result.status == "finding"
    assert result.applicability == "applicable"
    assert {finding["rule_id"] for finding in result.findings} == {
        "llm05.untrusted_boundary",
        "llm05.contextual_encoding",
        "llm05.parameterization",
        "llm05.string_concatenation",
        "llm05.schema_validation",
        "llm05.allowlist_validation",
        "llm05.active_content",
        "llm05.interpreter_behavior",
        "llm05.error_isolation",
        "llm05.output_isolation",
        "llm05.fixed_size_limit",
    }
    for finding in result.findings:
        assert finding["owasp_category"] == "LLM05"
        assert finding["status"] == "finding"
        assert finding["manifest_sha256"] == result.manifest_sha256
        assert re.fullmatch(r"llm05-sink-[0-9a-f]{64}", str(finding["sink_ref"]))
        assert str(finding["field_path"]).startswith("sinks[].")
        assert str(finding["reason_code"]).startswith("llm05_")
        assert str(finding["remediation_code"]).startswith("llm05.remediate.")
        assert "evidence" not in finding


def test_empty_manifest_is_not_applicable_not_a_secure_pass() -> None:
    result = audit_manifest_text(json.dumps(_manifest([]), sort_keys=True))
    assert result.status == "not_applicable"
    assert result.applicability == "not_applicable"
    assert result.summary == {"sinks": 0, "findings": 0}


@pytest.mark.parametrize(
    "mutator",
    [
        lambda doc: doc.__setitem__("unknown", "secret"),
        lambda doc: doc["sinks"][0].__setitem__("unknown", "secret"),
        lambda doc: doc.__setitem__("schema_version", "wrong"),
        lambda doc: doc.__setitem__("sinks", {}),
        lambda doc: doc["sinks"][0].__setitem__("id", "Not Canonical"),
        lambda doc: doc["sinks"][0].__setitem__("type", "unknown"),
        lambda doc: doc["sinks"][0].__setitem__("context", "query"),
        lambda doc: doc["sinks"][0].__setitem__("parameterized", 1),
        lambda doc: doc["sinks"][0].__setitem__("max_output_chars", True),
        lambda doc: doc["sinks"][0].__setitem__("max_output_chars", 0),
        lambda doc: doc["sinks"][0].__setitem__("max_output_chars", -1),
    ],
)
def test_strict_closed_schema_rejects_invalid_documents(mutator) -> None:  # type: ignore[no-untyped-def]
    doc = _manifest([_sink()])
    mutator(doc)
    with pytest.raises(OutputHandlingManifestError):
        audit_manifest_text(json.dumps(doc, sort_keys=True))


def test_duplicate_ids_and_duplicate_json_keys_are_rejected_without_echo() -> None:
    duplicate_ids = _manifest([_sink("sink.duplicate"), _sink("sink.duplicate")])
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_duplicate_id") as exc:
        audit_manifest_text(json.dumps(duplicate_ids, sort_keys=True))
    assert "sink.duplicate" not in str(exc.value)

    duplicate_key = (
        '{"schema_version":"ai-scan-output-handling-manifest-v1","sinks":['
        '{"id":"sink.one","id":"sink.secret","type":"html_dom",'
        '"context":"html_text","implementation_ref":"secret","trust_boundary":'
        '"untrusted_model_output","encoding":"html_escape","parameterized":true,'
        '"string_concatenation":false,"schema_validation":true,'
        '"allowlist_validation":true,"active_content":"disabled",'
        '"interpreter_behavior":"disabled","error_isolation":true,'
        '"output_isolation":true,"max_output_chars":1}]}'
    )
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_invalid_json") as exc:
        audit_manifest_text(duplicate_key)
    assert "sink.secret" not in str(exc.value)


def test_result_objects_never_retain_manifest_values() -> None:
    sink = _sink("sink.secret")
    submitted = {
        "id": "sink.secret",
        "implementation_ref": _credential_url("token"),
        "encoding": "raw",
    }
    sink.update(submitted)
    result = audit_manifest_text(json.dumps(_manifest([sink]), sort_keys=True))
    rendered = repr(result) + json.dumps(result.to_dict(), sort_keys=True)
    for value in submitted.values():
        assert str(value) not in rendered


def test_opaque_refs_are_domain_separated_deterministic_and_unique_for_2000_ids() -> None:
    sinks = [_sink(f"sink.item-{index}") for index in range(2000)]
    result = audit_manifest_text(json.dumps(_manifest(sinks), separators=(",", ":")))
    refs = {str(item["sink_ref"]) for item in result.sinks}
    assert result.status == "passed"
    assert len(refs) == 2000


def _write(path: Path, doc: dict[str, object]) -> Path:
    path.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    return path


def test_public_cli_secure_vulnerable_and_help_contract(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secure = _write(tmp_path / "secure.json", _manifest([_sink()]))
    vulnerable_sink = _sink("sink.vulnerable", "shell_process", "argv", "raw")
    vulnerable_sink["parameterized"] = False
    vulnerable_sink["string_concatenation"] = True
    vulnerable = _write(tmp_path / "vulnerable.json", _manifest([vulnerable_sink]))

    assert "output-handling-audit" in cli.build_parser().format_help()
    with pytest.raises(SystemExit) as help_exit:
        cli.main(["output-handling-audit", "--help"])
    assert help_exit.value.code == 0
    help_output = capsys.readouterr().out.lower()
    assert "offline" in help_output and "declaration" in help_output

    assert cli.main(["output-handling-audit", "--manifest", str(secure)]) == cli.EXIT_OK
    assert "status: passed" in capsys.readouterr().out
    assert (
        cli.main(
            ["output-handling-audit", "--manifest", str(vulnerable), "--format", "json"]
        )
        == cli.EXIT_CONFIRMED_FINDING
    )
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema_version"] == "ai-scan-output-handling-audit-result-v1"
    assert doc["owasp_category"] == "LLM05"
    assert doc["scope"] == "partial_offline_declaration_assessment"
    assert doc["network_requests"] == 0
    assert doc["executions"] == 0


def test_cli_never_reads_stdin_or_constructs_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "manifest.json", _manifest([_sink()]))

    def boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline command crossed a forbidden boundary")

    monkeypatch.setattr("builtins.input", boom)
    monkeypatch.setattr(cli, "_make_transport", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)

    assert cli.main(["output-handling-audit", "--manifest", str(path)]) == cli.EXIT_OK


def test_cli_opens_only_manifest_not_declared_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forbidden = tmp_path / "must-not-open.py"
    forbidden.write_text("raise AssertionError('executed')", encoding="utf-8")
    sink = _sink()
    sink["implementation_ref"] = str(forbidden)
    manifest = _write(tmp_path / "manifest.json", _manifest([sink]))
    real_open = os.open
    opened: list[str] = []

    def guarded_open(path: str, flags: int) -> int:
        opened.append(os.fspath(path))
        if os.fspath(path) != str(manifest):
            raise AssertionError("declared implementation reference was opened")
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", guarded_open)
    assert cli.main(["output-handling-audit", "--manifest", str(manifest)]) == cli.EXIT_OK
    assert opened == [str(manifest)]


def test_public_outputs_and_errors_are_non_echoing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secrets = [
        "sink.secret-token",
        _credential_url("SuperSecret"),
        "raw-secret-encoding",
        "未知鍵-秘密",
        "9999999",
    ]
    sink = _sink(secrets[0])
    sink["implementation_ref"] = secrets[1]
    sink["encoding"] = secrets[2]
    sink["max_output_chars"] = 9_999_999
    path = _write(tmp_path / "finding.json", _manifest([sink]))

    for format_name in ("human", "json"):
        assert (
            cli.main(
                ["output-handling-audit", "--manifest", str(path), "--format", format_name]
            )
            == cli.EXIT_CONFIRMED_FINDING
        )
        output = capsys.readouterr().out
        for secret in secrets:
            assert secret not in output

    invalid = _manifest([_sink()])
    invalid[secrets[3]] = secrets[1]
    invalid_path = _write(tmp_path / "invalid.json", invalid)
    assert cli.main(["output-handling-audit", "--manifest", str(invalid_path)]) == 1
    output = capsys.readouterr().out + capsys.readouterr().err
    for secret in secrets:
        assert secret not in output
    assert "llm05_manifest_invalid_top_level" in output


def test_packaged_schema_and_fixtures_are_semantically_valid() -> None:
    root = resources.files("ai_scan.owasp")
    schema_text = root.joinpath("output-handling-manifest-v1.schema.json").read_text(
        encoding="utf-8"
    )
    schema = load_schema_text(schema_text)
    assert schema["$id"] == "https://electricentropy.com/schemas/ai-scan-output-handling-v1"
    secure = audit_manifest_text(
        root.joinpath("output-handling-secure-v1.json").read_text(encoding="utf-8")
    )
    vulnerable = audit_manifest_text(
        root.joinpath("output-handling-vulnerable-v1.json").read_text(encoding="utf-8")
    )
    assert secure.status == "passed"
    assert vulnerable.status == "finding"
    assert vulnerable.findings


def test_schema_semantic_tamper_is_rejected_even_when_valid_json() -> None:
    text = resources.files("ai_scan.owasp").joinpath(
        "output-handling-manifest-v1.schema.json"
    ).read_text(encoding="utf-8")
    doc = json.loads(text)
    doc["properties"]["sinks"]["maxItems"] = 1999
    with pytest.raises(OutputHandlingManifestError, match="llm05_schema_semantic_mismatch"):
        load_schema_text(json.dumps(doc, sort_keys=True))


def test_manifest_file_loader_rejects_oversized_symlink_device_directory_and_fifo(
    tmp_path: Path,
) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (2 * 1024 * 1024 + 1))
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_too_large"):
        load_manifest_file(str(oversized))

    target = _write(tmp_path / "target.json", _manifest([_sink()]))
    link = tmp_path / "link.json"
    link.symlink_to(target)
    for path in (link, Path(os.devnull), tmp_path):
        with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_not_regular"):
            load_manifest_file(str(path))

    fifo = tmp_path / "fifo.json"
    os.mkfifo(fifo)
    start = time.monotonic()
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys;sys.path.insert(0,'src');"
                "from ai_scan.output_handling import load_manifest_file;"
                f"load_manifest_file({str(fifo)!r})"
            ),
        ],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=2,
    )
    assert proc.returncode != 0
    assert time.monotonic() - start < 1.0
    assert "llm05_manifest_not_regular" in proc.stderr


def test_manifest_loader_fails_before_open_without_required_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "manifest.json", _manifest([]))

    def forbidden_open(_path: str, _flags: int) -> int:
        raise AssertionError("must fail before os.open")

    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(os, "open", forbidden_open)
    with pytest.raises(OutputHandlingManifestError, match="llm05_safe_open_unavailable"):
        load_manifest_file(str(path))


@pytest.mark.parametrize("failure", ["read", "seek"])
def test_manifest_loader_maps_read_and_seek_errors_without_echo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    path = _write(tmp_path / "manifest.json", _manifest([]))
    secret = "SuperSecretReadError"  # pragma: allowlist secret

    if failure == "read":
        monkeypatch.setattr(os, "read", lambda _fd, _n: (_ for _ in ()).throw(OSError(secret)))
    else:
        monkeypatch.setattr(os, "lseek", lambda *_args: (_ for _ in ()).throw(OSError(secret)))
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_changed") as exc:
        load_manifest_file(str(path))
    assert secret not in str(exc.value)


def test_manifest_loader_rejects_same_size_second_read_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "manifest.json", _manifest([]))
    real_read = os.read
    reads = 0

    def changed_read(fd: int, size: int) -> bytes:
        nonlocal reads
        chunk = real_read(fd, size)
        if chunk:
            reads += 1
            if reads > 1:
                return chunk.replace(b"sinks", b"zzzzz")
        return chunk

    monkeypatch.setattr(os, "read", changed_read)
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_changed"):
        load_manifest_file(str(path))


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_manifest_rejects_nonfinite_and_overflow_numbers(literal: str) -> None:
    text = json.dumps(_manifest([_sink()]), sort_keys=True)
    text = text.replace("8192", literal)
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_invalid_json"):
        audit_manifest_text(text)


def test_manifest_rejects_excessive_depth_count_string_and_huge_integer() -> None:
    deep: object = "secret"
    for _ in range(20):
        deep = {"nested": deep}
    doc = _manifest([_sink()])
    doc["unexpected"] = deep
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_too_deep"):
        audit_manifest_text(json.dumps(doc))

    too_many = _manifest([_sink(f"sink.item-{index}") for index in range(2001)])
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_too_many_sinks"):
        audit_manifest_text(json.dumps(too_many, separators=(",", ":")))

    long_string = _sink()
    long_string["implementation_ref"] = "x" * 2049
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_string_too_long"):
        audit_manifest_text(json.dumps(_manifest([long_string])))

    huge = _sink()
    huge["max_output_chars"] = 10**100
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_invalid_size_limit"):
        audit_manifest_text(json.dumps(_manifest([huge])))


def test_audit_never_invokes_execution_import_process_or_network_primitives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins
    import importlib

    sink = _sink()
    sink["implementation_ref"] = "plugin://dangerous/module?command=rm"
    text = json.dumps(_manifest([sink]))

    def boom(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("forbidden execution primitive invoked")

    monkeypatch.setattr(builtins, "eval", boom)
    monkeypatch.setattr(builtins, "exec", boom)
    monkeypatch.setattr(importlib, "import_module", boom)
    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(os, "system", boom)
    monkeypatch.setattr(socket.socket, "connect", boom)

    assert audit_manifest_text(text).status == "passed"


def test_manifest_loader_rejects_short_read_and_metadata_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write(tmp_path / "manifest.json", _manifest([]))
    real_read = os.read

    def short_read(fd: int, size: int) -> bytes:
        chunk = real_read(fd, size)
        return chunk[:-1] if chunk else chunk

    monkeypatch.setattr(os, "read", short_read)
    with pytest.raises(OutputHandlingManifestError, match="llm05_manifest_changed"):
        load_manifest_file(str(path))
