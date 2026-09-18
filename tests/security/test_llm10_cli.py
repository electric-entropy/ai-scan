"""LLM10 public command, packaged contract and no side effects."""
from __future__ import annotations

import builtins
import copy
import io
import json
import os
import socket
import subprocess
import sys
from importlib import resources

import pytest
from jsonschema import Draft202012Validator

from ai_scan import cli
from ai_scan import consumption as api
from tests.security.test_llm09_cli import assert_exception_clean
from tests.security.test_llm10_consumption import (
    CONTROLS,
    EVENTS,
    NUMBERS,
    RULES,
    manifest,
    vulnerable,
)
from tests.security.test_llm10_contract import FIELDS, nodes
from tests.security.test_safe_manifest_file_edges import _RACES, _install_race


def root():
    return resources.files("ai_scan.owasp")


def schema():
    path = root().joinpath("consumption-manifest-v1.schema.json")
    assert path.is_file(), "packaged schema missing"
    return api.load_schema_text(path.read_text())


def test_schema_exact_closed_and_structural_parity():
    document = schema()
    Draft202012Validator.check_schema(document)
    validator = Draft202012Validator(document)
    assert validator.is_valid(manifest())
    for index, key in FIELDS:
        doc = manifest()
        del nodes(doc)[index][key]
        assert not validator.is_valid(doc)
    for index in range(6):
        doc = manifest()
        nodes(doc)[index]["risk"] = "private.submitted"
        assert not validator.is_valid(doc)
    for role in ("secure", "vulnerable"):
        doc = json.loads(root().joinpath(f"consumption-{role}-v1.json").read_text())
        assert validator.is_valid(doc)
    changed = copy.deepcopy(document)
    changed["additionalProperties"] = True
    with pytest.raises(api.ConsumptionManifestError):
        api.load_schema_text(json.dumps(changed))
    # Standard JSON Schema integers include 1.0; the documented runtime domain is stricter.
    doc = manifest()
    doc["scenarios"][0]["observations"]["requests"] = 1.0
    assert validator.is_valid(doc)
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_text(json.dumps(doc))


def test_schema_all_field_domains_and_semantic_boundaries():
    validator = Draft202012Validator(schema())
    for group in ("ceilings", "observations"):
        for key in NUMBERS:
            for value in (0, 1000000000, -1, 1000000001, True, None, "1", [], {}, 0.5):
                doc = manifest()
                s = doc["scenarios"][0]
                s[group] = dict.fromkeys(NUMBERS, 0)
                s[group][key] = value
                valid = type(value) is int and 0 <= value <= 1000000000
                if valid and key in ("input_tokens", "output_tokens"):
                    s[group]["total_tokens"] = value
                if valid and key == "total_tokens":
                    s[group]["input_tokens"] = value
                assert validator.is_valid(doc) is valid
                if valid:
                    api.audit_manifest_text(json.dumps(doc))
                else:
                    with pytest.raises(api.ConsumptionManifestError):
                        api.audit_manifest_text(json.dumps(doc))
    for group, fields in (("controls", CONTROLS), ("events", EVENTS)):
        for field in fields:
            for value in (0, 1, 1.0, None, "true", [], {}):
                doc = manifest()
                doc["scenarios"][0][group][field] = value
                assert not validator.is_valid(doc)
    for index, key in ((0, "context_ref"), (1, "scenario_ref")):
        for value in ("a.b", "a." + "b" * 62, "a" + ".b" * 15):
            doc = manifest()
            nodes(doc)[index][key] = value
            assert validator.is_valid(doc)
            api.audit_manifest_text(json.dumps(doc))
        for value in ("a.b\n", "a.b\r", "a.b\0", "a." + "b" * 63, "a" + ".b" * 16):
            doc = manifest()
            nodes(doc)[index][key] = value
            assert not validator.is_valid(doc)
    for field in ("work_after_cancellation", "work_after_exhaustion", "cleanup_observed"):
        doc = manifest()
        doc["scenarios"][0]["events"][field] = True
        assert not validator.is_valid(doc)


@pytest.mark.parametrize("change", ["same_size", "append", "truncate", "short_read"])
def test_same_descriptor_changes_reject(change, tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    text = json.dumps(manifest())
    path.write_text(text)
    real_read = os.read
    changed = False

    def racing_read(fd, size):
        nonlocal changed
        chunk = real_read(fd, size)
        if not changed:
            changed = True
            if change == "short_read":
                return b""
            replacement = {"same_size": text.replace("context.primary", "context.changed"),
                           "append": text + " ", "truncate": text[:-1]}[change]
            assert change != "same_size" or len(replacement) == len(text)
            path.write_text(replacement)
        return chunk

    monkeypatch.setattr(os, "read", racing_read)
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_file(str(path))


@pytest.mark.parametrize("format", ["json", "text"])
@pytest.mark.parametrize("role,code", [("secure", 0), ("vulnerable", 3)])
def test_fixtures_cli_and_rule_isolation(format, role, code, capsys):
    path = root().joinpath(f"consumption-{role}-v1.json")
    assert cli.main(["consumption-audit", "--manifest", str(path), "--format", format]) == code
    output = capsys.readouterr()
    assert not output.err
    doc = json.loads(path.read_text())
    assert str(path) not in output.out
    assert doc["context_ref"] not in output.out
    assert all(s["scenario_ref"] not in output.out for s in doc["scenarios"])
    if format == "json":
        result = json.loads(output.out)
        assert result["network_requests"] == result["executions"] == 0
        assert len(result["findings"]) == (8 if code else 0)
    if code:
        observed = []
        for s in doc["scenarios"]:
            result = api.audit_manifest_text(json.dumps({**doc, "scenarios": [s]}))
            assert len(result.findings) == 1
            observed.append(result.findings[0].rule)
        assert set(observed) == set(RULES)


@pytest.mark.parametrize("kind", ["missing", "json", "utf8", "nul", "directory", "symlink",
                                  "fifo", "device", "oversize"])
@pytest.mark.parametrize("format", ["json", "text"])
def test_invalid_fixed_code_and_no_echo(kind, format, tmp_path, capsys):
    path = tmp_path / "private-submitted-path"
    if kind == "json":
        path.write_text('{"private-submitted-ref":')
    elif kind == "utf8":
        path.write_bytes(b"private-submitted-ref\xff")
    elif kind == "nul":
        path = str(path) + "\0private-submitted-ref"
    elif kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        path.symlink_to(tmp_path)
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "device":
        path = "/dev/null"
    elif kind == "oversize":
        path.write_bytes(b" " * (api.MAX_MANIFEST_BYTES + 1))
    assert cli.main(["consumption-audit", "--manifest", str(path), "--format", format]) == 2
    output = capsys.readouterr()
    assert not output.err
    if format == "json":
        assert json.loads(output.out) == {"error": "llm10_manifest_invalid", "executions": 0,
                                         "network_requests": 0}
    else:
        assert output.out.strip() == "invalid: llm10_manifest_invalid"


@pytest.mark.parametrize("race", _RACES)
def test_file_races(race, tmp_path, monkeypatch):
    path, replacement = tmp_path / "private.json", tmp_path / "replacement.json"
    text = json.dumps(manifest())
    path.write_text(text)
    replacement.write_text(text + " ")
    _install_race(monkeypatch, path, replacement, race)
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_file(str(path))


@pytest.mark.parametrize("operation", ["text", "file", "schema"])
@pytest.mark.parametrize("text", ['{"private-submitted-ref":',
    '{"context_ref":"private-submitted-ref","context_ref":null}',
    json.dumps(manifest()).replace("scenario.primary", "private-submitted-ref/"),
    "\ud800private-submitted-ref", "[" * 1000 + "0" + "]" * 1000])
def test_exception_graph_and_project_locals(operation, text, tmp_path):
    path = tmp_path / "private-submitted-path"
    if operation == "file":
        path.write_bytes(text.encode("utf-8", errors="surrogatepass"))
    assert hasattr(api, "load_schema_text"), "schema boundary missing"
    method = {"text": api.audit_manifest_text, "file": api.audit_manifest_file,
              "schema": api.load_schema_text}[operation]
    try:
        method(str(path) if operation == "file" else text)
    except api.ConsumptionManifestError as exc:
        assert_exception_clean(exc, ["private-submitted-ref", "private-submitted-path",
                                     "scenario.primary", "context.primary"])
    else:
        pytest.fail("invalid accepted")


@pytest.mark.parametrize("value", [None, b"{}", {}, [], True, 1])
def test_public_types(value):
    for method in (api.audit_manifest_text, api.audit_manifest_file, api.load_manifest_file):
        with pytest.raises(api.ConsumptionManifestError):
            method(value)


def test_byte_boundary(tmp_path):
    text = json.dumps(manifest())
    for delta in (0, 1):
        padded = text + " " * (api.MAX_MANIFEST_BYTES - len(text) + delta)
        path = tmp_path / "manifest.json"
        path.write_text(padded)
        for method, value in ((api.audit_manifest_file, str(path)),
                              (api.audit_manifest_text, padded)):
            if delta:
                with pytest.raises(api.ConsumptionManifestError):
                    method(value)
            else:
                assert method(value).status == "passed"


@pytest.mark.parametrize("failure", ["read", "lseek", "fstat", "stat"])
def test_descriptor_errors_close_and_hide(failure, monkeypatch, tmp_path):
    path = tmp_path / "private-submitted-path"
    path.write_text(json.dumps(manifest()))
    real_open, real_close = os.open, os.close
    opened, closed = [], []

    def open_file(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def close_file(fd):
        closed.append(fd)
        return real_close(fd)

    def fail(*args, **kwargs):
        raise OSError("private-submitted-ref")

    with monkeypatch.context() as m:
        m.setattr(os, "open", open_file)
        m.setattr(os, "close", close_file)
        m.setattr(os, failure, fail)
        try:
            api.audit_manifest_file(str(path))
        except api.ConsumptionManifestError as exc:
            assert_exception_clean(exc, ["private-submitted-path", "private-submitted-ref"])
        else:
            pytest.fail("I/O failure accepted")
    assert len(opened) == 1 and closed == opened


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK"])
def test_missing_flags_fail_before_open(flag, monkeypatch):
    monkeypatch.delattr(os, flag)
    monkeypatch.setattr(os, "open", lambda *a, **kw: pytest.fail("unsafe open"))
    with pytest.raises(api.ConsumptionManifestError):
        api.audit_manifest_file("private-submitted-path")


@pytest.mark.parametrize("role", ["secure", "vulnerable"])
def test_no_dereference_or_side_effects(role, monkeypatch, capsys):
    path = str(root().joinpath(f"consumption-{role}-v1.json"))
    parser = cli.build_parser()
    real_open = os.open

    def deny(*args, **kwargs):
        pytest.fail("unexpected execution/reference access")

    def only_manifest(file, *args, **kwargs):
        assert file == path
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(cli, "build_parser", lambda: parser)
        m.setattr(os, "open", only_manifest)
        for obj, name in [(builtins, "open"), (io, "open"), (builtins, "input"),
                          (builtins, "eval"), (builtins, "exec"),
                          (socket.socket, "connect"), (socket, "getaddrinfo"),
                          (subprocess, "Popen"), (os, "system"), (sys.stdin, "read"),
                          (cli, "_make_transport"), (builtins, "__import__")]:
            m.setattr(obj, name, deny)
        assert cli.main(["consumption-audit", "--manifest", path]) == (0 if role == "secure" else 3)
    assert "network_requests" in capsys.readouterr().out


@pytest.mark.parametrize("mutation", ["swap", "schema", "missing_rule", "no_isolation"])
def test_doctor_semantic_drift(mutation, monkeypatch, capsys):
    original = api.load_manifest_file

    def changed(path):
        if "consumption-" in path:
            if mutation == "swap":
                if "secure-v1" in path:
                    return original(path.replace("secure-v1", "vulnerable-v1"))
                if "vulnerable-v1" in path:
                    return original(path.replace("vulnerable-v1", "secure-v1"))
            if mutation == "schema" and path.endswith("schema.json"):
                doc = json.loads(original(path))
                doc["additionalProperties"] = True
                return json.dumps(doc)
            if mutation == "missing_rule" and "vulnerable-v1" in path:
                return json.dumps(vulnerable("deadline"))
            if mutation == "no_isolation" and "vulnerable-v1" in path:
                doc = json.loads(original(path))
                # Preserve every rule and total findings, but move them into one scenario.
                merged = copy.deepcopy(manifest()["scenarios"][0])
                for s in doc["scenarios"]:
                    for group in ("controls", "events", "observations"):
                        for key, value in s[group].items():
                            if value != manifest()["scenarios"][0][group][key]:
                                merged[group][key] = value
                doc["scenarios"] = [merged]
                return json.dumps(doc)
        return original(path)

    monkeypatch.setattr(api, "load_manifest_file", changed)
    assert cli.main(["doctor", "--json"]) == 1
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert not next(c for c in checks if c["name"] == "owasp-llm10-consumption-resources")["ok"]


def test_doctor_and_exact_category_set(capsys):
    from ai_scan.orchestration import compile_plan
    from ai_scan.owasp_llm import load_coverage_matrix
    from ai_scan.targets import normalize_target

    assert cli.main(["doctor", "--json"]) == 0
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert next(c for c in checks if c["name"] == "owasp-llm10-consumption-resources")["ok"]
    matrix = load_coverage_matrix()
    assert {c.id for c in matrix.categories if c.current_active_cli_coverage} == {
        f"LLM{i:02}" for i in range(1, 11)}
    assert all(not c.full_coverage_claim_allowed for c in matrix.categories)
    for mode, count in (("reliable", 20), ("kitchen-sink", 40)):
        assert len(compile_plan(target=normalize_target("http://127.0.0.1:8000/"),
                                mode=mode).cases) == count


@pytest.mark.parametrize("args", [[], ["--manifest"],
    ["--manifest", "private-submitted-path", "--format", "private-submitted-ref"],
    ["--manifest", "private-submitted-path", "--private-submitted-ref"]])
def test_usage_errors(args, capsys):
    assert cli.main(["consumption-audit", *args]) == 2
    output = capsys.readouterr()
    assert "private-submitted" not in output.out + output.err
    assert "llm10_manifest_invalid" in output.out


@pytest.mark.parametrize("role", ["secure", "vulnerable"])
def test_real_syscalls(role, tmp_path):
    trace = tmp_path / "trace.log"
    path = root().joinpath(f"consumption-{role}-v1.json")
    result = subprocess.run([
        "strace", "-f", "-e", "trace=connect,execve", "-o", str(trace),
        sys.executable, "-m", "ai_scan", "consumption-audit", "--manifest", str(path),
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == (0 if role == "secure" else 3), result.stderr
    assert "LLM10 Unbounded Consumption" in result.stdout
    lines = trace.read_text().splitlines()
    assert not any("connect(" in line for line in lines)
    assert len([line for line in lines if "execve(" in line]) == 1
