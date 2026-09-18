"""Public command, inert resources, safe file and exception boundary."""
from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
import sys
from importlib import resources

import pytest

from ai_scan import cli
from ai_scan import misinformation as api
from tests.security.test_llm09_misinformation import manifest, vulnerable
from tests.security.test_safe_manifest_file_edges import _RACES, _install_race


def root():
    return resources.files("ai_scan.owasp")


@pytest.mark.parametrize("format", ["json", "text"])
@pytest.mark.parametrize("role,exit_code", [("secure", 0), ("vulnerable", 3)])
def test_packaged_fixtures_public_cli(role, exit_code, format, capsys):
    path = root().joinpath(f"misinformation-{role}-v1.json")
    args = ["misinformation-audit", "--manifest", str(path), "--format", format]
    assert cli.main(args) == exit_code
    output = capsys.readouterr()
    assert not output.err
    assert str(path) not in output.out
    text = path.read_text()
    submitted = json.loads(text)
    refs = [submitted["context_ref"]]
    for case in submitted["cases"]:
        refs.extend(case[k] for k in case if k.endswith("_ref"))
        for claim in case["expected_claims"] + case["observed_claims"]:
            refs.extend(claim[k] for k in ("claim_ref", "source_ref", "value_sha256"))
    assert all(v not in output.out for v in refs)
    if format == "json":
        doc = json.loads(output.out)
        assert doc["network_requests"] == doc["executions"] == 0
        assert len(doc["findings"]) == (5 if exit_code else 0)
        assert {f["rule_id"] for f in doc["findings"]} == (
            {"llm09." + r for r in api._RULE_META} if exit_code else set())
    if exit_code:
        # Each packaged case independently isolates one rule, not a verdict switch.
        for case in submitted["cases"]:
            single = {**submitted, "cases": [case]}
            assert len(api.audit_manifest_text(json.dumps(single)).findings) == 1


@pytest.mark.parametrize("kind", ["missing", "json", "utf8", "nul", "directory", "symlink",
                                  "fifo", "device", "oversize"])
@pytest.mark.parametrize("format", ["json", "text"])
def test_invalid_cli_is_two_and_never_echoes(kind, format, tmp_path, capsys):
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
    assert cli.main(["misinformation-audit", "--manifest", str(path), "--format", format]) == 2
    output = capsys.readouterr()
    assert not output.err
    if format == "json":
        assert json.loads(output.out) == {"error": "llm09_manifest_invalid",
                                        "executions": 0, "network_requests": 0}
    else:
        assert output.out.strip() == "invalid: llm09_manifest_invalid"


@pytest.mark.parametrize("race", _RACES)
@pytest.mark.parametrize("interface", ["file", "cli"])
def test_file_races_fail_closed(race, interface, tmp_path, monkeypatch, capsys):
    path, replacement = tmp_path / "private.json", tmp_path / "replacement.json"
    text = json.dumps(manifest())
    path.write_text(text)
    replacement.write_text(text + " ")
    _install_race(monkeypatch, path, replacement, race)
    if interface == "file":
        with pytest.raises(api.MisinformationManifestError):
            api.audit_manifest_file(str(path))
    else:
        assert cli.main(["misinformation-audit", "--manifest", str(path)]) == 2
        assert capsys.readouterr().out.strip() == "invalid: llm09_manifest_invalid"


def assert_exception_clean(exc, submitted):
    seen = set()
    stack = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        assert all(raw not in repr((current.args, vars(current))) for raw in submitted)
        tb = current.__traceback__
        while tb:
            if "/src/ai_scan/" in tb.tb_frame.f_code.co_filename:
                assert all(raw not in repr(tb.tb_frame.f_locals) for raw in submitted)
            tb = tb.tb_next
        stack.extend(e for e in (current.__cause__, current.__context__) if e is not None)


@pytest.mark.parametrize("mode", ["text", "file", "schema"])
@pytest.mark.parametrize("text", ['{"private-submitted-ref":',
    '{"context_ref":"private-submitted-ref","context_ref":null}',
    json.dumps(manifest()).replace("claim.primary", "private-submitted-ref/"),
    "\ud800private-submitted-ref", "[" * 1000 + "0" + "]" * 1000])
def test_exception_graph_and_product_locals_are_clean(mode, text, tmp_path):
    path = tmp_path / "private-submitted-path"
    if mode == "file":
        path.write_bytes(text.encode("utf-8", errors="surrogatepass"))
    operation = {"text": api.audit_manifest_text, "file": api.audit_manifest_file,
                 "schema": api.load_schema_text}[mode]
    try:
        operation(str(path) if mode == "file" else text)
    except api.MisinformationManifestError as exc:
        assert_exception_clean(exc, ["private-submitted-ref", "private-submitted-path",
                                    "claim.primary", "context.primary", "a" * 64])
    else:
        pytest.fail("invalid accepted")


@pytest.mark.parametrize("value", [None, b"{}", {}, [], True, 1])
def test_public_input_types(value):
    for operation in (api.audit_manifest_text, api.audit_manifest_file, api.load_schema_text):
        with pytest.raises(api.MisinformationManifestError):
            operation(value)


def test_byte_boundary_and_stable_double_read(tmp_path):
    text = json.dumps(manifest())
    for delta in [0, 1]:
        padded = text + " " * (api.MAX_MANIFEST_BYTES - len(text) + delta)
        path = tmp_path / "manifest.json"
        path.write_text(padded)
        if delta:
            with pytest.raises(api.MisinformationManifestError):
                api.audit_manifest_file(str(path))
            with pytest.raises(api.MisinformationManifestError):
                api.audit_manifest_text(padded)
        else:
            assert api.audit_manifest_file(str(path)).status == "passed"
            assert api.audit_manifest_text(padded).status == "passed"


@pytest.mark.parametrize("failure", ["read", "lseek", "fstat", "stat"])
def test_descriptor_failures_are_fixed_and_closed(failure, monkeypatch, tmp_path):
    path = tmp_path / "private-submitted-path"
    path.write_text(json.dumps(manifest()))
    real_open, real_close = os.open, os.close
    opened, closed = [], []

    def opened_file(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def closed_file(fd):
        closed.append(fd)
        return real_close(fd)

    def fail(*args, **kwargs):
        raise OSError("private-submitted-ref")

    with monkeypatch.context() as m:
        m.setattr(os, "open", opened_file)
        m.setattr(os, "close", closed_file)
        m.setattr(os, failure, fail)
        try:
            api.audit_manifest_file(str(path))
        except api.MisinformationManifestError as exc:
            assert_exception_clean(exc, ["private-submitted-path", "private-submitted-ref"])
        else:
            pytest.fail("I/O failure accepted")
    assert len(opened) == 1 and closed == opened


@pytest.mark.parametrize("flag", ["O_NOFOLLOW", "O_NONBLOCK"])
def test_missing_safe_flags_reject_before_open(flag, monkeypatch):
    monkeypatch.delattr(os, flag)
    monkeypatch.setattr(os, "open", lambda *a, **kw: pytest.fail("unsafe open"))
    with pytest.raises(api.MisinformationManifestError):
        api.audit_manifest_file("private-submitted-path")


@pytest.mark.parametrize("role", ["secure", "vulnerable"])
def test_command_never_executes_or_dereferences(role, monkeypatch, capsys):
    path = str(root().joinpath(f"misinformation-{role}-v1.json"))
    # Build parser before blocking imports; parser construction belongs to the existing CLI.
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
        assert cli.main(["misinformation-audit", "--manifest", path]) == (
            0 if role == "secure" else 3)
    assert "network_requests" in capsys.readouterr().out


@pytest.mark.parametrize("mutation", ["swap", "schema", "missing_rule"])
def test_doctor_semantically_rejects_fixture_or_schema_drift(mutation, monkeypatch, capsys):
    original = api.load_manifest_file

    def changed(path):
        if "misinformation-" in path:
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
                return json.dumps(vulnerable("missing_claim"))
        return original(path)

    monkeypatch.setattr(api, "load_manifest_file", changed)
    assert cli.main(["doctor", "--json"]) == 1
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert not next(c for c in checks if c["name"] == "owasp-llm09-misinformation-resources")["ok"]


def test_doctor_validates_resources(capsys):
    assert cli.main(["doctor", "--json"]) == 0
    checks = json.loads(capsys.readouterr().out)["checks"]
    assert next(c for c in checks if c["name"] == "owasp-llm09-misinformation-resources")["ok"]


@pytest.mark.parametrize("args", [[], ["--manifest"],
    ["--manifest", "private-submitted-path", "--format", "private-submitted-ref"],
    ["--manifest", "private-submitted-path", "--private-submitted-ref"],
    ["--manifest", "private-submitted-path", "--format", "json", "--extra"]])
def test_usage_errors_are_fixed_and_two(args, capsys):
    assert cli.main(["misinformation-audit", *args]) == 2
    output = capsys.readouterr()
    assert "private-submitted" not in output.out + output.err
    assert "llm09_manifest_invalid" in output.out


def test_exact_active_category_set_and_unchanged_plans():
    from ai_scan.orchestration import compile_plan
    from ai_scan.owasp_llm import load_coverage_matrix
    from ai_scan.targets import normalize_target

    matrix = load_coverage_matrix()
    assert {c.id for c in matrix.categories if c.current_active_cli_coverage} == {
        f"LLM{i:02}" for i in range(1, 10)}
    assert all(not c.full_coverage_claim_allowed for c in matrix.categories)
    for mode, count in [("reliable", 20), ("kitchen-sink", 40)]:
        plan = compile_plan(target=normalize_target("http://127.0.0.1:8000/"), mode=mode)
        assert len(plan.cases) == count


@pytest.mark.parametrize("change", ["same_size", "append", "truncate", "short_read"])
def test_descriptor_contents_changing_reject(change, tmp_path, monkeypatch):
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
            replacement = {"same_size": text.replace("source.primary", "source.changed"),
                           "append": text + " ", "truncate": text[:-1]}[change]
            assert change != "same_size" or len(replacement) == len(text)
            path.write_text(replacement)
        return chunk

    monkeypatch.setattr(os, "read", racing_read)
    with pytest.raises(api.MisinformationManifestError):
        api.audit_manifest_file(str(path))


@pytest.mark.parametrize("role", ["secure", "vulnerable"])
def test_real_command_syscalls_have_no_connect_or_child_exec(role, tmp_path):
    trace = tmp_path / "trace.log"
    path = root().joinpath(f"misinformation-{role}-v1.json")
    result = subprocess.run([
        "strace", "-f", "-e", "trace=connect,execve", "-o", str(trace),
        sys.executable, "-m", "ai_scan", "misinformation-audit", "--manifest", str(path),
    ], capture_output=True, text=True, timeout=20)
    assert result.returncode == (0 if role == "secure" else 3), result.stderr
    assert "LLM09 Misinformation" in result.stdout
    lines = trace.read_text().splitlines()
    assert not any("connect(" in line for line in lines)
    assert len([line for line in lines if "execve(" in line]) == 1
