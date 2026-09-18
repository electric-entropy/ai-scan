"""Adversarial public LLM06 boundaries; no declared object may be resolved."""

from __future__ import annotations

import builtins
import importlib
import io
import json
import os
import socket
import subprocess
import sys
from importlib import resources

import pytest

from ai_scan import agency, cli
from tests.security.test_llm06_agency import manifest, tool
from tests.security.test_manifest_exception_graph import (
    _assert_clean_public_error,
    _install_file_failure,
)
from tests.security.test_safe_manifest_file_edges import _RACES, _install_race


@pytest.mark.parametrize("name,code", [("secure", 0), ("vulnerable", cli.EXIT_CONFIRMED_FINDING)])
def test_both_fixtures_classify_with_every_execution_boundary_exploding(name, code, monkeypatch):
    path = str(resources.files("ai_scan.owasp").joinpath(f"agency-{name}-v1.json"))
    parser = cli.build_parser()
    parser.parse_args(["agency-audit", "--manifest", path])
    real_open = os.open
    opened = []

    def only_manifest(candidate, flags):
        assert candidate == path
        opened.append(candidate)
        return real_open(candidate, flags)

    def boom(*args, **kwargs):
        raise AssertionError("forbidden execution or resolution")

    with monkeypatch.context() as m:

        class NoInput:
            def read(self, *args):
                return boom()

            def readline(self, *args):
                return boom()

        m.setattr(sys, "stdin", NoInput())
        m.setattr(cli, "build_parser", lambda: parser)
        m.setattr(cli, "_make_transport", boom)
        m.setattr(os, "open", only_manifest)
        for owner, attrs in (
            (builtins, ("input", "open", "eval", "exec")),
            (io, ("open",)),
            (importlib, ("import_module",)),
            (socket.socket, ("connect", "connect_ex")),
            (socket, ("create_connection",)),
            (subprocess, ("run", "Popen", "call", "check_output")),
            (os, ("system", "popen", "fork", "posix_spawn")),
        ):
            for attr in attrs:
                m.setattr(owner, attr, boom)
        real_import = builtins.__import__
        builtins.__import__ = boom
        try:
            actual = cli.main(["agency-audit", "--manifest", path])
        finally:
            builtins.__import__ = real_import
        assert actual == code
    assert opened == [path]


def test_two_thousand_hostile_distinct_ids_are_opaque_and_not_retained():
    ids = [f"hostile.secret-payload-{i}" for i in range(2000)]
    items = [tool("read", ident) for ident in ids]
    for item in items:
        item["result_trust"] = "trusted"
    result = agency.audit_manifest_text(json.dumps(manifest(*items)))
    assert len(set(result.tool_refs)) == len(ids)
    assert len(result.findings) == len(ids)
    assert all(ref.startswith("llm06-tool-") and len(ref) == 75 for ref in result.tool_refs)
    output = repr(result) + agency.render_json(result) + agency.render_human(result)
    assert all(ident not in output for ident in ids)
    assert "secret-payload" not in output
    with pytest.raises(agency.AgencyManifestError):
        agency.audit_manifest_text(json.dumps(manifest(*items, tool("read", "extra.item"))))


@pytest.mark.parametrize("operation", ["open", "stat", "read", "seek", "fstat", "close"])
@pytest.mark.parametrize("loader", [agency.audit_manifest_file, agency.load_manifest_file])
def test_file_errors_have_clean_exception_graph(operation, loader, monkeypatch, tmp_path):
    path = tmp_path / "HOSTILE-PATH.json"
    path.write_text(json.dumps(manifest(tool())))
    _install_file_failure(monkeypatch, operation)
    with pytest.raises(agency.AgencyManifestError) as error:
        loader(str(path))
    _assert_clean_public_error(
        error.value, forbidden=(str(path), "UNIQUE_EXCEPTION_GRAPH_MARKER_2B5")
    )


@pytest.mark.parametrize(
    "text",
    [
        '{"HOSTILE":',
        '{"HOSTILE":1,"HOSTILE":2}',
        '{"HOSTILE":1e999}',
        '{"HOSTILE":NaN}',
        "\ud800HOSTILE",
        "[" * 500 + '"HOSTILE"' + "]" * 500,
        json.dumps(manifest(tool("read", "HOSTILE"))),
    ],
)
@pytest.mark.parametrize("loader", [agency.audit_manifest_text, agency.load_schema_text])
def test_text_errors_have_clean_exception_graph(text, loader):
    with pytest.raises(agency.AgencyManifestError) as error:
        loader(text)
    _assert_clean_public_error(error.value, forbidden=(text, "HOSTILE"))


@pytest.mark.parametrize("race", _RACES)
@pytest.mark.parametrize("interface", ["file", "cli"])
def test_path_descriptor_races_fail_closed(race, interface, monkeypatch, tmp_path, capsys):
    path = tmp_path / "HOSTILE.json"
    replacement = tmp_path / "replacement.json"
    path.write_text(json.dumps(manifest(tool())))
    replacement.write_text(json.dumps(manifest(tool("update"))))
    _install_race(monkeypatch, path, replacement, race)
    if interface == "file":
        with pytest.raises(agency.AgencyManifestError) as error:
            agency.audit_manifest_file(str(path))
        _assert_clean_public_error(error.value, forbidden=(str(path), "HOSTILE"))
    else:
        assert cli.main(["agency-audit", "--manifest", str(path)]) == 1
        out = capsys.readouterr()
        assert out.out == "invalid: llm06_manifest_invalid\n" and out.err == ""


@pytest.mark.parametrize(
    "kind", ["symlink", "directory", "fifo", "device", "oversize", "utf8", "nul"]
)
def test_special_files_and_invalid_bytes_reject(kind, tmp_path):
    path = tmp_path / "HOSTILE"
    if kind == "symlink":
        path.symlink_to(tmp_path / "missing")
    elif kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "device":
        path = os.devnull
    elif kind == "oversize":
        path.write_bytes(b" " * (agency.MAX_MANIFEST_BYTES + 1))
    elif kind == "utf8":
        path.write_bytes(b"HOSTILE\xff")
    else:
        path = "HOSTILE\0path"
    with pytest.raises(agency.AgencyManifestError) as error:
        agency.audit_manifest_file(str(path))
    _assert_clean_public_error(error.value, forbidden=(str(path), "HOSTILE"))


@pytest.mark.parametrize("flag", ["O_NONBLOCK", "O_NOFOLLOW"])
def test_missing_safe_flag_never_opens(flag, monkeypatch):
    def boom(*args):
        raise AssertionError("unsafe open")

    monkeypatch.delattr(os, flag)
    monkeypatch.setattr(os, "open", boom)
    with pytest.raises(agency.AgencyManifestError):
        agency.load_manifest_file("HOSTILE")


@pytest.mark.parametrize("format_name", ["json", "human"])
def test_cli_all_output_channels_non_echo(format_name, tmp_path, capsys):
    item = tool("delete", "hostile.secret-id")
    item.update(
        resource_ref="hostile.secret-resource",
        destination_ref="hostile.secret-dest",
        object_ref="hostile.secret-object",
        result_trust="trusted",
    )
    path = tmp_path / "HOSTILE.json"
    path.write_text(json.dumps(manifest(item)))
    assert (
        cli.main(["agency-audit", "--manifest", str(path), "--format", format_name])
        == cli.EXIT_CONFIRMED_FINDING
    )
    out = capsys.readouterr()
    assert "hostile.secret" not in out.out + out.err
    assert "HOSTILE" not in out.out + out.err and not out.err
    path.write_text('{"HOSTILE":"SECRET"}')
    assert cli.main(["agency-audit", "--manifest", str(path), "--format", format_name]) == 1
    out = capsys.readouterr()
    assert out.out == "invalid: llm06_manifest_invalid\n" and not out.err


@pytest.mark.parametrize("mode", ["short", "second", "append", "truncate"])
def test_same_descriptor_read_changes_reject(mode, monkeypatch, tmp_path):
    path = tmp_path / "HOSTILE.json"
    path.write_text(json.dumps(manifest(tool())))
    real_read = os.read
    reads = 0

    def mutate(fd, size):
        nonlocal reads
        data = real_read(fd, size)
        if data:
            reads += 1
            if mode == "short":
                return data[:-1]
            if mode == "second" and reads == 2:
                return data.replace(b"tool.primary", b"tool.changed")
            if reads == 1 and mode == "append":
                with path.open("ab") as stream:
                    stream.write(b" ")
            if reads == 1 and mode == "truncate":
                path.write_bytes(b"{}")
        return data

    monkeypatch.setattr(os, "read", mutate)
    with pytest.raises(agency.AgencyManifestError) as error:
        agency.audit_manifest_file(str(path))
    _assert_clean_public_error(error.value, forbidden=(str(path), "HOSTILE"))
