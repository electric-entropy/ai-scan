"""Public LLM03/LLM05 failures retain no submitted or parser data."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

import pytest

from ai_scan import cli
from ai_scan.output_handling import OutputHandlingManifestError, load_schema_text
from ai_scan.output_handling import audit_manifest_file as audit_output_file
from ai_scan.output_handling import audit_manifest_text as audit_output_text
from ai_scan.output_handling import load_manifest_file as load_output_file
from ai_scan.supply_chain import SupplyChainManifestError
from ai_scan.supply_chain import audit_manifest_file as audit_supply_file
from ai_scan.supply_chain import audit_manifest_text as audit_supply_text
from ai_scan.supply_chain import load_manifest_file as load_supply_file

_SECRET = "UNIQUE_EXCEPTION_GRAPH_MARKER_2B5"

_Product = tuple[
    str,
    Callable[[str], object],
    Callable[[str], object],
    type[ValueError],
]
_PRODUCTS: tuple[_Product, ...] = (
    (
        "supply-chain-audit",
        audit_supply_file,
        audit_supply_text,
        SupplyChainManifestError,
    ),
    (
        "output-handling-audit",
        audit_output_file,
        audit_output_text,
        OutputHandlingManifestError,
    ),
)
_FILE_FAILURES = ("open", "stat", "read", "seek", "fstat", "close")
_LOADERS = (
    (load_supply_file, SupplyChainManifestError),
    (load_output_file, OutputHandlingManifestError),
)


def _valid_document(command: str) -> dict[str, object]:
    if command == "supply-chain-audit":
        return {"schema_version": "ai-scan-supply-chain-manifest-v1", "items": []}
    return {"schema_version": "ai-scan-output-handling-manifest-v1", "sinks": []}


def _unknown_document(command: str) -> dict[str, object]:
    document = _valid_document(command)
    document[f"unknown_{_SECRET}"] = "value"
    return document


def _semantic_document(command: str) -> dict[str, object]:
    document = _valid_document(command)
    document["schema_version"] = _SECRET
    return document


def _exception_graph_text(exc: BaseException) -> str:
    """Render only exception state and AI-Scan traceback locals, with cycle bounds."""
    rendered: list[str] = []
    pending = [exc]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered.extend((repr(current.args), repr(vars(current))))
        for linked in (current.__cause__, current.__context__):
            if linked is not None:
                pending.append(linked)
        traceback: TracebackType | None = current.__traceback__
        while traceback is not None:
            module = str(traceback.tb_frame.f_globals.get("__name__", ""))
            if module.startswith("ai_scan"):
                rendered.append(repr(traceback.tb_frame.f_locals))
            traceback = traceback.tb_next
    return "\n".join(rendered)


def _assert_clean_public_error(
    exc: BaseException, *, forbidden: tuple[str | bytes, ...]
) -> None:
    assert exc.__cause__ is None
    assert exc.__context__ is None
    assert vars(exc) == {}
    assert len(exc.args) == 1 and isinstance(exc.args[0], str)
    graph = _exception_graph_text(exc)
    for value in forbidden:
        assert repr(value) not in graph
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore")
        assert value not in graph


def _install_file_failure(monkeypatch: pytest.MonkeyPatch, operation: str) -> None:
    secret_error = OSError(f"operating-system-{operation}-{_SECRET}")

    def fail(*_args: object, **_kwargs: object) -> object:
        raise secret_error

    attribute = "lseek" if operation == "seek" else operation
    monkeypatch.setattr(os, attribute, fail)


@pytest.mark.parametrize(("command", "audit_file", "audit_text", "error_type"), _PRODUCTS)
@pytest.mark.parametrize(
    "scenario", ("malformed", "invalid_utf8", "nul_path", "unknown", "semantic")
)
def test_python_manifest_boundaries_discard_all_untrusted_exception_state(
    tmp_path: Path,
    command: str,
    audit_file: Callable[[str], object],
    audit_text: Callable[[str], object],
    error_type: type[ValueError],
    scenario: str,
) -> None:
    path = tmp_path / f"manifest-{_SECRET}.json"
    text_input: str | None = None
    file_input: str | None = None
    if scenario == "malformed":
        submitted: str | bytes = json.dumps({_SECRET: "value"})[:-1] + ", invalid}"
        text_input = submitted
    elif scenario == "invalid_utf8":
        submitted = b"{\xff" + _SECRET.encode()
        path.write_bytes(submitted)
        file_input = str(path)
    elif scenario == "nul_path":
        submitted = f"invalid-{_SECRET}\0path"
        file_input = submitted
    else:
        document = (
            _unknown_document(command)
            if scenario == "unknown"
            else _semantic_document(command)
        )
        submitted = json.dumps(document, sort_keys=True)
        text_input = submitted

    with pytest.raises(error_type) as exc_info:
        if text_input is not None:
            audit_text(text_input)
        else:
            assert file_input is not None
            audit_file(file_input)

    _assert_clean_public_error(exc_info.value, forbidden=(_SECRET, submitted, str(path)))


@pytest.mark.parametrize(("command", "audit_file", "audit_text", "error_type"), _PRODUCTS)
@pytest.mark.parametrize("operation", _FILE_FAILURES)
def test_python_manifest_file_failures_discard_nested_os_exceptions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    audit_file: Callable[[str], object],
    audit_text: Callable[[str], object],
    error_type: type[ValueError],
    operation: str,
) -> None:
    del audit_text
    path = tmp_path / f"manifest-{_SECRET}.json"
    path.write_text(json.dumps(_valid_document(command)), encoding="utf-8")
    _install_file_failure(monkeypatch, operation)

    with pytest.raises(error_type) as exc_info:
        audit_file(str(path))

    _assert_clean_public_error(exc_info.value, forbidden=(_SECRET, str(path)))


@pytest.mark.parametrize(("loader", "error_type"), _LOADERS)
@pytest.mark.parametrize("operation", _FILE_FAILURES)
def test_public_loaders_discard_nested_os_exceptions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    loader: Callable[[str], str],
    error_type: type[ValueError],
    operation: str,
) -> None:
    path = tmp_path / f"loader-{_SECRET}.json"
    path.write_text("{}", encoding="utf-8")
    _install_file_failure(monkeypatch, operation)

    with pytest.raises(error_type) as exc_info:
        loader(str(path))

    _assert_clean_public_error(exc_info.value, forbidden=(_SECRET, str(path)))


@pytest.mark.parametrize(
    "schema_text",
    (
        json.dumps({_SECRET: "value"})[:-1] + ", invalid}",
        json.dumps({"$schema": _SECRET}),
    ),
)
def test_public_schema_loader_discards_parser_and_semantic_input(schema_text: str) -> None:
    with pytest.raises(OutputHandlingManifestError) as exc_info:
        load_schema_text(schema_text)

    _assert_clean_public_error(exc_info.value, forbidden=(_SECRET, schema_text))


@pytest.mark.parametrize(("command", "audit_file", "audit_text", "error_type"), _PRODUCTS)
@pytest.mark.parametrize(
    "scenario", ("malformed", "invalid_utf8", "nul_path", "unknown", "semantic")
)
def test_cli_manifest_failures_never_print_submitted_data(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    audit_file: Callable[[str], object],
    audit_text: Callable[[str], object],
    error_type: type[ValueError],
    scenario: str,
) -> None:
    del audit_file, audit_text, error_type
    path = tmp_path / f"manifest-{_SECRET}.json"
    if scenario == "invalid_utf8":
        path.write_bytes(b"{\xff" + _SECRET.encode())
        submitted = str(path)
    elif scenario == "nul_path":
        submitted = f"invalid-{_SECRET}\0path"
    else:
        if scenario == "malformed":
            text = json.dumps({_SECRET: "value"})[:-1] + ", invalid}"
        else:
            document = (
                _unknown_document(command)
                if scenario == "unknown"
                else _semantic_document(command)
            )
            text = json.dumps(document, sort_keys=True)
        path.write_text(text, encoding="utf-8")
        submitted = str(path)

    assert cli.main([command, "--manifest", submitted]) == cli.EXIT_RUNTIME_ERROR
    output = capsys.readouterr().out + capsys.readouterr().err
    assert _SECRET not in output
    assert submitted not in output
