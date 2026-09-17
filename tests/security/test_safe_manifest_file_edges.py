"""Shared pathname/descriptor race regressions for LLM03 and LLM05 loaders."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.core.safe_file import SafeFileError, read_stable_regular_file
from ai_scan.output_handling import OutputHandlingManifestError
from ai_scan.output_handling import load_manifest_file as load_output_manifest
from ai_scan.supply_chain import SupplyChainManifestError
from ai_scan.supply_chain import load_manifest_file as load_supply_manifest

Loader = Callable[[str], str]

_PRODUCTS: tuple[tuple[str, Loader, type[ValueError], str, str], ...] = (
    (
        "supply-chain-audit",
        load_supply_manifest,
        SupplyChainManifestError,
        "manifest changed during read",
        "manifest path is invalid",
    ),
    (
        "output-handling-audit",
        load_output_manifest,
        OutputHandlingManifestError,
        "llm05_manifest_changed",
        "llm05_manifest_invalid_path",
    ),
)

_RACES = (
    "replacement_after_open",
    "replacement_during_first_read",
    "replacement_during_second_read",
    "unlink_recreate",
    "symlink_swap",
    "hardlink_swap",
    "metadata_change",
    "path_stat_failure",
)


def _manifest(command: str) -> str:
    if command == "supply-chain-audit":
        document = {"schema_version": "ai-scan-supply-chain-manifest-v1", "items": []}
    else:
        document = {"schema_version": "ai-scan-output-handling-manifest-v1", "sinks": []}
    return json.dumps(document, sort_keys=True)


def _install_race(
    monkeypatch: pytest.MonkeyPatch, path: Path, replacement: Path, race: str
) -> None:
    real_open = os.open
    real_read = os.read
    real_lseek = os.lseek
    real_stat = os.stat
    second_read = False
    triggered = False

    def replace_path() -> None:
        nonlocal triggered
        if triggered:
            return
        triggered = True
        if race.startswith("replacement"):
            os.replace(replacement, path)
        elif race == "unlink_recreate":
            path.unlink()
            path.write_bytes(replacement.read_bytes())
        elif race == "symlink_swap":
            path.unlink()
            path.symlink_to(replacement)
        elif race == "hardlink_swap":
            path.unlink()
            os.link(replacement, path)
        elif race == "metadata_change":
            info = real_stat(path, follow_symlinks=False)
            os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns + 1))

    if race == "path_stat_failure":

        def failing_stat(
            candidate: os.PathLike[str] | str,
            *,
            dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> os.stat_result:
            if os.fspath(candidate) == os.fspath(path) and not follow_symlinks:
                raise OSError("SecretPathStatFailure")  # pragma: allowlist secret
            return real_stat(candidate, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

        monkeypatch.setattr(os, "stat", failing_stat)
        return

    if race == "replacement_after_open":

        def racing_open(candidate: os.PathLike[str] | str, flags: int) -> int:
            fd = real_open(candidate, flags)
            replace_path()
            return fd

        monkeypatch.setattr(os, "open", racing_open)
        return

    def tracking_lseek(fd: int, offset: int, whence: int) -> int:
        nonlocal second_read
        result = real_lseek(fd, offset, whence)
        second_read = True
        return result

    def racing_read(fd: int, size: int) -> bytes:
        if race == "replacement_during_second_read":
            if second_read:
                replace_path()
        else:
            replace_path()
        return real_read(fd, size)

    monkeypatch.setattr(os, "lseek", tracking_lseek)
    monkeypatch.setattr(os, "read", racing_read)


@pytest.mark.parametrize(
    ("command", "loader", "error_type", "changed_code", "invalid_path_code"),
    _PRODUCTS,
    ids=("llm03", "llm05"),
)
@pytest.mark.parametrize("interface", ("loader", "cli"))
@pytest.mark.parametrize("race", _RACES)
def test_public_manifest_inputs_reject_path_descriptor_races_with_fixed_codes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    loader: Loader,
    error_type: type[ValueError],
    changed_code: str,
    invalid_path_code: str,
    interface: str,
    race: str,
) -> None:
    del invalid_path_code
    path = tmp_path / "manifest.json"
    replacement = tmp_path / "replacement.json"
    text = _manifest(command)
    path.write_text(text, encoding="utf-8")
    replacement.write_text(text + "\n", encoding="utf-8")
    _install_race(monkeypatch, path, replacement, race)

    if interface == "loader":
        with pytest.raises(error_type, match=f"^{changed_code}$"):
            loader(str(path))
    else:
        assert cli.main([command, "--manifest", str(path)]) == cli.EXIT_RUNTIME_ERROR
        assert capsys.readouterr().out.strip() == f"invalid: {changed_code}"


@pytest.mark.parametrize(
    ("command", "loader", "error_type", "changed_code", "invalid_path_code"),
    _PRODUCTS,
    ids=("llm03", "llm05"),
)
@pytest.mark.parametrize("interface", ("loader", "cli"))
def test_public_manifest_inputs_reject_embedded_nul_with_fixed_code(
    capsys: pytest.CaptureFixture[str],
    command: str,
    loader: Loader,
    error_type: type[ValueError],
    changed_code: str,
    invalid_path_code: str,
    interface: str,
) -> None:
    del changed_code
    invalid_path = "sensitive-path\0tail"
    if interface == "loader":
        with pytest.raises(error_type, match=f"^{invalid_path_code}$") as exc_info:
            loader(invalid_path)
        assert invalid_path not in str(exc_info.value)
        assert "null" not in str(exc_info.value).lower()
    else:
        assert cli.main([command, "--manifest", invalid_path]) == cli.EXIT_RUNTIME_ERROR
        output = capsys.readouterr().out.strip()
        assert output == f"invalid: {invalid_path_code}"
        assert invalid_path not in output
        assert "null" not in output.lower()


@pytest.mark.parametrize(
    ("command", "loader", "error_type", "changed_code", "invalid_path_code"),
    _PRODUCTS,
    ids=("llm03", "llm05"),
)
@pytest.mark.parametrize("interface", ("loader", "cli"))
def test_public_manifest_inputs_map_path_stat_value_error_to_fixed_code(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    loader: Loader,
    error_type: type[ValueError],
    changed_code: str,
    invalid_path_code: str,
    interface: str,
) -> None:
    del changed_code
    path = tmp_path / "manifest.json"
    path.write_text(_manifest(command), encoding="utf-8")
    real_stat = os.stat

    def invalid_stat(
        candidate: os.PathLike[str] | str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if os.fspath(candidate) == os.fspath(path) and not follow_symlinks:
            raise ValueError("embedded null byte from sensitive pathname")
        return real_stat(candidate, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", invalid_stat)
    if interface == "loader":
        with pytest.raises(error_type, match=f"^{invalid_path_code}$") as exc_info:
            loader(str(path))
        assert "null" not in str(exc_info.value).lower()
        assert "sensitive" not in str(exc_info.value).lower()
    else:
        assert cli.main([command, "--manifest", str(path)]) == cli.EXIT_RUNTIME_ERROR
        assert capsys.readouterr().out.strip() == f"invalid: {invalid_path_code}"


def test_shared_loader_closes_descriptor_when_path_stat_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "manifest.json"
    path.write_text("{}", encoding="utf-8")
    real_open = os.open
    real_stat = os.stat
    opened: list[int] = []

    def recording_open(candidate: os.PathLike[str] | str, flags: int) -> int:
        fd = real_open(candidate, flags)
        opened.append(fd)
        return fd

    def failing_stat(
        candidate: os.PathLike[str] | str,
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if os.fspath(candidate) == os.fspath(path) and not follow_symlinks:
            raise OSError("path stat failed")
        return real_stat(candidate, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "stat", failing_stat)
    with pytest.raises(SafeFileError, match="^changed$"):
        read_stable_regular_file(str(path), max_bytes=100)

    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])


@pytest.mark.parametrize(
    ("command", "loader", "error_type", "changed_code", "invalid_path_code"),
    _PRODUCTS,
    ids=("llm03", "llm05"),
)
@pytest.mark.parametrize("interface", ("loader", "cli"))
def test_public_manifest_inputs_accept_stable_regular_files(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    command: str,
    loader: Loader,
    error_type: type[ValueError],
    changed_code: str,
    invalid_path_code: str,
    interface: str,
) -> None:
    del error_type, changed_code, invalid_path_code
    text = _manifest(command)
    path = tmp_path / "manifest.json"
    path.write_text(text, encoding="utf-8")

    if interface == "loader":
        assert loader(str(path)) == text
    else:
        assert cli.main([command, "--manifest", str(path)]) == cli.EXIT_OK
        assert capsys.readouterr().out
