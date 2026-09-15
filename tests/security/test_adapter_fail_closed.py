"""CLI adapter migration safety regressions."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import pytest

from ai_scan import cli


def test_active_cli_builds_adapter_before_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    url = "http://mock.local/chat"
    constructed = 0

    def boom(_controller: object) -> NoReturn:
        nonlocal constructed
        constructed += 1
        raise AssertionError("transport must not be constructed")

    monkeypatch.setattr(cli, "_make_transport", boom)
    code = cli.main(["fingerprint", "--target", url, "--method", "GET"])
    assert code == cli.EXIT_RUNTIME_ERROR
    assert constructed == 0
