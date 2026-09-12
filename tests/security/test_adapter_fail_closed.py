"""CLI adapter migration safety regressions."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import pytest

from ai_scan import cli
from ai_scan.authorization import Receipt, write_receipt
from ai_scan.targets import normalize_target


def _receipt_for(tmp_path: Path, target_url: str) -> str:
    path = tmp_path / "auth.json"
    write_receipt(
        Receipt.create(
            target=normalize_target(target_url),
            client="C",
            engagement="E",
            expires="2999-01-01",
        ),
        str(path),
    )
    return str(path)


def test_active_cli_builds_adapter_before_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    url = "http://mock.local/chat"
    receipt = _receipt_for(tmp_path, url)
    constructed = 0

    def boom(_controller: object) -> NoReturn:
        nonlocal constructed
        constructed += 1
        raise AssertionError("transport must not be constructed")

    monkeypatch.setattr(cli, "_make_transport", boom)
    code = cli.main(
        [
            "fingerprint",
            "--target",
            url,
            "--method",
            "GET",
            "--auth-receipt",
            receipt,
            "--non-interactive",
        ]
    )
    assert code == cli.EXIT_RUNTIME_ERROR
    assert constructed == 0
