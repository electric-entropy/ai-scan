"""Phase A1 — plan provenance, policy binding, and strict run-path parsing.

A self-consistent digest only proves a plan was not corrupted; it does not prove
the plan is the canonical one the mode's policy compiles. A re-digested plan that
widens a limit, alters a case, swaps a pack, or names an unregistered adapter is
recompiled against policy and rejected before any transport is constructed. The
active run path parses plan JSON strictly (duplicate keys / non-finite rejected).
"""

from __future__ import annotations

import json

import pytest

from ai_scan import cli
from ai_scan.core.errors import ConfigError
from ai_scan.orchestration import (
    PlanError,
    compile_plan,
    load_plan,
    plan_to_dict,
    verify_plan_integrity,
)
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.conftest import MockResponse

_URL = "http://127.0.0.1:9/chat"


def _reseal(body: dict) -> dict:
    body = dict(body)
    body.pop("digest", None)
    body["digest"] = compute_digest(body)
    return body


def _plan_dict(mode: str = "reliable") -> dict:
    return plan_to_dict(compile_plan(normalize_target(_URL), mode))


def test_canonical_plan_passes_integrity() -> None:
    verify_plan_integrity(load_plan(_plan_dict()))  # no raise


def test_widened_limit_is_rejected() -> None:
    doc = _plan_dict()
    doc["limits"][0] = doc["limits"][0] + 10_000  # widen max_physical_requests
    with pytest.raises(PlanError):
        verify_plan_integrity(load_plan(_reseal(doc)))


def test_altered_case_template_is_rejected() -> None:
    doc = _plan_dict()
    doc["cases"][0][5] = doc["cases"][0][5] + " tamper"  # keep structural validity
    with pytest.raises(PlanError):
        verify_plan_integrity(load_plan(_reseal(doc)))


def test_swapped_pack_digest_is_rejected() -> None:
    doc = _plan_dict()
    doc["packs"][0][2] = "0" * 64  # a different (bogus) pack digest
    with pytest.raises(PlanError):
        verify_plan_integrity(load_plan(_reseal(doc)))


def test_unregistered_adapter_is_rejected() -> None:
    doc = _plan_dict()
    doc["adapter"] = "totally_unregistered_adapter"
    with pytest.raises(PlanError):
        verify_plan_integrity(load_plan(_reseal(doc)))


def test_plan_binds_exact_target_path(mock_server, tmp_path) -> None:
    # A plan compiled for /chat must not run against /admin on the same origin.
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    origin = server.base_url
    plan_url = f"{origin}/chat"
    plan_path = tmp_path / "plan.json"
    receipt = _write_receipt(tmp_path, plan_url)
    assert cli.main(["plan", "--target", plan_url, "--out", str(plan_path)]) == cli.EXIT_OK

    rc = cli.main(
        [
            "run", "--target", f"{origin}/admin", "--plan", str(plan_path),
            "--auth-receipt", receipt, "--non-interactive",
        ]
    )
    assert rc != cli.EXIT_OK  # the /admin target is rejected against a /chat plan


def _write_receipt(tmp_path, url: str) -> str:
    from ai_scan.authorization import Receipt, write_receipt

    path = tmp_path / "auth.json"
    write_receipt(
        Receipt.create(
            target=normalize_target(url), client="C", engagement="E", expires="2999-01-01"
        ),
        str(path),
    )
    return str(path)


def test_ai_scan_plan_output_passes_validate_config(tmp_path) -> None:
    # A1.3: the artifact `ai-scan plan` emits is exactly what validate-config accepts.
    plan_path = tmp_path / "plan.json"
    assert cli.main(["plan", "--target", _URL, "--out", str(plan_path)]) == cli.EXIT_OK
    assert cli.main(
        ["validate-config", "--file", str(plan_path), "--kind", "plan"]
    ) == cli.EXIT_OK


def test_validate_config_rejects_tampered_plan(tmp_path) -> None:
    plan_path = tmp_path / "plan.json"
    assert cli.main(["plan", "--target", _URL, "--out", str(plan_path)]) == cli.EXIT_OK
    doc = json.loads(plan_path.read_text(encoding="utf-8"))
    doc["limits"][0] = doc["limits"][0] + 9999
    plan_path.write_text(json.dumps(_reseal(doc)), encoding="utf-8")
    assert cli.main(
        ["validate-config", "--file", str(plan_path), "--kind", "plan"]
    ) != cli.EXIT_OK


def test_run_path_rejects_duplicate_json_keys(tmp_path) -> None:
    text = json.dumps(_plan_dict())
    dup = text[:-1] + ', "seed": 7}'  # a duplicate top-level key
    path = tmp_path / "plan.json"
    path.write_text(dup, encoding="utf-8")
    with pytest.raises((PlanError, ConfigError)):
        cli._load_plan_file(str(path))


def test_run_path_rejects_non_finite_numbers(tmp_path) -> None:
    text = json.dumps(_plan_dict())
    bad = text.replace('"seed": 0', '"seed": Infinity', 1)
    path = tmp_path / "plan.json"
    path.write_text(bad, encoding="utf-8")
    with pytest.raises((PlanError, ConfigError)):
        cli._load_plan_file(str(path))
