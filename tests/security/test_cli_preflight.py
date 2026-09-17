"""Milestone 2: offline preflight — validation before any transport/network."""

from __future__ import annotations

import json

import pytest

from ai_scan import cli
from tests.conftest import MockRequest, MockResponse

# --- blocker 4: invalid --request-template fails before transport ------------


@pytest.mark.parametrize(
    ("command", "extra"),
    [("fingerprint", []), ("inject", ["--goal", "g"]), ("assess", [])],
)
def test_invalid_template_no_transport_no_requests(
    command: str, extra: list[str], mock_server, tmp_path, monkeypatch
) -> None:
    hits = {"n": 0}

    def app(req: MockRequest) -> MockResponse:
        hits["n"] += 1
        return MockResponse(status=200, body=b"{}")

    server = mock_server(app)
    url = f"{server.base_url}/chat"

    constructed = {"n": 0}
    real_make = cli._make_transport

    def counting_make(controller):
        constructed["n"] += 1
        return real_make(controller)

    monkeypatch.setattr(cli, "_make_transport", counting_make)

    bad_template = tmp_path / "tmpl.txt"
    bad_template.write_text('{"input": "no marker here"}', encoding="utf-8")  # missing '*'

    code = cli.main(
        [
            command, "--target", url, *extra,
            "--request-template", str(bad_template),
        ]
    )
    assert code == cli.EXIT_RUNTIME_ERROR
    assert constructed["n"] == 0, "transport must not be constructed for an invalid template"
    assert hits["n"] == 0, "no request may be sent for an invalid template"


# --- blocker 7: validate-config CLI command ----------------------------------


def _valid_pack_doc() -> dict:
    return {
        "schema_version": 1, "kind": "pack", "id": "safe", "version": "v1",
        "trust": "builtin", "digest": "a" * 64, "families": ["x"],
    }


def test_validate_config_accepts_valid_document(tmp_path) -> None:
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(_valid_pack_doc()), encoding="utf-8")
    assert cli.main(["validate-config", "--kind", "pack", "--file", str(path)]) == cli.EXIT_OK


def test_validate_config_rejects_invalid_document(tmp_path) -> None:
    doc = _valid_pack_doc()
    doc["surprise"] = "x"  # unknown field
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    code = cli.main(["validate-config", "--kind", "pack", "--file", str(path)])
    assert code == cli.EXIT_RUNTIME_ERROR


@pytest.mark.parametrize(
    ("kind", "doc"),
    [
        (
            "target",
            {
                "schema_version": 1,
                "kind": "target",
                "name": "app",
                "adapter": "generic_http",
                "endpoints": ["https://api.example.com/chat"],
                "request": {"method": "ATTACKER_VALUE", "prompt_marker": "*"},
                "response": {"extract": "raw_body"},
            },
        ),
        (
            "engagement",
            {
                "schema_version": 1,
                "kind": "engagement",
                "engagement_id": "E",
                "client": "C",
                "approver": "A",
                "issued_at": "ATTACKER_VALUE",
                "expires_at": "2026-09-12T00:00:00Z",
                "target_scopes": ["https://api.example.com"],
                "capabilities": ["read"],
                "limits": {
                    "max_physical_requests": 987654321,
                    "max_duration_seconds": 1800,
                    "requests_per_second": 1,
                    "max_concurrency": 1,
                },
                "signer_key_id": "k",
            },
        ),
        (
            "finding",
            {
                "schema_version": 2,
                "kind": "finding",
                "id": "f-1",
                "attack_id": "a",
                "status": "ATTACKER_VALUE",
                "severity": "low",
                "title": "t",
                "description": "d",
                "evidence_ids": [],
            },
        ),
    ],
)
def test_validate_config_errors_do_not_echo_schema_values_or_numbers(
    kind: str, doc: dict, tmp_path, capsys
) -> None:
    path = tmp_path / f"{kind}.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    assert (
        cli.main(["validate-config", "--kind", kind, "--file", str(path)])
        == cli.EXIT_RUNTIME_ERROR
    )
    out = capsys.readouterr().out
    assert "ATTACKER_VALUE" not in out
    assert "987654321" not in out


def test_validate_config_rejects_missing_file(tmp_path) -> None:
    assert cli.main(
        ["validate-config", "--kind", "pack", "--file", str(tmp_path / "nope.json")]
    ) == cli.EXIT_RUNTIME_ERROR


def test_validate_config_never_constructs_transport(tmp_path, monkeypatch) -> None:
    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))
    doc = _valid_pack_doc()
    doc["digest"] = "nothex"  # invalid → rejected
    path = tmp_path / "pack.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    code = cli.main(["validate-config", "--kind", "pack", "--file", str(path)])
    assert code == cli.EXIT_RUNTIME_ERROR
    assert constructed["n"] == 0


def test_validate_config_kind_choices_cover_all_schemas() -> None:
    from ai_scan.core.config import SUPPORTED_SCHEMAS

    parser = cli.build_parser()
    action = next(a for a in parser._actions if a.dest == "command")  # noqa: SLF001
    sub = action.choices["validate-config"]
    kind_action = next(a for a in sub._actions if a.dest == "kind")  # noqa: SLF001
    assert set(kind_action.choices) == set(SUPPORTED_SCHEMAS)
