"""LLM03 offline supply-chain manifest CLI coverage."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from importlib import resources
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.supply_chain import SupplyChainManifestError, audit_manifest_text, load_manifest_file

_GOOD_DIGEST = "a" * 64
_OTHER_DIGEST = "b" * 64


def _manifest(items: list[dict[str, object]]) -> dict[str, object]:
    return {
        "schema_version": "ai-scan-supply-chain-manifest-v1",
        "items": items,
    }


def _secure_items() -> list[dict[str, object]]:
    return [
        {
            "id": "model.main",
            "kind": "model",
            "name": "example-chat-model",
            "source_url": "https://huggingface.co/example/chat-model",
            "revision": "0123456789abcdef0123456789abcdef01234567",
            "sha256": _GOOD_DIGEST,
            "artifact_path": "models/example-chat-model.safetensors",
            "uses_unsafe_serialization": False,
            "enables_remote_code": False,
        },
        {
            "id": "dependency.tokenizer",
            "kind": "dependency",
            "name": "tokenizers",
            "source_url": "https://pypi.org/project/tokenizers/",
            "revision": "0.19.1",
            "sha256": _OTHER_DIGEST,
            "uses_unsafe_serialization": False,
            "enables_remote_code": False,
        },
    ]


def _write(path: Path, doc: dict[str, object]) -> Path:
    path.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
    return path


def test_secure_manifest_has_no_findings_and_uses_opaque_item_refs() -> None:
    text = json.dumps(_manifest(_secure_items()), sort_keys=True)
    result = audit_manifest_text(text)

    assert result.status == "passed"
    assert result.applicability == "applicable"
    assert result.manifest_sha256
    assert result.summary["findings"] == 0
    refs = {item["item_ref"] for item in result.items}
    assert len(refs) == 2
    assert all(
        isinstance(ref, str) and re.fullmatch(r"llm03-item-[0-9a-f]{32}", ref)
        for ref in refs
    )
    assert all("id" not in item and "name" not in item for item in result.items)
    assert all(item["manifest_sha256"] == result.manifest_sha256 for item in result.items)


def test_vulnerable_manifest_reports_explicit_evidence_and_remediation() -> None:
    item = _secure_items()[0] | {
        "id": "model.vulnerable",
        "revision": "main",
        "source_url": "http://example.test/model",
        "sha256": "not-a-sha",
        "artifact_path": "weights/model.bin",
        "uses_unsafe_serialization": True,
        "enables_remote_code": True,
    }

    result = audit_manifest_text(json.dumps(_manifest([item]), sort_keys=True))

    assert result.status == "finding"
    rules = {finding["rule_id"] for finding in result.findings}
    assert rules == {
        "llm03.missing_or_mutable_revision",
        "llm03.invalid_sha256",
        "llm03.non_https_source",
        "llm03.unsafe_serialization",
        "llm03.remote_code_enabled",
    }
    for finding in result.findings:
        assert finding["manifest_sha256"] == result.manifest_sha256
        assert isinstance(finding["item_ref"], str)
        assert re.fullmatch(r"llm03-item-[0-9a-f]{32}", str(finding["item_ref"]))
        assert "item_id" not in finding
        assert "item_name" not in finding
        assert finding["applicability"] == "applicable"
        assert finding["field_path"] in {
            "items[].source_url",
            "items[].revision",
            "items[].sha256",
            "items[].artifact_path",
            "items[].uses_unsafe_serialization",
            "items[].enables_remote_code",
        }
        assert finding["reason_code"] in {
            "missing_source",
            "non_https_source",
            "missing_revision",
            "mutable_revision",
            "missing_sha256",
            "invalid_sha256",
            "unsafe_serialization_flag",
            "unsafe_serialization_extension",
            "remote_code_enabled",
        }
        assert "evidence" not in finding
        assert finding["remediation"]


def _assert_public_output_excludes_values(output: str, forbidden_values: Sequence[object]) -> None:
    for value in forbidden_values:
        if value is None or value is False or value is True:
            continue
        assert str(value) not in output


def test_public_json_and_human_outputs_do_not_echo_manifest_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_id = "sk." + "abcdefghijklmnopqrst"
    secret_name = "Bearer " + "ABCDEFGHIJKL"
    secret_revision = "-".join(("MUTABLE", "REVISION", "SECRET"))
    secret_path = "weights/" + "SECRET-PATH.bin"
    secret_source = "http://" + "leaky.example.test/" + "model"
    secret_digest = "-".join(("SECRET", "DIGEST", "NOT", "A", "SHA"))
    doc = _manifest(
        [
            {
                "id": secret_id,
                "kind": "model",
                "name": secret_name,
                "source_url": secret_source,
                "revision": secret_revision,
                "sha256": secret_digest,
                "artifact_path": secret_path,
                "uses_unsafe_serialization": True,
                "enables_remote_code": True,
            }
        ]
    )
    path = _write(tmp_path / "manifest.json", doc)
    forbidden = [
        secret_id,
        secret_name,
        secret_revision,
        secret_path,
        secret_source,
        secret_digest,

        "http://",
        "leaky.example.test",
    ]

    assert (
        cli.main(["supply-chain-audit", "--manifest", str(path), "--format", "json"])
        == cli.EXIT_CONFIRMED_FINDING
    )
    json_out = capsys.readouterr().out
    parsed = json.loads(json_out)
    _assert_public_output_excludes_values(json_out, forbidden)
    assert {finding["rule_id"] for finding in parsed["findings"]} >= {
        "llm03.non_https_source",
        "llm03.missing_or_mutable_revision",
        "llm03.invalid_sha256",
        "llm03.unsafe_serialization",
        "llm03.remote_code_enabled",
    }
    assert {finding["reason_code"] for finding in parsed["findings"]} >= {
        "non_https_source",
        "mutable_revision",
        "invalid_sha256",
        "unsafe_serialization_flag",
        "unsafe_serialization_extension",
        "remote_code_enabled",
    }
    assert all("evidence" not in finding for finding in parsed["findings"])
    assert all(
        "item_id" not in finding and "item_name" not in finding
        for finding in parsed["findings"]
    )

    assert cli.main(["supply-chain-audit", "--manifest", str(path)]) == cli.EXIT_CONFIRMED_FINDING
    human_out = capsys.readouterr().out
    _assert_public_output_excludes_values(human_out, forbidden)
    assert "reason=mutable_revision" in human_out
    assert "path=items[].revision" in human_out


def test_public_error_outputs_do_not_echo_unknown_duplicate_malformed_or_numeric_values(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    submitted_values = [
        "unknown_secret_key",
        "Bearer ABCDEFGHIJKL",
        "duplicate_secret_key",
        "first-secret-value",
        "second-secret-value",
        "malformed-secret-value",
        123456789,
    ]
    unknown_doc = _manifest(_secure_items())
    unknown_doc["items"][0]["unknown_secret_key"] = "Bearer ABCDEFGHIJKL"  # type: ignore[index]
    unknown_path = _write(tmp_path / "unknown.json", unknown_doc)
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(unknown_path), "--format", "json"])
        == cli.EXIT_RUNTIME_ERROR
    )
    unknown_out = capsys.readouterr().out
    _assert_public_output_excludes_values(unknown_out, submitted_values)
    assert "invalid:" in unknown_out

    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(
        '{"schema_version":"ai-scan-supply-chain-manifest-v1",'
        '"items":[{"id":"model.main","kind":"model","name":"x",'
        '"duplicate_secret_key":"first-secret-value",'
        '"duplicate_secret_key":"second-secret-value",'
        '"uses_unsafe_serialization":false,"enables_remote_code":false}]}',
        encoding="utf-8",
    )
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(duplicate_path)])
        == cli.EXIT_RUNTIME_ERROR
    )
    duplicate_out = capsys.readouterr().out
    _assert_public_output_excludes_values(duplicate_out, submitted_values)

    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text('{"malformed-secret-value": 123456789,,}', encoding="utf-8")
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(malformed_path)])
        == cli.EXIT_RUNTIME_ERROR
    )
    malformed_out = capsys.readouterr().out
    _assert_public_output_excludes_values(malformed_out, submitted_values)

    numeric_doc = _manifest(_secure_items())
    numeric_doc["items"][0]["revision"] = 123456789  # type: ignore[index]
    numeric_path = _write(tmp_path / "numeric.json", numeric_doc)
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(numeric_path)])
        == cli.EXIT_RUNTIME_ERROR
    )
    numeric_out = capsys.readouterr().out
    _assert_public_output_excludes_values(numeric_out, submitted_values)


def test_missing_provenance_is_inconclusive_not_a_secure_pass() -> None:
    item = {
        "id": "plugin.local",
        "kind": "plugin",
        "name": "local-plugin",
        "uses_unsafe_serialization": False,
        "enables_remote_code": False,
    }

    result = audit_manifest_text(json.dumps(_manifest([item]), sort_keys=True))

    assert result.status == "inconclusive"
    assert {finding["rule_id"] for finding in result.findings} == {
        "llm03.missing_source",
        "llm03.missing_revision",
        "llm03.missing_sha256",
    }
    assert all(finding["status"] == "inconclusive" for finding in result.findings)


@pytest.mark.parametrize("artifact_path", ["weights/model.PTH", "weights/model.ckpt"])
def test_unsafe_serialization_extension_variants_are_findings(artifact_path: str) -> None:
    item = _secure_items()[0] | {"id": "model.unsafe", "artifact_path": artifact_path}

    result = audit_manifest_text(json.dumps(_manifest([item]), sort_keys=True))

    assert result.status == "finding"
    assert any(
        finding["rule_id"] == "llm03.unsafe_serialization" for finding in result.findings
    )


@pytest.mark.parametrize(
    "mutator",
    [
        lambda doc: doc.__setitem__("unexpected", True),
        lambda doc: doc["items"][0].__setitem__("unknown", "field"),
        lambda doc: doc["items"].append(dict(doc["items"][0])),
        lambda doc: doc["items"][0].__setitem__("id", "model.ｍain"),
        lambda doc: doc["items"][0].__setitem__("artifact_path", "../models/evil.safetensors"),
        lambda doc: doc["items"][0].__setitem__("source_url", "https://example.com/%E2%80%AE/model"),
    ],
)
def test_schema_rejects_unknown_duplicates_confusables_traversal_and_unicode(mutator) -> None:  # type: ignore[no-untyped-def]
    doc = _manifest(_secure_items())
    mutator(doc)
    with pytest.raises(SupplyChainManifestError):
        audit_manifest_text(json.dumps(doc, sort_keys=True))


def test_duplicate_json_keys_are_rejected() -> None:
    text = (
        '{"schema_version":"ai-scan-supply-chain-manifest-v1",'
        '"items":[{"id":"model.main","id":"model.other","kind":"model",'
        '"name":"x","uses_unsafe_serialization":false,"enables_remote_code":false}]}'
    )
    with pytest.raises(SupplyChainManifestError, match="duplicate JSON key") as exc_info:
        audit_manifest_text(text)
    assert "model.main" not in str(exc_info.value)
    assert "model.other" not in str(exc_info.value)


def _credential_url(secret: str) -> str:
    return "https://user:" + secret + "@example.com/model"


@pytest.mark.parametrize(
    "label,source_url,secret",
    [
        ("query", "https://example.com/model?access_token=SECRET123", "SECRET123"),
        ("credentials", _credential_url("Super" + "Secret123"), "Super" + "Secret123"),
        ("fragment", "https://example.com/model#SECRETFRAG", "SECRETFRAG"),
        ("malformed-port", "https://example.com:bad/model", "bad"),
        ("empty-host", "https:///model", None),
        ("punycode", "https://xn--pple-43d.example/model", None),
        ("encoded-authority", "https://example.com%2f.evil.test/model", None),
        ("encoded-path", "https://example.com/%2fmodel", None),
        ("non-default-port", "https://example.com:444/model", None),
        ("unicode-confusable", "https://ｅxample.com/model", None),
    ],
)
def test_source_url_rejects_ambiguous_or_noncanonical_urls_without_echoing_values(
    label: str, source_url: str, secret: str | None
) -> None:
    item = _secure_items()[0] | {"source_url": source_url}
    with pytest.raises(SupplyChainManifestError) as exc_info:
        audit_manifest_text(json.dumps(_manifest([item]), ensure_ascii=False, sort_keys=True))

    message = str(exc_info.value)
    assert "source_url" in message
    assert source_url not in message
    if secret is not None:
        assert secret not in message
    assert label


def test_parser_and_schema_errors_do_not_echo_unknown_duplicate_or_malformed_secrets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile_key = "Authorization: " + "Bearer " + "ABCDEF1234567890QRST"
    doc = _manifest(_secure_items())
    doc["items"][0][hostile_key] = _credential_url("Super" + "Secret123")  # type: ignore[index]
    path = _write(tmp_path / "manifest.json", doc)

    assert cli.main(["supply-chain-audit", "--manifest", str(path)]) == cli.EXIT_RUNTIME_ERROR
    out = capsys.readouterr().out
    assert "invalid:" in out
    assert hostile_key not in out
    assert "ABCDEF1234567890QRST" not in out
    assert "SuperSecret123" not in out

    duplicate = (
        '{"schema_version":"ai-scan-supply-chain-manifest-v1",'
        '"items":[{"id":"model.main","kind":"model","name":"x",'
        '"api_key_ABCDEFGHIJKLMNOPQRSTUV":"x",'
        '"api_key_ABCDEFGHIJKLMNOPQRSTUV":"y",'
        '"uses_unsafe_serialization":false,"enables_remote_code":false}]}'
    )
    duplicate_path = tmp_path / "duplicate.json"
    duplicate_path.write_text(duplicate, encoding="utf-8")
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(duplicate_path)])
        == cli.EXIT_RUNTIME_ERROR
    )
    out = capsys.readouterr().out
    assert "api_key_ABCDEFGHIJKLMNOPQRSTUV" not in out


@pytest.mark.parametrize("revision", ["ABCDEF0123456789ABCDEF0123456789ABCDEF01", "main"])
def test_uppercase_sha_and_mutable_revision_are_accepted_but_flagged(revision: str) -> None:
    item = _secure_items()[0] | {"id": "model.flagged", "revision": revision}

    result = audit_manifest_text(json.dumps(_manifest([item]), sort_keys=True))

    assert result.status == "finding"
    assert any(
        finding["rule_id"] == "llm03.missing_or_mutable_revision"
        and finding["field_path"] == "items[].revision"
        and finding["reason_code"] == "mutable_revision"
        for finding in result.findings
    )


@pytest.mark.parametrize("payload", ["\ufeff{}", '{"a": 1}\x00', '{"a": 1} trailing'])
def test_manifest_rejects_bom_nul_and_trailing_data_without_echoing_payload(payload: str) -> None:
    with pytest.raises(SupplyChainManifestError) as exc_info:
        audit_manifest_text(payload)
    assert payload not in str(exc_info.value)


def test_manifest_file_loader_rejects_oversized_symlink_and_special_files(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (65 * 1024))
    with pytest.raises(SupplyChainManifestError, match="too large"):
        load_manifest_file(str(oversized))

    target = _write(tmp_path / "target.json", _manifest(_secure_items()))
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(SupplyChainManifestError, match="regular non-symlink"):
        load_manifest_file(str(link))

    with pytest.raises(SupplyChainManifestError, match="regular non-symlink"):
        load_manifest_file(os.devnull)

    directory = tmp_path / "manifest-dir"
    directory.mkdir()
    with pytest.raises(SupplyChainManifestError, match="regular non-symlink"):
        load_manifest_file(str(directory))


def test_manifest_file_loader_rejects_fifo_promptly_before_read(tmp_path: Path) -> None:
    fifo = tmp_path / "manifest.json"
    os.mkfifo(fifo)
    start = time.monotonic()
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; sys.path.insert(0, 'src'); "
                "from ai_scan.supply_chain import load_manifest_file; "
                f"load_manifest_file({str(fifo)!r})"
            ),
        ],
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True,
        text=True,
        timeout=2,
    )
    elapsed = time.monotonic() - start
    assert proc.returncode != 0
    assert elapsed < 1.0
    assert "regular non-symlink file" in proc.stderr


def test_manifest_file_loader_rejects_mutation_and_short_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_fstat = os.fstat
    real_read = os.read
    state = {"read": False}

    def fake_fstat(fd: int) -> os.stat_result:
        result = real_fstat(fd)
        if state["read"]:
            return os.stat_result((result.st_mode, result.st_ino + 1, *result[2:]))
        return result

    def fake_read(fd: int, n: int) -> bytes:
        state["read"] = True
        return real_read(fd, n)

    manifest_path = Path(__file__)
    monkeypatch.setattr(os, "fstat", fake_fstat)
    monkeypatch.setattr(os, "read", fake_read)
    with pytest.raises(SupplyChainManifestError, match="changed during read"):
        load_manifest_file(str(manifest_path))


def test_manifest_file_loader_rejects_same_size_content_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(b'{"schema_version":"ai-scan-supply-chain-manifest-v1","items":[]}')
    real_read = os.read
    read_count = {"value": 0}

    def fake_read(fd: int, n: int) -> bytes:
        chunk = real_read(fd, n)
        if chunk:
            read_count["value"] += 1
            if read_count["value"] > 1:
                return chunk.replace(b"items", b"zzzzz")
        return chunk

    monkeypatch.setattr(os, "read", fake_read)

    with pytest.raises(SupplyChainManifestError, match="changed during read"):
        load_manifest_file(str(manifest_path))


def test_manifest_file_loader_fails_closed_when_nonblocking_open_flags_are_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest_path = _write(tmp_path / "manifest.json", _manifest([]))

    def forbidden_open(_path: str, _flags: int) -> int:
        raise AssertionError(
            "load_manifest_file must fail before os.open without nonblocking flags"
        )

    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(os, "open", forbidden_open)

    with pytest.raises(SupplyChainManifestError, match="nonblocking safe open is unavailable"):
        load_manifest_file(str(manifest_path))


def test_public_cli_json_and_human_outputs_are_offline_and_structured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_controller):  # type: ignore[no-untyped-def]
        raise AssertionError("supply-chain-audit must not construct transport")

    monkeypatch.setattr(cli, "_make_transport", boom)
    path = _write(tmp_path / "manifest.json", _manifest(_secure_items()))

    assert (
        cli.main(["supply-chain-audit", "--manifest", str(path), "--format", "json"])
        == cli.EXIT_OK
    )
    doc = json.loads(capsys.readouterr().out)
    assert doc["schema_version"] == "ai-scan-supply-chain-audit-result-v1"
    assert doc["owasp_category"] == "LLM03"
    assert doc["scope"] == "partial_offline_manifest_assessment"
    assert doc["status"] == "passed"
    assert doc["network_requests"] == 0
    assert doc["manifest_sha256"]

    assert cli.main(["supply-chain-audit", "--manifest", str(path)]) == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "LLM03 Supply Chain offline manifest assessment" in out
    assert "status: passed" in out


def test_public_cli_returns_finding_and_inconclusive_exit_codes(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    vulnerable = _secure_items()[0] | {"id": "model.v", "sha256": "bad", "revision": "latest"}
    finding_path = _write(tmp_path / "finding.json", _manifest([vulnerable]))
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(finding_path)])
        == cli.EXIT_CONFIRMED_FINDING
    )
    assert "findings: 2" in capsys.readouterr().out

    incomplete = {
        "id": "dataset.local",
        "kind": "dataset",
        "name": "local-dataset",
        "uses_unsafe_serialization": False,
        "enables_remote_code": False,
    }
    inconclusive_path = _write(tmp_path / "inconclusive.json", _manifest([incomplete]))
    assert (
        cli.main(["supply-chain-audit", "--manifest", str(inconclusive_path)])
        == cli.EXIT_INCONCLUSIVE
    )
    assert "status: inconclusive" in capsys.readouterr().out


def test_packaged_secure_and_vulnerable_fixtures_are_executable_public_contract(capsys) -> None:  # type: ignore[no-untyped-def]
    for name, expected in (
        ("supply-chain-secure-v1.json", cli.EXIT_OK),
        ("supply-chain-vulnerable-v1.json", cli.EXIT_CONFIRMED_FINDING),
    ):
        path = resources.files("ai_scan.owasp").joinpath(name)
        with resources.as_file(path) as fixture_path:
            assert cli.main(["supply-chain-audit", "--manifest", str(fixture_path)]) == expected
            out = capsys.readouterr().out
            assert "LLM03" in out
