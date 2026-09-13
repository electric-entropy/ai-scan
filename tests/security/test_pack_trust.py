from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.core.models import PackTrust
from ai_scan.packs import PackResolutionError, compute_digest, load_pack, resolve_packs


def _reliable_pack_data() -> dict[str, object]:
    raw = resources.files("ai_scan.packs.builtin").joinpath(
        "direct-injection-reliable-v1.json"
    ).read_text(encoding="utf-8")
    return json.loads(raw)


def test_registry_rejects_unknown_pack_ids_without_path_resolution() -> None:
    with pytest.raises(PackResolutionError, match="unknown built-in pack"):
        from ai_scan.packs import load_builtin_pack

        load_builtin_pack("../../payloads/safe")


def test_registry_trust_gate_does_not_widen_scope() -> None:
    with pytest.raises(PackResolutionError, match="no packs resolve"):
        resolve_packs("reliable", trust=frozenset({PackTrust.SIGNED}))


def test_capability_intersection_filters_required_capabilities() -> None:
    data = _reliable_pack_data()
    data["id"] = "capability-pack"
    data["required_capabilities"] = ["rag_upload"]
    data["digest"] = compute_digest(data)
    pack = load_pack(data, verify=True)

    assert not (pack.required_capabilities <= frozenset())
    assert pack.required_capabilities <= frozenset({"rag_upload"})


def test_pack_errors_scrub_secret_like_untrusted_values() -> None:
    data = _reliable_pack_data()
    data["id"] = "unit-pack"
    secret_like = "sk-" + ("A" * 16)
    data[secret_like] = "untrusted field name"
    data["digest"] = compute_digest(data)

    with pytest.raises(Exception) as excinfo:
        load_pack(data, verify=True)
    assert secret_like not in str(excinfo.value)


def test_packs_list_and_validate_are_offline(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    def fail_transport(*args: object, **kwargs: object) -> object:
        raise AssertionError("transport must not be constructed for pack commands")

    monkeypatch.setattr(cli, "_make_transport", fail_transport)

    assert cli.main(["packs", "list", "--mode", "reliable"]) == cli.EXIT_OK
    listed = capsys.readouterr().out
    assert "direct-injection-reliable" in listed
    assert "direct-injection-kitchen" not in listed

    assert cli.main(["packs", "validate", "direct-injection-reliable"]) == cli.EXIT_OK
    validated = capsys.readouterr().out
    assert "valid: direct-injection-reliable" in validated


def test_pack_file_validation_fails_closed_before_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    def fail_transport(*args: object, **kwargs: object) -> object:
        raise AssertionError("transport must not be constructed for pack commands")

    monkeypatch.setattr(cli, "_make_transport", fail_transport)
    bad = tmp_path / "bad.json"
    bad.write_text(
        '{"schema_version": 1, "id": "bad", "python": "ex" "ec()"}', encoding="utf-8"
    )

    assert cli.main(["packs", "validate", str(bad)]) == cli.EXIT_RUNTIME_ERROR
    assert "invalid:" in capsys.readouterr().out


def test_packs_validate_rejects_duplicate_json_keys_in_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys
) -> None:
    # A duplicate key (malicious unsupported first value, valid second) must be
    # rejected by the CLI file path, exactly as built-in loading rejects it.
    def fail_transport(*args: object, **kwargs: object) -> object:
        raise AssertionError("transport must not be constructed for pack commands")

    monkeypatch.setattr(cli, "_make_transport", fail_transport)
    dup = tmp_path / "dup.json"
    dup.write_text(
        '{"schema_version": 99, "schema_version": 1, "id": "dup"}', encoding="utf-8"
    )

    assert cli.main(["packs", "validate", str(dup)]) == cli.EXIT_RUNTIME_ERROR
    out = capsys.readouterr().out
    assert "invalid:" in out
    assert "duplicate key" in out
