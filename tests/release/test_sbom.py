"""W5 — real, standards-valid CycloneDX SBOM generation + validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from scripts import generate_sbom as sb


def test_generate_sbom_is_valid_and_non_empty() -> None:
    doc = sb.build_sbom()
    sb.validate_sbom(doc)  # must not raise
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["metadata"]["component"]["type"] == "application"
    assert doc["metadata"]["component"]["name"] == "ai-scan"
    assert doc["metadata"]["component"]["version"]
    assert len(doc["components"]) > 0
    for comp in doc["components"]:
        assert comp["name"] and comp["version"] and comp["type"]


def test_sbom_app_version_matches_installed_metadata() -> None:
    from importlib import metadata

    doc = sb.build_sbom()
    assert doc["metadata"]["component"]["version"] == metadata.version("ai-scan")


def test_validate_rejects_empty_components() -> None:
    doc = sb.build_sbom()
    doc["components"] = []
    with pytest.raises(sb.SbomError):
        sb.validate_sbom(doc)


def test_validate_rejects_wrong_bomformat() -> None:
    doc = sb.build_sbom()
    doc["bomFormat"] = "SPDX"
    with pytest.raises(sb.SbomError):
        sb.validate_sbom(doc)


def test_validate_rejects_missing_component_version() -> None:
    doc = sb.build_sbom()
    doc["components"][0] = {k: v for k, v in doc["components"][0].items() if k != "version"}
    with pytest.raises(sb.SbomError):
        sb.validate_sbom(doc)


def test_main_writes_and_validates(tmp_path: Path) -> None:
    out = tmp_path / "sbom.cdx.json"
    rc = sb.main(["--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    sb.validate_sbom(doc)


def test_sbom_is_deterministic() -> None:
    assert sb.build_sbom() == sb.build_sbom()
