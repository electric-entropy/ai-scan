"""W2 — sdist/wheel contain the intended data and exclude local artifacts.

Chosen sdist contract: tests are NOT shipped (avoids fixture-missing failures and
leaking test data). The runtime package data (py.typed, schemas, builtin packs,
templates) and the license must be present in both artifacts.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory: pytest.TempPathFactory) -> dict[str, list[str]]:
    out = tmp_path_factory.mktemp("dist")
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(_REPO_ROOT)],
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = list(out.glob("*.whl"))
    sdists = list(out.glob("*.tar.gz"))
    assert len(wheels) == 1 and len(sdists) == 1
    with zipfile.ZipFile(wheels[0]) as zf:
        wheel_names = zf.namelist()
    with tarfile.open(sdists[0], "r:gz") as tf:
        sdist_names = tf.getnames()
    return {"wheel": wheel_names, "sdist": sdist_names}


def test_wheel_includes_runtime_data(artifacts: dict[str, list[str]]) -> None:
    names = artifacts["wheel"]
    assert any(n.endswith("ai_scan/py.typed") for n in names)
    assert any("ai_scan/schemas/plan-v1.schema.json" in n for n in names)
    assert any("ai_scan/packs/builtin/" in n and n.endswith(".json") for n in names)
    assert any("ai_scan/reporting/templates/report.html" in n for n in names)


def test_wheel_has_license_and_entrypoint_metadata(artifacts: dict[str, list[str]]) -> None:
    names = artifacts["wheel"]
    assert any(n.endswith("LICENSE") for n in names)
    assert any(n.endswith("entry_points.txt") for n in names)


def test_sdist_includes_runtime_data_and_license(artifacts: dict[str, list[str]]) -> None:
    names = artifacts["sdist"]
    assert any(n.endswith("pyproject.toml") for n in names)
    assert any(n.endswith("LICENSE") for n in names)
    assert any("src/ai_scan/py.typed" in n for n in names)
    assert any("src/ai_scan/schemas/plan-v1.schema.json" in n for n in names)
    assert any("src/ai_scan/packs/builtin/" in n and n.endswith(".json") for n in names)


def test_sdist_does_not_ship_tests(artifacts: dict[str, list[str]]) -> None:
    # Chosen contract: tests are not shipped, so no fixture-missing failures.
    assert not any("/tests/" in n or n.endswith("/tests") for n in artifacts["sdist"])


def test_artifacts_exclude_local_and_generated(artifacts: dict[str, list[str]]) -> None:
    forbidden = (".hermes", ".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache")
    forbidden_suffix = (".checkpoint.json", ".bundle.json", "sbom.cdx.json")
    for group in ("wheel", "sdist"):
        for name in artifacts[group]:
            assert not any(part in name for part in forbidden), (group, name)
            assert not any(name.endswith(sfx) for sfx in forbidden_suffix), (group, name)
