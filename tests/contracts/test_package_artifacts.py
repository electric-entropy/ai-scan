"""Milestone 2: built wheel and sdist include all schemas, py.typed, payloads.

Builds the distributions once (no build isolation, using the current toolchain)
and inspects the actual artifacts — so a missing ``package-data`` entry fails
here rather than only in manual release checks.
"""

from __future__ import annotations

import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_SCHEMAS = [
    "target-v1.schema.json",
    "engagement-v1.schema.json",
    "plan-v1.schema.json",
    "pack-v1.schema.json",
    "evidence-v2.schema.json",
    "finding-v2.schema.json",
    "receipt-v2.schema.json",
]
EXPECTED_DATA = [
    "py.typed",
    "payloads/safe.json",
    "packs/builtin/direct-injection-reliable-v1.json",
    "packs/builtin/direct-injection-kitchen-v1.json",
    "packs/builtin/indirect-injection-reliable-v1.json",
    "packs/builtin/indirect-injection-kitchen-v1.json",
    "packs/builtin/rag-isolation-reliable-v1.json",
    "packs/builtin/rag-isolation-kitchen-v1.json",
    "reporting/templates/report.html",
]
EXPECTED_SDIST_FILES = [
    "Dockerfile.worker",
    "docker/entrypoint.py",
    "docs/container-worker.md",
    "tests/integration/test_container_worker.py",
]


@pytest.fixture(scope="module")
def built_dists(tmp_path_factory) -> tuple[Path, Path]:
    pytest.importorskip("build")
    out = tmp_path_factory.mktemp("dist")
    result = subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--outdir", str(out), str(REPO_ROOT)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:  # pragma: no cover - surfaces build failures
        pytest.fail(f"build failed:\n{result.stdout}\n{result.stderr}")
    wheels = list(out.glob("*.whl"))
    sdists = list(out.glob("*.tar.gz"))
    assert wheels and sdists, "expected a wheel and an sdist"
    return wheels[0], sdists[0]


def test_wheel_contains_all_schemas_and_data(built_dists) -> None:
    wheel, _sdist = built_dists
    with zipfile.ZipFile(wheel) as zf:
        names = set(zf.namelist())
    for schema in EXPECTED_SCHEMAS:
        assert f"ai_scan/schemas/{schema}" in names, f"wheel missing {schema}"
    for data in EXPECTED_DATA:
        assert f"ai_scan/{data}" in names, f"wheel missing {data}"


def test_sdist_contains_all_schemas_and_data(built_dists) -> None:
    _wheel, sdist = built_dists
    with tarfile.open(sdist, "r:gz") as tf:
        names = set(tf.getnames())

    def present(suffix: str) -> bool:
        return any(n.endswith(f"/src/ai_scan/{suffix}") for n in names)

    for schema in EXPECTED_SCHEMAS:
        assert present(f"schemas/{schema}"), f"sdist missing {schema}"
    for data in EXPECTED_DATA:
        assert present(data), f"sdist missing {data}"
    for suffix in EXPECTED_SDIST_FILES:
        assert any(n.endswith(f"/{suffix}") for n in names), f"sdist missing {suffix}"
