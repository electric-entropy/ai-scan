"""Milestone 21 release-hardening contracts."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

RELEASE_DOCS = [
    "CHANGELOG.md",
    "docs/operator-guide.md",
    "docs/pack-authoring.md",
    "docs/evidence-and-retention.md",
    "docs/threat-model.md",
]
WORKFLOWS = [
    ".github/workflows/ci.yml",
    ".github/workflows/package.yml",
]


def _read(rel: str) -> str:
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def test_release_documentation_is_self_contained() -> None:
    for rel in RELEASE_DOCS:
        text = _read(rel)
        assert ".hermes" not in text
        assert "external target" in text.lower() or rel != "docs/operator-guide.md"

    readme = _read("README.md")
    security = _read("SECURITY.md")
    for rel in RELEASE_DOCS:
        assert rel in readme or rel == "CHANGELOG.md"
    assert "docs/operator-guide.md" in security
    assert "docs/evidence-and-retention.md" in security
    assert "docs/pack-authoring.md" in security


def test_ci_and_package_workflows_are_sha_pinned() -> None:
    version_ref = re.compile(r"uses:\s*[^@\s]+@v\d")
    sha_ref = re.compile(r"uses:\s*[^@\s]+@[0-9a-f]{40}(?:\s|$)")
    for rel in WORKFLOWS:
        text = _read(rel)
        assert not version_ref.search(text), f"{rel} has mutable version action ref"
        uses_lines = [
            line.strip() for line in text.splitlines() if line.strip().startswith("uses:")
        ]
        assert uses_lines, f"{rel} should use at least checkout/setup actions"
        for line in uses_lines:
            assert sha_ref.search(line), f"{rel} action is not pinned to a full SHA: {line}"


def test_ci_release_gates_cover_milestone_21_acceptance() -> None:
    ci = _read(".github/workflows/ci.yml")
    required_snippets = [
        'python-version: ["3.11", "3.12"]',
        "python -m pytest tests/contracts -q",
        "python -m pytest -q",
        "ruff check .",
        "mypy",
        "python -m build",
        "ai-scan --help",
        "License-Expression",
        "py.typed",
        "Secret scan",
        "Dependency audit and SBOM",
        "Container worker static scan",
    ]
    for snippet in required_snippets:
        assert snippet in ci


def test_package_workflow_keeps_distribution_artifacts_and_listing() -> None:
    package = _read(".github/workflows/package.yml")
    for snippet in [
        "python -m build",
        "ai-scan --help",
        "License-Expression",
        "artifact-contents.json",
        "Upload artifacts",
        "dist/*.whl",
        "dist/*.tar.gz",
    ]:
        assert snippet in package
