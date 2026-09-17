"""W1 — CI/package workflow correctness (least-priv, gates, tag binding, pins)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CI = _REPO_ROOT / ".github" / "workflows" / "ci.yml"
_PACKAGE = _REPO_ROOT / ".github" / "workflows" / "package.yml"

# actions/upload-artifact SHAs (v4.6.2 verified in the audit; v7.0.1 verified
# upstream during v0.2.1 release maintenance).
_UPLOAD_ARTIFACT_V462_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
_UPLOAD_ARTIFACT_V701_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [_CI, _PACKAGE])
def test_workflow_has_least_privilege_permissions(path: Path) -> None:
    text = _text(path)
    assert "permissions:" in text
    assert "contents: read" in text


@pytest.mark.parametrize("path", [_CI, _PACKAGE])
def test_workflow_has_concurrency_cancellation(path: Path) -> None:
    text = _text(path)
    assert "concurrency:" in text
    assert "cancel-in-progress: true" in text


@pytest.mark.parametrize("path", [_CI, _PACKAGE])
def test_workflow_jobs_have_timeout(path: Path) -> None:
    assert "timeout-minutes:" in _text(path)


def test_upload_artifact_pin_matches_comment() -> None:
    text = _text(_PACKAGE)
    # The upload-artifact action must be pinned to the SHA whose comment it bears.
    line = next(
        ln for ln in text.splitlines() if "actions/upload-artifact@" in ln
    )
    assert _UPLOAD_ARTIFACT_V701_SHA in line
    assert "v7.0.1" in line


def test_package_gates_precede_upload() -> None:
    text = _text(_PACKAGE)
    upload_at = text.index("Upload artifacts")
    for gate in (
        "python -m pytest",
        "ruff check",
        "mypy",
        "python -m build",
        "scripts.credential_scan",
        "scripts.generate_sbom",
        "scripts.reproducible_build",
        "Container worker hardened protocol smoke",
    ):
        assert gate in text, gate
        assert text.index(gate) < upload_at, gate


def test_package_verifies_tag_equals_version() -> None:
    text = _text(_PACKAGE)
    # A step must compare the pushed tag to the project version and fail on mismatch.
    assert "github.ref_name" in text or "GITHUB_REF_NAME" in text
    assert "tag" in text.lower() and "version" in text.lower()
    assert "importlib.metadata" in text or "metadata.version" in text


def test_package_uploads_built_dist_not_checked_in() -> None:
    text = _text(_PACKAGE)
    assert "dist/*.whl" in text
    assert "dist/*.tar.gz" in text


def test_ci_runs_core_gates() -> None:
    text = _text(_CI)
    for gate in (
        "python -m pytest",
        "ruff check",
        "mypy",
        "python -m build",
        "scripts.credential_scan",
        "scripts.generate_sbom",
    ):
        assert gate in text, gate


def test_package_uploads_sbom_artifact() -> None:
    text = _text(_PACKAGE)
    assert "sbom.cdx.json" in text


@pytest.mark.parametrize("path", [_CI, _PACKAGE])
def test_fresh_wheel_smoke_runs_doctor(path: Path) -> None:
    # The offline `doctor` health check must run against the installed wheel.
    assert "ai-scan doctor" in _text(path)


# Known-good SHAs for the pinned actions (comment version -> commit SHA).
_KNOWN_ACTION_SHAS = {
    "actions/upload-artifact": {
        "v4.6.2": _UPLOAD_ARTIFACT_V462_SHA,
        "v7.0.1": _UPLOAD_ARTIFACT_V701_SHA,
    },
}
_USES_RE = re.compile(
    r"uses:\s*(?P<action>[^@\s]+)@(?P<sha>[0-9a-fA-F]{40})\s*#\s*(?P<ver>v[\w.]+)"
)


@pytest.mark.parametrize("path", [_CI, _PACKAGE])
def test_every_action_is_sha_pinned_with_version_comment(path: Path) -> None:
    for line in _text(path).splitlines():
        stripped = line.strip()
        if not stripped.startswith("- uses:") and not stripped.startswith("uses:"):
            continue
        match = _USES_RE.search(line)
        assert match, f"action not SHA-pinned with a version comment: {line!r}"
        # No mutable refs (e.g. @v4, @main) may slip in.
        assert "@main" not in line and not re.search(r"@v\d+\b", line), line


def test_pinned_shas_match_known_versions() -> None:
    for path in (_CI, _PACKAGE):
        for line in _text(path).splitlines():
            match = _USES_RE.search(line)
            if not match:
                continue
            action, sha, ver = match.group("action"), match.group("sha"), match.group("ver")
            known = _KNOWN_ACTION_SHAS.get(action, {})
            if ver in known:
                assert sha.lower() == known[ver], f"{action}@{ver} SHA mismatch: {sha}"


@pytest.mark.parametrize(
    "path,image",
    [(_CI, "ai-scan-worker:ci"), (_PACKAGE, "ai-scan-worker:release")],
)
def test_worker_workflow_runs_hardened_protocol_smoke(path: Path, image: str) -> None:
    text = _text(path)
    expected_request = (
        "expected='{" + '"protocol_version":"worker-v1","operation":"ping","payload":""' + "}'"
    )
    expected_result = (
        "test \"$actual\" = '{\"output\":\"pong\","
        "\"protocol_version\":\"worker-v1\",\"status\":\"ok\"}'"
    )
    assert "Container worker hardened protocol smoke" in text
    assert f"docker build -f Dockerfile.worker -t {image} ." in text
    assert f"docker run --rm --entrypoint id {image} -u" in text
    assert "test \"$uid\" != \"0\"" in text
    for flag in (
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--user 65532:65532",
    ):
        assert flag in text
    assert expected_request in text
    assert expected_result in text
