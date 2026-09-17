"""Astra Step 1D residue, docs, workflow, and cumulative acceptance gates."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ai_scan.attacks import memory
from ai_scan.worker import WorkerOptions, WorkerRequest
from ai_scan.worker.protocol import WorkerResult

_REPO = Path(__file__).resolve().parents[2]
_README = _REPO / "README.md"
_OPERATOR = _REPO / "docs" / "operator-guide.md"
_CONTAINER_WORKER = _REPO / "docs" / "container-worker.md"
_CI = _REPO / ".github" / "workflows" / "ci.yml"
_PACKAGE = _REPO / ".github" / "workflows" / "package.yml"

_FORBIDDEN_PRODUCT_AUTH_PHRASES = (
    "state-write authorization",
    "scanner authorization",
    "scan authorization",
    "requires authorization",
    "require authorization",
    "authorization requirement",
    "authorization gate",
    "authorization prompt",
    "approval prompt",
    "preapproval",
    "pre-approval",
    "non-interactive",
    "--yes",
)


def _tracked_text_files() -> list[tuple[Path, str]]:
    import subprocess

    out = subprocess.run(
        ["git", "ls-files"],
        cwd=_REPO,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    suffixes = {
        ".py",
        ".md",
        ".json",
        ".toml",
        ".yml",
        ".yaml",
        ".in",
        ".txt",
        ".cfg",
        ".ini",
        ".sh",
    }
    names = {"Dockerfile.worker", "MANIFEST.in", ".dockerignore"}
    files: list[tuple[Path, str]] = []
    for rel in out.splitlines():
        path = _REPO / rel
        if not path.is_file():
            continue
        if path.name in names or path.suffix in suffixes:
            files.append((path, rel))
    return files


def _workflow_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_memory_plugin_docstring_describes_policy_without_product_authorization() -> None:
    doc = memory.__doc__ or ""
    lowered = doc.lower()
    assert "synthetic state" in lowered
    assert "state_write" in lowered or "state-write" in lowered
    assert "declared identities" in lowered
    assert "read-back evidence" in lowered
    assert "controls" in lowered
    assert "authoriz" not in lowered


def test_shipped_text_has_no_generic_product_authorization_wording() -> None:
    offenders: list[tuple[str, str]] = []
    for path, rel in _tracked_text_files():
        if rel in {
            "tests/release/test_no_authorization.py",
            "tests/release/test_docs_claims.py",
            "tests/contracts/test_cli_v2.py",
            "tests/contracts/test_mvp_compatibility.py",
            "tests/release/test_astra_step1d_acceptance.py",
        }:
            continue
        lowered = path.read_text(encoding="utf-8").lower()
        for phrase in _FORBIDDEN_PRODUCT_AUTH_PHRASES:
            if phrase in lowered:
                offenders.append((rel, phrase))
    assert offenders == []


def test_named_host_https_limitation_is_prominent_and_examples_avoid_happy_path() -> None:
    readme = _README.read_text(encoding="utf-8").lower()
    operator = _OPERATOR.read_text(encoding="utf-8").lower()
    combined = readme + "\n" + operator
    assert "named-host https" in combined
    assert "fails closed" in combined
    assert "vetted-ip" in combined
    assert "sni" in combined
    assert "certificate" in combined
    assert "not yet implemented" in combined
    assert "https://api.example.com/chat" not in readme


def test_worker_options_emit_exact_ping_request_and_hardening_flags() -> None:
    request = WorkerRequest("worker-v1", "ping", "")
    assert request.to_dict() == {
        "protocol_version": "worker-v1",
        "operation": "ping",
        "payload": "",
    }
    result = WorkerResult.from_json(
        '{"protocol_version":"worker-v1","status":"ok","output":"pong"}'
    )
    assert result.protocol_version == "worker-v1"
    assert result.status == "ok"
    assert result.output == "pong"

    command = WorkerOptions(image="ai-scan-worker:test").docker_run_command()
    flags = ("--network", "--cap-drop", "--security-opt", "--user")
    assert [command[command.index(flag) + 1] for flag in flags] == [
        "none",
        "ALL",
        "no-new-privileges",
        "65532:65532",
    ]
    assert "--read-only" in command


@pytest.mark.parametrize(
    "workflow,image",
    [(_CI, "ai-scan-worker:ci"), (_PACKAGE, "ai-scan-worker:release")],
)
def test_workflows_run_actual_hardened_worker_protocol_exchange(workflow: Path, image: str) -> None:
    text = _workflow_text(workflow)
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
    assert "--network none" in text
    assert "--read-only" in text
    assert "--cap-drop ALL" in text
    assert "--security-opt no-new-privileges" in text
    assert "--user 65532:65532" in text
    assert "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m" in text
    assert "--tmpfs /work:rw,noexec,nosuid,nodev,size=16m" in text
    assert expected_request in text
    assert expected_result in text


@pytest.mark.parametrize("workflow", [_CI, _PACKAGE])
def test_workflow_actions_remain_immutable_sha_pinned(workflow: Path) -> None:
    text = _workflow_text(workflow)
    uses_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip().startswith(("uses:", "- uses:"))
    ]
    assert uses_lines
    for line in uses_lines:
        assert re.search(r"@[0-9a-f]{40}\s+#\s+v[0-9]", line), line
        assert not re.search(r"@(main|master|v\d+)\b", line), line


def test_docs_describe_worker_protocol_smoke_not_static_build_only() -> None:
    combined = (
        _README.read_text(encoding="utf-8")
        + "\n"
        + _OPERATOR.read_text(encoding="utf-8")
        + "\n"
        + _CONTAINER_WORKER.read_text(encoding="utf-8")
    ).lower()
    assert "hardened worker protocol smoke" in combined
    assert "exact pong" in combined
    assert "non-root uid" in combined
    assert "build/scan" not in combined
    assert "static scan" not in combined


def test_cumulative_astra_acceptance_harness_is_documented_and_local() -> None:
    harness = _REPO / "tests" / "release" / "test_astra_cumulative_acceptance.py"
    assert harness.is_file()
    text = harness.read_text(encoding="utf-8")
    for token in (
        "transport/proxy/DNS/deadline",
        "redaction",
        "provider extraction",
        "evidence round-trip/replay/plugin physical trials",
        "H3 lifecycle",
        "M3 interruption/resume/accounting",
        "no-product-authorization",
        "worker protocol",
    ):
        assert token in text
    assert "old /tmp scripts" not in text.lower()
