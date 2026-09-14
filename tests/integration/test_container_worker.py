"""Milestone 20: optional isolated local worker controls."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, cast

import pytest

from ai_scan.worker import LocalWorker, WorkerExecutionError, WorkerOptions, WorkerRequest
from ai_scan.worker.protocol import WorkerProtocolError, WorkerResult

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_worker_protocol_rejects_unknown_fields_and_oversized_payload() -> None:
    with pytest.raises(WorkerProtocolError):
        WorkerRequest.from_json(
            '{"protocol_version":"worker-v1","operation":"ping","payload":"","extra":true}'
        )
    with pytest.raises(WorkerProtocolError):
        WorkerRequest("worker-v1", "echo", "x" * (64 * 1024 + 1))


def test_worker_options_generate_fail_closed_docker_hardening(tmp_path: Path) -> None:
    options = WorkerOptions(
        artifact_dir=tmp_path,
        secret_env=frozenset({"AI_SCAN_TOKEN"}),
        cpus=0.5,
        memory="128m",
        pids_limit=32,
        timeout_seconds=5,
    )
    command = options.docker_run_command()

    assert command[:3] == ["docker", "run", "--rm"]
    assert "--read-only" in command
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert command[command.index("--user") + 1] == "65532:65532"
    assert command[command.index("--pids-limit") + 1] == "32"
    assert command[command.index("--memory") + 1] == "128m"
    assert not any("docker.sock" in part for part in command)
    assert not any(str(Path.home()) == part for part in command)
    assert any(part.startswith("type=bind,") and "dst=/artifacts" in part for part in command)
    assert command[command.index("--env") + 1] == "AI_SCAN_TOKEN"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"image": "bad image"},
        {"pids_limit": 0},
        {"timeout_seconds": 0},
        {"secret_env": {"TOKEN"}},
        {"secret_env": frozenset({"bad-name"})},
    ],
)
def test_worker_options_reject_malformed_inputs(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        WorkerOptions(**kwargs)  # type: ignore[arg-type]


def test_entrypoint_handles_valid_ping_without_network_or_docker() -> None:
    request = WorkerRequest("worker-v1", "ping", "").to_json()
    completed = subprocess.run(
        [sys.executable, str(REPO_ROOT / "docker" / "entrypoint.py")],
        input=request,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert WorkerResult.from_json(completed.stdout).output == "pong"


def test_entrypoint_does_not_reflect_malformed_payload() -> None:
    hostile_marker = "credential-shaped-canary-value"
    completed = subprocess.run(
        [sys.executable, str(REPO_ROOT / "docker" / "entrypoint.py")],
        input=f"not json {hostile_marker}",
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 1
    assert hostile_marker not in completed.stdout
    result = WorkerResult.from_json(completed.stdout)
    assert result.status == "error"
    assert result.output == "invalid worker request"


class _FakePopen:
    """Minimal stand-in for subprocess.Popen used by LocalWorker.run()."""

    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        import io

        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(stdout)
        self._rc = returncode
        self.wait_timeout: float | None = None

    def wait(self, timeout: float | None = None) -> int:
        self.wait_timeout = timeout
        return self._rc

    def poll(self) -> int:
        return self._rc

    def kill(self) -> None:  # pragma: no cover - not reached on the happy path
        pass


def test_local_worker_uses_shell_false_and_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []
    procs: list[_FakePopen] = []

    def fake_popen(*args: object, **kwargs: object) -> _FakePopen:
        calls.append({"args": args, "kwargs": kwargs})
        proc = _FakePopen(WorkerResult("worker-v1", "ok", "pong").to_json().encode("utf-8"))
        procs.append(proc)
        return proc

    def forbid_run(*_a: object, **_k: object) -> None:
        raise AssertionError("run() must stream via Popen, not subprocess.run")

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(subprocess, "run", forbid_run)
    worker = LocalWorker(WorkerOptions(timeout_seconds=7))
    result = worker.run(WorkerRequest("worker-v1", "ping", ""))
    assert result.output == "pong"
    kwargs = cast(dict[str, Any], calls[0]["kwargs"])
    args = cast(tuple[object, ...], calls[0]["args"])
    assert "shell" not in kwargs
    assert "capture_output" not in kwargs
    assert kwargs["stdout"] is subprocess.PIPE
    assert kwargs["stderr"] is subprocess.DEVNULL
    assert isinstance(args[0], list)
    # timeout is enforced as the remaining deadline budget (0 < t <= 7).
    assert procs[0].wait_timeout is not None
    assert 0 < procs[0].wait_timeout <= 7


def test_local_worker_fail_closed_on_bad_worker_output(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_popen(*args: object, **kwargs: object) -> _FakePopen:
        return _FakePopen(b"{}", returncode=0)

    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    with pytest.raises(WorkerExecutionError):
        LocalWorker().run(WorkerRequest("worker-v1", "ping", ""))
