"""Docker-backed optional local worker launcher.

The launcher builds a deterministic `docker run` command with fail-closed
hardening. It uses `subprocess.run([...], shell=False)` only, validates all
operator-controlled values before command construction, and keeps Docker network
access disabled by default so the worker cannot create an out-of-broker egress
path.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from ai_scan.worker.protocol import WorkerProtocolError, WorkerRequest, WorkerResult

_IMAGE_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$")
_SECRET_ENV_RE: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_DEFAULT_USER = "65532:65532"
_DEFAULT_WORKDIR = "/work"
_ARTIFACT_TARGET = "/artifacts"


class WorkerExecutionError(RuntimeError):
    """Raised when the isolated worker cannot be launched or returns invalid output."""


def _validate_positive_int(value: int, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")


def _validate_positive_float(value: float, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value <= 0:
        raise ValueError(f"{field} must be a positive number")


def _validate_docker_token(value: str, field: str) -> str:
    if not isinstance(value, str) or not _IMAGE_RE.fullmatch(value):
        raise ValueError(f"{field} is not a safe Docker reference")
    return value


def _artifact_dir(path: Path | None) -> Path | None:
    if path is None:
        return None
    resolved = path.expanduser().resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise ValueError("artifact_dir must be an existing directory")
    return resolved


@dataclass(frozen=True)
class WorkerOptions:
    """Hardening and resource settings for a disposable local worker."""

    image: str = "ai-scan-worker:local"
    cpus: float = 1.0
    memory: str = "256m"
    pids_limit: int = 64
    timeout_seconds: int = 30
    tmpfs_size: str = "16m"
    artifact_dir: Path | None = None
    secret_env: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _validate_docker_token(self.image, "image")
        _validate_positive_float(self.cpus, "cpus")
        _validate_positive_int(self.pids_limit, "pids_limit")
        _validate_positive_int(self.timeout_seconds, "timeout_seconds")
        _validate_docker_token(self.memory, "memory")
        _validate_docker_token(self.tmpfs_size, "tmpfs_size")
        object.__setattr__(self, "artifact_dir", _artifact_dir(self.artifact_dir))
        if not isinstance(self.secret_env, frozenset):
            raise ValueError("secret_env must be a frozenset of environment names")
        for name in self.secret_env:
            if not isinstance(name, str) or not _SECRET_ENV_RE.fullmatch(name):
                raise ValueError("secret_env contains an invalid environment name")

    def docker_run_command(self) -> list[str]:
        """Return the hardened docker command prefix.

        The command has no Docker socket mount, no host home mount, no Linux
        capabilities, no network, a read-only root filesystem, tmpfs scratch
        space, a non-root uid/gid, and bounded CPU/memory/PID limits.
        """

        command = [
            "docker",
            "run",
            "--rm",
            "--interactive",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.pids_limit),
            "--cpus",
            str(self.cpus),
            "--memory",
            self.memory,
            "--user",
            _DEFAULT_USER,
            "--workdir",
            _DEFAULT_WORKDIR,
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={self.tmpfs_size}",
            "--tmpfs",
            f"{_DEFAULT_WORKDIR}:rw,noexec,nosuid,nodev,size={self.tmpfs_size}",
        ]
        if self.artifact_dir is not None:
            command.extend(
                [
                    "--mount",
                    f"type=bind,src={self.artifact_dir},dst={_ARTIFACT_TARGET},rw",
                ]
            )
        for name in sorted(self.secret_env):
            command.extend(["--env", name])
        command.append(self.image)
        return command


@dataclass(frozen=True)
class LocalWorker:
    """Execute a worker request in a short-lived hardened container."""

    options: WorkerOptions = WorkerOptions()

    def run(self, request: WorkerRequest) -> WorkerResult:
        command = self.options.docker_run_command()
        try:
            completed = subprocess.run(
                command,
                input=request.to_json(),
                text=True,
                capture_output=True,
                timeout=self.options.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkerExecutionError("isolated worker execution failed") from exc
        if completed.returncode != 0:
            raise WorkerExecutionError("isolated worker exited unsuccessfully")
        try:
            return WorkerResult.from_json(completed.stdout)
        except WorkerProtocolError as exc:
            raise WorkerExecutionError("isolated worker returned invalid protocol output") from exc
