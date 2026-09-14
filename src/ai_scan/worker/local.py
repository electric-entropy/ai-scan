"""Docker-backed optional local worker launcher.

The launcher builds a deterministic `docker run` command with fail-closed
hardening. It runs the process with `subprocess.Popen([...], shell=False)` and a
bounded stdout read (never `capture_output`, which would fully buffer a hostile
worker's stdout before validation), validates all operator-controlled values
before command construction, and keeps Docker network access disabled by default
so the worker cannot create an out-of-broker egress path.
"""

from __future__ import annotations

import math
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

from ai_scan.worker.protocol import (
    MAX_MESSAGE_BYTES,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResult,
)

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
    if not math.isfinite(value):
        raise ValueError(f"{field} must be a finite number")


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
    # Expose an EMPTY dedicated output directory, never one with arbitrary
    # pre-existing contents that could leak into or out of the worker.
    if any(resolved.iterdir()):
        raise ValueError("artifact_dir must be an empty dedicated directory")
    return resolved


def _read_capped(stream: IO[bytes], cap: int) -> bytes:
    """Read at most ``cap`` bytes; fail closed if the stream exceeds it.

    Reads ``cap + 1`` bytes so an unbounded worker stdout cannot force a large
    allocation before the size is checked.
    """
    raw = stream.read(cap + 1)
    if len(raw) > cap:
        raise WorkerExecutionError("isolated worker produced too much output")
    return raw


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
        request_bytes = request.to_json().encode("utf-8")
        # Stream stdout with a bounded read instead of subprocess.run(
        # capture_output=True), which would fully buffer a hostile worker's
        # stdout in memory before any size check. stderr is redirected to
        # /dev/null so the same allocation issue cannot move there.
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError as exc:
            raise WorkerExecutionError("isolated worker execution failed") from exc

        assert proc.stdin is not None and proc.stdout is not None
        stdin, stdout_stream = proc.stdin, proc.stdout

        def _write() -> None:
            try:
                stdin.write(request_bytes)
                stdin.close()
            except OSError:
                # Worker exited/closed stdin early; stdout/return code decide.
                pass

        read_result: dict[str, object] = {}

        def _read() -> None:
            try:
                read_result["stdout"] = _read_capped(stdout_stream, MAX_MESSAGE_BYTES)
            except WorkerExecutionError as exc:  # oversized output
                read_result["error"] = exc

        # The whole IO (stdin write, bounded stdout read, and process exit) must
        # complete within timeout_seconds. Both the write and the read run on
        # daemon threads so a worker that never reads stdin, or that emits a
        # partial result and holds stdout open, cannot hang past the deadline.
        deadline = time.monotonic() + self.options.timeout_seconds
        writer = threading.Thread(target=_write, daemon=True)
        reader = threading.Thread(target=_read, daemon=True)
        writer.start()
        reader.start()
        try:
            writer.join(max(0.0, deadline - time.monotonic()))
            reader.join(max(0.0, deadline - time.monotonic()))
            if writer.is_alive() or reader.is_alive():
                raise WorkerExecutionError("isolated worker timed out")
            if "error" in read_result:
                raise read_result["error"]  # type: ignore[misc]
            try:
                returncode = proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired as exc:
                raise WorkerExecutionError("isolated worker timed out") from exc
        finally:
            if proc.poll() is None:
                proc.kill()
            # Reap the IO threads once the process is gone (their blocking pipe
            # operations unblock on kill).
            writer.join(1.0)
            reader.join(1.0)
        if returncode != 0:
            raise WorkerExecutionError("isolated worker exited unsuccessfully")
        stdout = read_result.get("stdout", b"")
        try:
            return WorkerResult.from_json(stdout)  # type: ignore[arg-type]
        except WorkerProtocolError as exc:
            raise WorkerExecutionError("isolated worker returned invalid protocol output") from exc
