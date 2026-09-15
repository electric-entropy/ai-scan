"""W6 — isolated-worker hardening and container ignore rules."""

from __future__ import annotations

import io
import math
import sys
import time
from pathlib import Path

import pytest

from ai_scan.worker import local, protocol

_REPO_ROOT = Path(__file__).resolve().parents[2]


def _valid_request_json() -> str:
    return protocol.WorkerRequest("worker-v1", "echo", "hi").to_json()


def test_protocol_rejects_duplicate_json_keys() -> None:
    dup = '{"protocol_version": "worker-v1", "protocol_version": "worker-v1",' \
          ' "operation": "ping", "payload": ""}'
    with pytest.raises(protocol.WorkerProtocolError):
        protocol.WorkerRequest.from_json(dup)


def test_protocol_rejects_non_finite_numbers_in_json() -> None:
    bad = '{"protocol_version": "worker-v1", "operation": "echo", "payload": NaN}'
    with pytest.raises(protocol.WorkerProtocolError):
        protocol.WorkerRequest.from_json(bad)


@pytest.mark.parametrize("value", [math.inf, -math.inf, math.nan])
def test_options_reject_non_finite_cpus(value: float) -> None:
    with pytest.raises(ValueError):
        local.WorkerOptions(cpus=value)


def test_read_bounded_rejects_oversized_stdin_before_full_read() -> None:
    oversized = b"x" * (protocol.MAX_MESSAGE_BYTES + 1024)
    stream = io.BytesIO(oversized)
    with pytest.raises(protocol.WorkerProtocolError):
        protocol.read_bounded(stream)
    # It must not have consumed the whole stream (bounded read, no full alloc).
    assert stream.tell() <= protocol.MAX_MESSAGE_BYTES + 1


def test_read_bounded_accepts_valid_message() -> None:
    payload = _valid_request_json().encode("utf-8")
    assert protocol.read_bounded(io.BytesIO(payload)) == payload


def test_launcher_caps_output_before_allocation() -> None:
    huge = io.BytesIO(b"y" * (protocol.MAX_MESSAGE_BYTES * 4))
    with pytest.raises(local.WorkerExecutionError):
        local._read_capped(huge, protocol.MAX_MESSAGE_BYTES)


class _RecordingStream(io.BytesIO):
    """A BytesIO that records the size argument of every read()."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_sizes: list[int] = []

    def read(self, size: int | None = -1) -> bytes:
        self.read_sizes.append(-1 if size is None else size)
        return super().read(size)


class _FakePopen:
    def __init__(self, stdout: bytes, returncode: int = 0) -> None:
        self.stdin = io.BytesIO()
        self.stdout = _RecordingStream(stdout)
        self.stderr = None
        self._rc = returncode
        self.killed = False

    def wait(self, timeout: float | None = None) -> int:
        return self._rc

    def poll(self) -> int:
        return self._rc

    def kill(self) -> None:
        self.killed = True


def _patch_launcher(monkeypatch: pytest.MonkeyPatch, stdout: bytes, rc: int = 0) -> dict:
    captured: dict = {}

    def fake_popen(cmd, **kwargs):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        proc = _FakePopen(stdout, rc)
        captured["proc"] = proc
        return proc

    def forbid_run(*_a, **_k):  # type: ignore[no-untyped-def]
        raise AssertionError("LocalWorker.run must not use subprocess.run/capture_output")

    monkeypatch.setattr(local.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(local.subprocess, "run", forbid_run)
    return captured


def test_run_streams_stdout_without_capture_output(monkeypatch: pytest.MonkeyPatch) -> None:
    result = protocol.WorkerResult("worker-v1", "ok", "pong").to_json().encode("utf-8")
    captured = _patch_launcher(monkeypatch, result)
    out = local.LocalWorker().run(protocol.WorkerRequest("worker-v1", "ping", ""))
    assert out.output == "pong"
    kwargs = captured["kwargs"]
    # The launcher must NOT use capture_output and must bound the stdout read.
    assert "capture_output" not in kwargs
    assert kwargs.get("stdout") is local.subprocess.PIPE
    # stderr must be capped/redirected (not an unbounded PIPE) so the same
    # allocation issue cannot move there.
    assert kwargs.get("stderr") is local.subprocess.DEVNULL
    read_sizes = captured["proc"].stdout.read_sizes
    assert read_sizes and -1 not in read_sizes
    assert max(read_sizes) <= protocol.MAX_MESSAGE_BYTES + 1


def test_run_fails_closed_on_oversized_worker_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    oversized = b"y" * (protocol.MAX_MESSAGE_BYTES + 100)
    captured = _patch_launcher(monkeypatch, oversized)
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker().run(protocol.WorkerRequest("worker-v1", "echo", "hi"))
    read_sizes = captured["proc"].stdout.read_sizes
    assert -1 not in read_sizes  # never an unbounded full-buffer read


def test_run_preserves_nonzero_exit_handling(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_launcher(monkeypatch, b"", rc=1)
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker().run(protocol.WorkerRequest("worker-v1", "ping", ""))


def test_read_bounded_boundary_exact_max() -> None:
    exact = b"x" * protocol.MAX_MESSAGE_BYTES
    assert protocol.read_bounded(io.BytesIO(exact)) == exact
    with pytest.raises(protocol.WorkerProtocolError):
        protocol.read_bounded(io.BytesIO(b"x" * (protocol.MAX_MESSAGE_BYTES + 1)))


# --- Real-subprocess timeout regressions (Crayon W6 blocker 3) ---------------
# These run LocalWorker.run() against a real python subprocess (via a
# monkeypatched command) so the timeout is exercised over real pipe IO, not only
# proc.wait(). A hostile worker that hangs on stdin-write or holds stdout open
# after a partial write must still be bounded by timeout_seconds.

_VALID_RESULT_SCRIPT = (
    "import sys;"
    'sys.stdout.write(\'{"protocol_version":"worker-v1","status":"ok","output":"pong"}\');'
    "sys.stdout.flush()"
)


def _patch_command(monkeypatch: pytest.MonkeyPatch, script: str) -> None:
    monkeypatch.setattr(
        local.WorkerOptions, "docker_run_command", lambda self: [sys.executable, "-c", script]
    )


def test_run_returns_result_via_real_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_command(monkeypatch, _VALID_RESULT_SCRIPT)
    captured: dict = {}
    real_popen = local.subprocess.Popen

    def recording_popen(cmd, **kwargs):  # type: ignore[no-untyped-def]
        captured["kwargs"] = kwargs
        return real_popen(cmd, **kwargs)

    def forbid_run(*_a, **_k):  # type: ignore[no-untyped-def]
        raise AssertionError("run() must not use subprocess.run")

    monkeypatch.setattr(local.subprocess, "Popen", recording_popen)
    monkeypatch.setattr(local.subprocess, "run", forbid_run)
    out = local.LocalWorker(local.WorkerOptions(timeout_seconds=5)).run(
        protocol.WorkerRequest("worker-v1", "ping", "")
    )
    assert out.output == "pong"
    assert "capture_output" not in captured["kwargs"]
    assert captured["kwargs"]["stdout"] is local.subprocess.PIPE
    assert captured["kwargs"]["stderr"] is local.subprocess.DEVNULL


def test_run_times_out_on_fully_hanging_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_command(monkeypatch, "import time; time.sleep(4)")
    start = time.monotonic()
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker(local.WorkerOptions(timeout_seconds=1)).run(
            protocol.WorkerRequest("worker-v1", "ping", "")
        )
    assert time.monotonic() - start < 3.0  # timeout fired, did not wait for worker exit


def test_run_times_out_on_partial_then_open_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    # Worker emits a small result then holds stdout open — the read must not hang.
    _patch_command(
        monkeypatch,
        "import sys, time; sys.stdout.write('partial'); sys.stdout.flush(); time.sleep(4)",
    )
    start = time.monotonic()
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker(local.WorkerOptions(timeout_seconds=1)).run(
            protocol.WorkerRequest("worker-v1", "echo", "hi")
        )
    assert time.monotonic() - start < 3.0


def test_run_times_out_on_stdin_write_hang(monkeypatch: pytest.MonkeyPatch) -> None:
    # Worker closes stdout immediately (reader gets EOF) but never reads stdin and
    # keeps running; the write and/or wait must still be bounded by the timeout.
    _patch_command(monkeypatch, "import sys, time; sys.stdout.close(); time.sleep(4)")
    big = protocol.WorkerRequest("worker-v1", "echo", "x" * protocol.MAX_PAYLOAD_BYTES)
    start = time.monotonic()
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker(local.WorkerOptions(timeout_seconds=1)).run(big)
    assert time.monotonic() - start < 3.0


def test_run_nonzero_exit_via_real_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_command(monkeypatch, "import sys; sys.exit(3)")
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker(local.WorkerOptions(timeout_seconds=5)).run(
            protocol.WorkerRequest("worker-v1", "ping", "")
        )


def test_run_invalid_protocol_via_real_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_command(monkeypatch, "import sys; sys.stdout.write('{}'); sys.stdout.flush()")
    with pytest.raises(local.WorkerExecutionError):
        local.LocalWorker(local.WorkerOptions(timeout_seconds=5)).run(
            protocol.WorkerRequest("worker-v1", "ping", "")
        )


def test_output_dir_must_be_empty(tmp_path: Path) -> None:
    (tmp_path / "pre_existing.txt").write_text("stale", encoding="utf-8")
    with pytest.raises(ValueError):
        local.WorkerOptions(artifact_dir=tmp_path)
    empty = tmp_path / "out"
    empty.mkdir()
    # An empty dedicated directory is accepted.
    local.WorkerOptions(artifact_dir=empty)


def test_dockerignore_excludes_sensitive_paths() -> None:
    text = (_REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
    patterns = {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    }
    for needed in (".git", ".hermes", "dist", "build", "tests", "*.checkpoint.json"):
        assert any(needed in p for p in patterns), needed
    for keyword in ("report", "bundle", "checkpoint", "secret"):
        assert any(keyword in p.lower() for p in patterns), keyword
