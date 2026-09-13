# Optional isolated local worker

AI-Scan can launch a disposable local Docker worker for future adapter/plugin work
without changing CLI semantics. The default worker protocol currently supports
only safe non-network `ping`/`echo` smoke operations; active assessment traffic
continues to flow through the in-process authorization gate, request broker,
scope guard, budgets, and redaction pipeline.

## Build

```bash
docker build -f Dockerfile.worker -t ai-scan-worker:local .
```

The image runs as UID/GID `65532:65532` and starts `docker/entrypoint.py`, which
accepts one bounded JSON worker request on stdin and returns one bounded JSON
result on stdout.

## Runtime hardening

`ai_scan.worker.local.WorkerOptions.docker_run_command()` constructs the Docker
invocation with these controls:

- non-root user `65532:65532`;
- read-only root filesystem;
- tmpfs-only `/tmp` and `/work` scratch paths with `noexec,nosuid,nodev`;
- `--cap-drop ALL` and `--security-opt no-new-privileges`;
- no Docker socket mount and no implicit host-home mount;
- `--network none` by default, so the worker cannot bypass the central request
  broker or connect to disallowed fixtures;
- CPU, memory, PID, and subprocess timeout limits;
- optional artifact output only through one explicit operator-selected bind mount
  at `/artifacts`;
- optional short-lived secret injection by validated environment-variable name
  only. Secret values are never interpolated into commands or error messages.

## Egress policy

This milestone intentionally fails closed for container egress: Docker networking
is disabled. Target-scoped egress for containerized active work requires a
separate network policy layer that pins the actual container connection target to
the same resolved endpoint vetted by AI-Scan's `ScopeGuard`. Until that exists,
worker code must not perform active network assessment traffic.

## CI/rootless-compatible test path

The committed tests do not require a Docker daemon. They verify the protocol,
entrypoint subprocess behavior, and generated Docker hardening arguments. On a
host with Docker available, run the optional smoke path manually:

```bash
docker build -f Dockerfile.worker -t ai-scan-worker:local .
python - <<'PY'
from ai_scan.worker import LocalWorker, WorkerRequest
print(LocalWorker().run(WorkerRequest('worker-v1', 'ping', '')).to_json())
PY
```

Expected result: `{"output":"pong","protocol_version":"worker-v1","status":"ok"}`.
