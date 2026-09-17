# Optional isolated local worker

AI-Scan can launch a disposable local Docker worker for future adapter/plugin work
without changing CLI semantics. The default worker protocol currently supports
only safe non-network `ping`/`echo` smoke operations; active assessment traffic
continues to flow through the in-process request broker, scope guard, budgets,
and redaction pipeline.

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
entrypoint subprocess behavior, and generated Docker hardening arguments. The CI
and package workflows additionally run a hardened worker protocol smoke when
Docker is available: they build the image, verify a non-root uid, then send the
exact `worker-v1` ping request and require the exact pong result under
`--network none`, `--read-only`, `--cap-drop ALL`, and
`--security-opt no-new-privileges`. On a host with Docker available, run the same
smoke path manually:

```bash
docker build -f Dockerfile.worker -t ai-scan-worker:local .
uid="$(docker run --rm --entrypoint id ai-scan-worker:local -u)"
test "$uid" != "0"
actual="$(printf '%s' '{"protocol_version":"worker-v1","operation":"ping","payload":""}' | docker run --rm --interactive --read-only --network none --cap-drop ALL --security-opt no-new-privileges --user 65532:65532 --workdir /work --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --tmpfs /work:rw,noexec,nosuid,nodev,size=16m ai-scan-worker:local)"
test "$actual" = '{"output":"pong","protocol_version":"worker-v1","status":"ok"}'
```

Expected result: `{"output":"pong","protocol_version":"worker-v1","status":"ok"}`.
