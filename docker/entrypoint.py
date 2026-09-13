"""Container entrypoint for the optional ai-scan local worker."""

from __future__ import annotations

import sys

from ai_scan.worker.protocol import WorkerProtocolError, WorkerRequest, error_result, handle_request


def main() -> int:
    raw = sys.stdin.buffer.read()
    try:
        request = WorkerRequest.from_json(raw)
        result = handle_request(request)
    except WorkerProtocolError:
        # Do not reflect malformed input or exception text across the boundary.
        result = error_result("invalid worker request")
    sys.stdout.write(result.to_json())
    sys.stdout.write("\n")
    return 0 if result.status == "ok" else 1


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess/container smoke paths
    raise SystemExit(main())
