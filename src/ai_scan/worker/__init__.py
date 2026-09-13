"""Optional isolated local worker support."""

from ai_scan.worker.local import LocalWorker, WorkerExecutionError, WorkerOptions
from ai_scan.worker.protocol import WorkerProtocolError, WorkerRequest, WorkerResult

__all__ = [
    "LocalWorker",
    "WorkerExecutionError",
    "WorkerOptions",
    "WorkerProtocolError",
    "WorkerRequest",
    "WorkerResult",
]
