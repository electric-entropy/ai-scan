"""Atomic local content-addressed evidence artifact store.

The store persists already-redacted JSON-compatible evidence artifacts by their
canonical SHA-256 content digest. Writes are fail-closed: values are recursively
scrubbed before hashing, written through a private temporary file opened with
``0600`` permissions, fsynced, then atomically renamed into place. Reads accept
only canonical digest names, so callers cannot traverse outside the store root.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ai_scan.packs.signatures import compute_digest, verify_digest
from ai_scan.transport import scrub_structure

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class StoreError(Exception):
    """Raised when an evidence artifact cannot be stored or verified."""


@dataclass(frozen=True)
class ArtifactRef:
    """Reference to a locally persisted content-addressed artifact."""

    digest: str
    path: Path
    media_type: str = "application/json"


class ArtifactStore:
    """Private, content-addressed store for redacted JSON evidence artifacts."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)

    def write_json(self, value: dict[str, Any]) -> ArtifactRef:
        """Scrub, digest, and atomically persist ``value`` by content digest."""
        scrubbed = scrub_structure(value)
        if not isinstance(scrubbed, dict):  # pragma: no cover - scrub preserves dict here
            raise StoreError("artifact must be a JSON object")
        digest = compute_digest(scrubbed)
        content = dict(scrubbed)
        content["digest"] = digest
        payload = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        path = self._path_for_digest(digest)
        if path.exists():
            return ArtifactRef(digest=digest, path=path)
        self._atomic_private_write(path, payload)
        return ArtifactRef(digest=digest, path=path)

    def read_json(self, digest: str) -> dict[str, Any]:
        """Read and verify a stored artifact by canonical digest."""
        path = self._path_for_digest(digest)
        try:
            with path.open(encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise StoreError("artifact cannot be read") from exc
        if not isinstance(data, dict) or not verify_digest(data):
            raise StoreError("artifact digest verification failed")
        if data["digest"] != digest:
            raise StoreError("artifact digest mismatch")
        return data

    def _path_for_digest(self, digest: str) -> Path:
        if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
            raise StoreError("invalid artifact digest")
        path = self.root / digest[:2] / f"{digest}.json"
        resolved_root = self.root.resolve()
        resolved_parent = path.parent.resolve() if path.parent.exists() else path.parent
        if path.parent.exists() and not resolved_parent.is_relative_to(resolved_root):
            raise StoreError("artifact path escapes store root")
        return path

    def _atomic_private_write(self, path: Path, payload: str) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=path.parent)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            os.chmod(path, 0o600)
        except OSError as exc:
            raise StoreError("artifact write failed") from exc
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
