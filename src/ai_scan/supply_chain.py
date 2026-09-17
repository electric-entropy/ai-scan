"""Offline OWASP LLM03 supply-chain manifest assessment.

This module validates an explicitly supplied local manifest only. It never opens,
imports, deserializes, or executes listed model/plugin/dependency artifacts and it
never performs network access.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from typing import Any, Literal, cast
from urllib.parse import unquote, urlsplit

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError

MANIFEST_SCHEMA_VERSION = "ai-scan-supply-chain-manifest-v1"
RESULT_SCHEMA_VERSION = "ai-scan-supply-chain-audit-result-v1"
MAX_MANIFEST_BYTES = 64 * 1024

ItemKind = Literal["model", "dataset", "plugin", "dependency"]
AuditStatus = Literal["passed", "finding", "inconclusive", "not_applicable"]
FindingStatus = Literal["finding", "inconclusive"]

_TOP_LEVEL_KEYS = frozenset({"schema_version", "items"})
_ITEM_KEYS = frozenset(
    {
        "id",
        "kind",
        "name",
        "source_url",
        "revision",
        "sha256",
        "artifact_path",
        "uses_unsafe_serialization",
        "enables_remote_code",
    }
)
_KIND_VALUES = frozenset({"model", "dataset", "plugin", "dependency"})
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,8}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IMMUTABLE_GIT_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_PIN_RE = re.compile(r"^\d+(?:\.\d+){1,3}(?:[+.-][A-Za-z0-9][A-Za-z0-9._-]*)?$")
_HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_MUTABLE_REVISIONS = frozenset(
    {"main", "master", "latest", "head", "dev", "develop", "trunk", "nightly", "stable"}
)
_UNSAFE_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".ckpt")
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


class SupplyChainManifestError(ValueError):
    """Manifest file or document is malformed and cannot be assessed safely."""


@dataclass(frozen=True)
class ManifestItem:
    """One declared AI supply-chain artifact from the offline manifest."""

    id: str
    kind: ItemKind
    name: str
    source_url: str | None
    revision: str | None
    sha256: str | None
    artifact_path: str | None
    uses_unsafe_serialization: bool
    enables_remote_code: bool


@dataclass(frozen=True)
class SupplyChainAuditResult:
    """Structured result for the offline LLM03 manifest assessment."""

    manifest_sha256: str
    status: AuditStatus
    applicability: Literal["applicable", "not_applicable"]
    items: tuple[dict[str, object], ...]
    findings: tuple[dict[str, object], ...]
    limitations: tuple[str, ...]

    @property
    def summary(self) -> dict[str, int]:
        return {
            "items": len(self.items),
            "findings": sum(1 for finding in self.findings if finding["status"] == "finding"),
            "inconclusive": sum(
                1 for finding in self.findings if finding["status"] == "inconclusive"
            ),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "owasp_category": "LLM03",
            "scope": "partial_offline_manifest_assessment",
            "applicability": self.applicability,
            "status": self.status,
            "manifest_sha256": self.manifest_sha256,
            "network_requests": 0,
            "items": list(self.items),
            "findings": list(self.findings),
            "summary": self.summary,
            "limitations": list(self.limitations),
        }


_LIMITATIONS = (
    "Partial offline manifest assessment only; no live target, registry, or model behavior "
    "execution is performed.",
    "AI-Scan does not import, deserialize, load, hash, or execute the listed artifacts.",
    "Signatures, attestations, dataset contents, registry metadata, transitive dependency "
    "resolution, and runtime dependency loading remain out of scope.",
)

_REMEDIATION = {
    "llm03.missing_source": (
        "Declare a canonical HTTPS source URL or mark the item outside this manifest scope."
    ),
    "llm03.non_https_source": (
        "Use a canonical https:// source URL without credentials, redirects, or "
        "confusable characters."
    ),
    "llm03.missing_revision": (
        "Pin an immutable commit/release/version rather than relying on an implicit "
        "latest artifact."
    ),
    "llm03.missing_or_mutable_revision": (
        "Pin an immutable commit SHA or exact release/version and avoid mutable branch aliases."
    ),
    "llm03.missing_sha256": "Declare the expected lowercase SHA-256 digest for the artifact bytes.",
    "llm03.invalid_sha256": (
        "Use a lowercase 64-character SHA-256 digest and verify it outside AI-Scan's "
        "offline manifest audit."
    ),
    "llm03.unsafe_serialization": (
        "Prefer non-executable artifact formats such as safetensors and prohibit "
        "pickle/torch pickle loaders."
    ),
    "llm03.remote_code_enabled": (
        "Disable remote-code/trust-remote-code execution unless separately sandboxed "
        "and reviewed."
    ),
}


def load_manifest_file(path: str) -> str:
    """Open one bounded regular non-symlink manifest file and return its UTF-8 text."""
    if not hasattr(os, "O_NONBLOCK") or not hasattr(os, "O_NOFOLLOW"):
        raise SupplyChainManifestError("nonblocking safe open is unavailable")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_NOFOLLOW
        | os.O_NONBLOCK
    )
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SupplyChainManifestError("manifest must be a regular non-symlink file") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise SupplyChainManifestError("manifest must be a regular non-symlink file")
        if before.st_size > MAX_MANIFEST_BYTES:
            raise SupplyChainManifestError("manifest is too large")
        before_identity = _manifest_stat_identity(before)
        chunks = _read_bounded_manifest(fd)
        after = os.fstat(fd)
        after_identity = _manifest_stat_identity(after)
        if (
            before_identity != after_identity
            or len(chunks) != before.st_size
        ):
            raise SupplyChainManifestError("manifest changed during read")
        try:
            os.lseek(fd, 0, os.SEEK_SET)
        except OSError as exc:
            raise SupplyChainManifestError("manifest changed during read") from exc
        repeated = _read_bounded_manifest(fd)
        repeated_after = os.fstat(fd)
        if (
            _manifest_stat_identity(repeated_after) != before_identity
            or repeated != chunks
            or len(repeated) != before.st_size
        ):
            raise SupplyChainManifestError("manifest changed during read")
        try:
            return bytes(chunks).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SupplyChainManifestError("manifest must be UTF-8 JSON") from exc
    finally:
        os.close(fd)


def _manifest_stat_identity(
    info: os.stat_result,
) -> tuple[int, int, int, int, int | None, int | None]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        getattr(info, "st_mtime_ns", None),
        getattr(info, "st_ctime_ns", None),
    )


def _read_bounded_manifest(fd: int) -> bytes:
    chunks = bytearray()
    try:
        while True:
            chunk = os.read(fd, min(8192, MAX_MANIFEST_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > MAX_MANIFEST_BYTES:
                raise SupplyChainManifestError("manifest is too large")
    except OSError as exc:
        raise SupplyChainManifestError("manifest changed during read") from exc
    return bytes(chunks)


def audit_manifest_file(path: str) -> SupplyChainAuditResult:
    """Load and assess a local manifest file without touching listed artifacts."""
    return audit_manifest_text(load_manifest_file(path))


def audit_manifest_text(text: str) -> SupplyChainAuditResult:
    """Assess strict manifest JSON text and return a deterministic structured result."""
    if len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise SupplyChainManifestError("manifest is too large")
    try:
        raw = load_json_strict(text)
    except ConfigError as exc:
        raise SupplyChainManifestError(str(exc)) from exc
    if not isinstance(raw, dict):
        raise SupplyChainManifestError("manifest document must be an object")
    _reject_unknown("manifest", raw, _TOP_LEVEL_KEYS)
    if raw.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise SupplyChainManifestError("unsupported manifest schema_version")
    item_values = raw.get("items")
    if not isinstance(item_values, list):
        raise SupplyChainManifestError("items must be a list")
    manifest_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if not item_values:
        return SupplyChainAuditResult(
            manifest_sha256=manifest_sha256,
            status="not_applicable",
            applicability="not_applicable",
            items=(),
            findings=(),
            limitations=_LIMITATIONS,
        )
    items = tuple(_item_from_raw(_object(value, "item")) for value in item_values)
    _require_unique_item_ids(items)
    item_docs: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for item in items:
        item_ref = _item_ref(item)
        item_docs.append(
            {
                "item_ref": item_ref,
                "manifest_sha256": manifest_sha256,
                "applicability": "applicable",
            }
        )
        findings.extend(_findings_for_item(item, manifest_sha256))
    status = _status_for(findings)
    return SupplyChainAuditResult(
        manifest_sha256=manifest_sha256,
        status=status,
        applicability="applicable",
        items=tuple(item_docs),
        findings=tuple(findings),
        limitations=_LIMITATIONS,
    )


def render_human(result: SupplyChainAuditResult) -> str:
    """Render a concise deterministic human result."""
    summary = result.summary
    lines = [
        "LLM03 Supply Chain offline manifest assessment",
        "scope: partial_offline_manifest_assessment",
        f"applicability: {result.applicability}",
        f"status: {result.status}",
        f"manifest_sha256: {result.manifest_sha256}",
        f"items: {summary['items']}",
        f"findings: {summary['findings']}",
        f"inconclusive: {summary['inconclusive']}",
        "network_requests: 0",
    ]
    for finding in result.findings:
        lines.append(
            f"- {finding['status']} {finding['rule_id']} item={finding['item_ref']} "
            f"path={finding['field_path']} reason={finding['reason_code']} "
            f"remediation={finding['remediation']}"
        )
    lines.append("limitations:")
    lines.extend(f"- {item}" for item in result.limitations)
    return "\n".join(lines)


def render_json(result: SupplyChainAuditResult) -> str:
    """Render stable JSON output."""
    return json.dumps(result.to_dict(), indent=2, sort_keys=True, allow_nan=False)


def _item_from_raw(raw: dict[str, Any]) -> ManifestItem:
    _reject_unknown("item", raw, _ITEM_KEYS)
    item_id = _required_string(raw, "id")
    if not _ID_RE.fullmatch(item_id):
        raise SupplyChainManifestError("item.id must be lowercase ASCII with separators")
    kind = _required_string(raw, "kind")
    if kind not in _KIND_VALUES:
        raise SupplyChainManifestError("item.kind is not supported")
    name = _required_string(raw, "name")
    source_url = _optional_string(raw, "source_url")
    revision = _optional_string(raw, "revision")
    sha256 = _optional_string(raw, "sha256")
    artifact_path = _optional_string(raw, "artifact_path")
    for label, value in (
        ("item.id", item_id),
        ("item.name", name),
        ("item.source_url", source_url),
        ("item.revision", revision),
        ("item.sha256", sha256),
        ("item.artifact_path", artifact_path),
    ):
        if value is not None:
            _validate_safe_text(label, value)
    if source_url is not None:
        _validate_source_url(source_url)
    if artifact_path is not None:
        _validate_artifact_path(artifact_path)
    return ManifestItem(
        id=item_id,
        kind=cast(ItemKind, kind),
        name=name,
        source_url=source_url,
        revision=revision,
        sha256=sha256,
        artifact_path=artifact_path,
        uses_unsafe_serialization=_required_bool(raw, "uses_unsafe_serialization"),
        enables_remote_code=_required_bool(raw, "enables_remote_code"),
    )


def _findings_for_item(item: ManifestItem, manifest_sha256: str) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    if item.source_url is None:
        findings.append(
            _finding(
                "llm03.missing_source",
                "inconclusive",
                item,
                manifest_sha256,
                "items[].source_url",
                "missing_source",
            )
        )
    elif not item.source_url.startswith("https://"):
        findings.append(
            _finding(
                "llm03.non_https_source",
                "finding",
                item,
                manifest_sha256,
                "items[].source_url",
                "non_https_source",
            )
        )
    if item.revision is None:
        findings.append(
            _finding(
                "llm03.missing_revision",
                "inconclusive",
                item,
                manifest_sha256,
                "items[].revision",
                "missing_revision",
            )
        )
    elif not _is_immutable_revision(item.revision):
        findings.append(
            _finding(
                "llm03.missing_or_mutable_revision",
                "finding",
                item,
                manifest_sha256,
                "items[].revision",
                "mutable_revision",
            )
        )
    if item.sha256 is None:
        findings.append(
            _finding(
                "llm03.missing_sha256",
                "inconclusive",
                item,
                manifest_sha256,
                "items[].sha256",
                "missing_sha256",
            )
        )
    elif not _SHA256_RE.fullmatch(item.sha256):
        findings.append(
            _finding(
                "llm03.invalid_sha256",
                "finding",
                item,
                manifest_sha256,
                "items[].sha256",
                "invalid_sha256",
            )
        )
    if item.uses_unsafe_serialization:
        findings.append(
            _finding(
                "llm03.unsafe_serialization",
                "finding",
                item,
                manifest_sha256,
                "items[].uses_unsafe_serialization",
                "unsafe_serialization_flag",
            )
        )
    if _unsafe_extension(item.artifact_path):
        findings.append(
            _finding(
                "llm03.unsafe_serialization",
                "finding",
                item,
                manifest_sha256,
                "items[].artifact_path",
                "unsafe_serialization_extension",
            )
        )
    if item.enables_remote_code:
        findings.append(
            _finding(
                "llm03.remote_code_enabled",
                "finding",
                item,
                manifest_sha256,
                "items[].enables_remote_code",
                "remote_code_enabled",
            )
        )
    return findings


def _finding(
    rule_id: str,
    status: FindingStatus,
    item: ManifestItem,
    manifest_sha256: str,
    field_path: str,
    reason_code: str,
) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "status": status,
        "owasp_category": "LLM03",
        "applicability": "applicable",
        "manifest_sha256": manifest_sha256,
        "item_ref": _item_ref(item),
        "field_path": field_path,
        "reason_code": reason_code,
        "remediation": _REMEDIATION[rule_id],
    }


def _item_ref(item: ManifestItem) -> str:
    digest = hashlib.sha256(
        ("ai-scan-llm03-manifest-item-ref-v1\0" + item.id).encode("utf-8")
    ).hexdigest()
    return f"llm03-item-{digest[:32]}"


def _status_for(findings: list[dict[str, object]]) -> AuditStatus:
    if any(finding["status"] == "finding" for finding in findings):
        return "finding"
    if any(finding["status"] == "inconclusive" for finding in findings):
        return "inconclusive"
    return "passed"


def _is_immutable_revision(value: str) -> bool:
    lowered = value.lower()
    if lowered in _MUTABLE_REVISIONS:
        return False
    return bool(_IMMUTABLE_GIT_RE.fullmatch(value) or _VERSION_PIN_RE.fullmatch(value))


def _unsafe_extension(path: str | None) -> bool:
    if path is None:
        return False
    return path.lower().endswith(_UNSAFE_EXTENSIONS)


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SupplyChainManifestError(f"{name} must be an object")
    return value


def _reject_unknown(path: str, raw: dict[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise SupplyChainManifestError(f"{path}: unknown field is not allowed")


def _required_string(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SupplyChainManifestError(f"{key} must be a non-empty string")
    return value


def _optional_string(raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SupplyChainManifestError(f"{key} must be a non-empty string when present")
    return value


def _required_bool(raw: dict[str, Any], key: str) -> bool:
    value = raw.get(key)
    if value is not True and value is not False:
        raise SupplyChainManifestError(f"{key} must be a boolean")
    return value


def _require_unique_item_ids(items: tuple[ManifestItem, ...]) -> None:
    ids = [item.id for item in items]
    if len(ids) != len(set(ids)):
        raise SupplyChainManifestError("item ids must be unique")


def _validate_safe_text(label: str, value: str) -> None:
    if value != unicodedata.normalize("NFC", value):
        raise SupplyChainManifestError(f"{label} must use normalized Unicode")
    for ch in value:
        if ch.isspace() and ch not in {" "}:
            raise SupplyChainManifestError(f"{label} contains unsafe whitespace")
        if unicodedata.category(ch) in _FORBIDDEN_CATEGORIES:
            raise SupplyChainManifestError(f"{label} contains control/format/private Unicode")
        if ord(ch) > 127 and label in {"item.id", "item.source_url", "item.artifact_path"}:
            raise SupplyChainManifestError(f"{label} must be ASCII")


def _validate_source_url(value: str) -> None:
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError as exc:
        raise SupplyChainManifestError("source_url is not canonical") from exc
    if not parts.scheme or not parts.netloc:
        raise SupplyChainManifestError("source_url must be an absolute URL")
    if parts.username or parts.password:
        raise SupplyChainManifestError("source_url must not contain credentials")
    if parts.query:
        raise SupplyChainManifestError("source_url must not contain a query")
    if parts.fragment:
        raise SupplyChainManifestError("source_url must not contain a fragment")
    host = parts.hostname
    if not host or host != host.lower() or host.startswith(".") or host.endswith("."):
        raise SupplyChainManifestError("source_url host is not canonical")
    if any(part in {"", ".", ".."} for part in host.split(".")):
        raise SupplyChainManifestError("source_url host is not canonical")
    if host.startswith("xn--") or ".xn--" in host or any(ord(ch) > 127 for ch in host):
        raise SupplyChainManifestError("source_url host is not canonical")
    if not _HOST_RE.fullmatch(host):
        raise SupplyChainManifestError("source_url host is not canonical")
    raw_host = parts.netloc.rsplit(":", 1)[0] if port is not None else parts.netloc
    if raw_host != host:
        raise SupplyChainManifestError("source_url host is not canonical")
    if "%" in parts.netloc or "%" in parts.path:
        raise SupplyChainManifestError("source_url must not contain encoded authority or path")
    if port is not None and port != (443 if parts.scheme == "https" else 80):
        raise SupplyChainManifestError("source_url port is not canonical")
    _reject_changing_percent_decode("source_url", value)


def _validate_artifact_path(value: str) -> None:
    if value.startswith(("/", "\\")) or ":" in value:
        raise SupplyChainManifestError("artifact_path must be a relative path")
    _reject_changing_percent_decode("artifact_path", value)
    normalized = value.replace("\\", "/")
    if any(part in {"", ".", ".."} for part in normalized.split("/")):
        raise SupplyChainManifestError("artifact_path must not contain traversal or empty segments")


def _reject_changing_percent_decode(label: str, value: str) -> None:
    current = value
    for _ in range(5):
        decoded = unquote(current)
        if decoded == current:
            _validate_safe_text(label, decoded)
            if ".." in decoded.replace("\\", "/").split("/"):
                raise SupplyChainManifestError(f"{label} must not contain traversal")
            return
        current = decoded
    raise SupplyChainManifestError(f"{label} percent-encoding is too deeply nested")


__all__ = [
    "SupplyChainAuditResult",
    "SupplyChainManifestError",
    "audit_manifest_file",
    "audit_manifest_text",
    "load_manifest_file",
    "render_human",
    "render_json",
]
