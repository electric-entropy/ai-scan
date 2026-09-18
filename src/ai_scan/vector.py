"""Inert LLM08 vector/embedding declaration assessment."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, NoReturn

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.core.safe_file import read_stable_regular_file

MANIFEST_SCHEMA_VERSION = "ai-scan-vector-manifest-v1"
MAX_MANIFEST_BYTES = 65536
MAX_SOURCE_REFS = 32
_REF = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}", re.ASCII)
_REF_FIELDS = frozenset(
    {
        "tenant_ref",
        "context_ref",
        "collection_ref",
        "query_context_ref",
        "model_ref",
        "version_ref",
        "index_version_ref",
        "rollback_ref",
    }
)
_REMOVED_CLASSES = ("credentials", "pii", "secrets")
_TOP_KEYS = frozenset(
    {
        "schema_version",
        "scope",
        "ingestion",
        "embedding",
        "retrieval",
        "privacy",
        "lifecycle",
        "poisoning",
        "operations",
    }
)
_SECTIONS = tuple(k for k in _TOP_KEYS if k != "schema_version")
_LIMITATIONS = (
    "Partial offline declaration assessment only; no full LLM08 coverage or compliance claim.",
    "No vector store, embedding model, index, retrieval path, tenant isolation, "
    "or runtime behavior was verified.",
    "Declared documents, embeddings, indexes, model files, plugins, URLs, commands, "
    "archives, and code are never opened, imported, connected to, or executed.",
    "Declaration checks passed does not prove runtime isolation or absence of vector "
    "and embedding weaknesses.",
)
_RULE_META = {
    "scope_partitioning": ("high", "scope", "llm08_scope_partitioning_unsafe"),
    "ingestion_provenance": ("high", "ingestion", "llm08_ingestion_provenance_unsafe"),
    "embedding_lineage": ("high", "embedding", "llm08_embedding_lineage_unsafe"),
    "retrieval_controls": ("medium", "retrieval", "llm08_retrieval_controls_unsafe"),
    "data_minimization": ("high", "privacy", "llm08_data_minimization_unsafe"),
    "lifecycle": ("medium", "lifecycle", "llm08_lifecycle_unsafe"),
    "poisoning_resistance": ("high", "poisoning", "llm08_poisoning_resistance_unsafe"),
    "isolation_operations": ("medium", "operations", "llm08_isolation_operations_unsafe"),
}


class VectorManifestError(ValueError):
    """Fixed nonsecret error at the public vector declaration boundary."""


def _raise_error(code: str) -> NoReturn:
    raise VectorManifestError(code)


@dataclass(frozen=True)
class VectorFinding:
    context_ref: str
    rule: str
    finding_ref: str

    def to_dict(self) -> dict[str, str]:
        severity, field_path, reason = _RULE_META[self.rule]
        return {
            "context_ref": self.context_ref,
            "finding_ref": self.finding_ref,
            "rule_id": "llm08." + self.rule,
            "severity": severity,
            "field_path": field_path,
            "reason_code": reason,
            "remediation_code": "llm08.remediate." + self.rule,
        }


@dataclass(frozen=True)
class VectorAuditResult:
    """Only opaque identities and fixed rule identifiers survive assessment."""

    manifest_sha256: str
    context_ref: str
    findings: tuple[VectorFinding, ...]

    @property
    def status(self) -> str:
        return "finding" if self.findings else "passed"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "ai-scan-vector-audit-result-v1",
            "owasp_category": "LLM08",
            "scope": "partial_offline_declaration_assessment",
            "manifest_sha256": self.manifest_sha256,
            "status": self.status,
            "message": "declaration findings" if self.findings else "declaration checks passed",
            "context_ref": self.context_ref,
            "findings": [finding.to_dict() for finding in self.findings],
            "network_requests": 0,
            "executions": 0,
            "limitations": list(_LIMITATIONS),
        }


def _audit(text: str) -> VectorAuditResult:
    if type(text) is not str or len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ValueError
    raw = load_json_strict(text)
    # Strict parsing rejects duplicate keys/non-finite values first. Reparse the
    # bounded text losslessly so fractional literals cannot round into integers.
    raw = json.loads(text, parse_float=Decimal)
    _validate(raw)
    scope = raw["scope"]
    identity = ("v1", scope["tenant_ref"], scope["context_ref"], scope["collection_ref"])
    context_ref = _opaque_ref("context", identity)
    findings = tuple(
        VectorFinding(context_ref, rule, _opaque_ref("finding", (*identity, "llm08." + rule)))
        for rule in _rules(raw)
    )
    return VectorAuditResult(
        hashlib.sha256(text.encode("utf-8")).hexdigest(), context_ref, findings
    )


def _opaque_ref(domain: str, identity: tuple[str, ...]) -> str:
    canonical = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return (
        "llm08-" + domain + "-"
        + hashlib.sha256(
            ("ai-scan-llm08-" + domain + "-ref-v1\0" + canonical).encode("ascii")
        ).hexdigest()
    )


def _rules(raw: dict[str, Any]) -> tuple[str, ...]:
    rules: list[str] = []
    scope = raw["scope"]
    if (
        scope["server_bound"] is not True
        or scope["cross_context_fallback"]
        or scope["global_search"]
    ):
        rules.append("scope_partitioning")
    ingestion = raw["ingestion"]
    if (
        ingestion["lineage"] == "none"
        or ingestion["quarantine"] is not True
        or ingestion["duplicate_policy"] == "unchecked"
        or ingestion["atomic_promotion"] is not True
    ):
        rules.append("ingestion_provenance")
    embedding = raw["embedding"]
    if (
        embedding["pinned"] is not True
        or embedding["migration"] == "in_place"
        or embedding["reject_incompatible"] is not True
        or embedding["rollback_metadata"] is not True
    ):
        rules.append("embedding_lineage")
    retrieval = raw["retrieval"]
    if (
        retrieval["top_k"] > 20
        or retrieval["candidates"] > 200
        or retrieval["threshold_policy"] != "minimum"
        or retrieval["minimum_score"] < 50
        or retrieval["metadata_filters"] != "exact"
        or retrieval["empty_filter"] != "reject"
        or retrieval["query_bytes"] > 8192
        or retrieval["result_bytes"] > 65536
    ):
        rules.append("retrieval_controls")
    privacy = raw["privacy"]
    if (
        frozenset(privacy["removed_classes"]) != frozenset(_REMOVED_CLASSES)
        or (privacy["retention"] == "bounded" and privacy["retention_hours"] > 24)
        or privacy["vector_export"]
        or privacy["debug_dumps"]
        or privacy["log_bodies"]
    ):
        rules.append("data_minimization")
    lifecycle = raw["lifecycle"]
    if (
        lifecycle["index_hours"] > 24
        or lifecycle["cache_hours"] > 24
        or lifecycle["replica_hours"] > 24
        or lifecycle["backup_hours"] > 168
        or lifecycle["tombstones"] is not True
        or lifecycle["orphan_detection"] is not True
        or lifecycle["rebuild"] != "accepted_lineage"
        or lifecycle["restore_namespace"] is not True
    ):
        rules.append("lifecycle")
    poisoning = raw["poisoning"]
    if (
        poisoning["trust_tiers"] != "enforced"
        or poisoning["anomaly"] is not True
        or poisoning["near_duplicate"] is not True
        or poisoning["contributions_per_source"] > 1000
        or poisoning["rate_per_minute"] > 60
        or poisoning["chunk_provenance"] is not True
        or poisoning["recovery"] != "accepted_lineage"
    ):
        rules.append("poisoning_resistance")
    operations = raw["operations"]
    if (
        operations["storage_partition"] is not True
        or operations["cache_partition"] is not True
        or operations["cache_scope"] is not True
        or operations["cache_model"] is not True
        or operations["cache_index"] is not True
        or operations["concurrency"] > 8
        or operations["storage_mb"] > 10240
        or operations["timeout_seconds"] > 30
        or operations["audit_events"] != "opaque"
        or operations["failure_scope"] != "closed"
    ):
        rules.append("isolation_operations")
    return tuple(rules)


def _exact(value: Any, keys: frozenset[str]) -> None:
    if type(value) is not dict or frozenset(value) != keys:
        raise ValueError


def _bool(value: Any) -> None:
    if type(value) is not bool:
        raise ValueError


def _integer(value: Any, maximum: int, minimum: int = 1) -> int:
    # Draft 2020-12 integers include finite integral JSON numbers (8.0, 8e0).
    if type(value) is Decimal:
        if not value.is_finite() or not minimum <= value <= maximum:
            raise ValueError
        if value != value.to_integral_value():
            raise ValueError
        value = int(value)
    if type(value) is float and math.isfinite(value) and value.is_integer():
        value = int(value)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError
    return int(value)


def _enum(value: Any, values: tuple[str, ...]) -> None:
    if type(value) is not str or value not in values:
        raise ValueError


def _ref(value: Any) -> None:
    if type(value) is not str or len(value) > 64 or not _REF.fullmatch(value):
        raise ValueError


def _validate(raw: Any) -> None:
    _exact(raw, _TOP_KEYS)
    if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError
    _validate_scope(raw["scope"])
    _validate_ingestion(raw["ingestion"])
    _validate_embedding(raw["embedding"])
    _validate_retrieval(raw["retrieval"])
    _validate_privacy(raw["privacy"])
    _validate_lifecycle(raw["lifecycle"])
    _validate_poisoning(raw["poisoning"])
    _validate_operations(raw["operations"])


def _validate_scope(scope: Any) -> None:
    _exact(
        scope,
        frozenset(
            {
                "tenant_ref",
                "context_ref",
                "collection_ref",
                "query_context_ref",
                "server_bound",
                "cross_context_fallback",
                "global_search",
            }
        ),
    )
    for key in ("tenant_ref", "context_ref", "collection_ref", "query_context_ref"):
        _ref(scope[key])
    for key in ("server_bound", "cross_context_fallback", "global_search"):
        _bool(scope[key])
    if (
        len({scope["tenant_ref"], scope["context_ref"], scope["collection_ref"]}) != 3
        or scope["query_context_ref"] != scope["context_ref"]
    ):
        raise ValueError


def _validate_ingestion(ingestion: Any) -> None:
    _exact(
        ingestion,
        frozenset({"source_refs", "lineage", "quarantine", "duplicate_policy", "atomic_promotion"}),
    )
    refs = ingestion["source_refs"]
    if type(refs) is not list or not 1 <= len(refs) <= MAX_SOURCE_REFS:
        raise ValueError
    seen: set[str] = set()
    for item in refs:
        _ref(item)
        if item in seen:
            raise ValueError
        seen.add(item)
    _enum(ingestion["lineage"], ("digest", "signature", "immutable", "none"))
    _enum(ingestion["duplicate_policy"], ("reject", "digest_upsert", "unchecked"))
    for key in ("quarantine", "atomic_promotion"):
        _bool(ingestion[key])


def _validate_embedding(embedding: Any) -> None:
    _exact(
        embedding,
        frozenset(
            {
                "model_ref",
                "version_ref",
                "index_version_ref",
                "rollback_ref",
                "pinned",
                "dimensions",
                "index_dimensions",
                "normalization",
                "distance",
                "migration",
                "reject_incompatible",
                "rollback_metadata",
            }
        ),
    )
    for key in ("model_ref", "version_ref", "index_version_ref", "rollback_ref"):
        _ref(embedding[key])
    for key in ("pinned", "reject_incompatible", "rollback_metadata"):
        _bool(embedding[key])
    embedding["dimensions"] = _integer(embedding["dimensions"], 65536)
    embedding["index_dimensions"] = _integer(embedding["index_dimensions"], 65536)
    if embedding["dimensions"] != embedding["index_dimensions"]:
        raise ValueError
    _enum(embedding["normalization"], ("unit", "none"))
    _enum(embedding["distance"], ("cosine", "dot", "euclidean"))
    _enum(embedding["migration"], ("reindex", "blocked", "in_place"))
    if embedding["distance"] == "dot" and embedding["normalization"] != "unit":
        raise ValueError


def _validate_retrieval(retrieval: Any) -> None:
    _exact(
        retrieval,
        frozenset(
            {
                "top_k",
                "candidates",
                "threshold_policy",
                "minimum_score",
                "metadata_filters",
                "empty_filter",
                "query_bytes",
                "result_bytes",
            }
        ),
    )
    retrieval["top_k"] = _integer(retrieval["top_k"], 10000)
    retrieval["candidates"] = _integer(retrieval["candidates"], 100000)
    _enum(retrieval["threshold_policy"], ("minimum", "disabled"))
    retrieval["minimum_score"] = _integer(retrieval["minimum_score"], 100, 0)
    _enum(retrieval["metadata_filters"], ("exact", "none"))
    _enum(retrieval["empty_filter"], ("reject", "global"))
    retrieval["query_bytes"] = _integer(retrieval["query_bytes"], 10000000)
    retrieval["result_bytes"] = _integer(retrieval["result_bytes"], 10000000)
    if (
        retrieval["candidates"] < retrieval["top_k"]
        or retrieval["result_bytes"] < retrieval["query_bytes"]
    ):
        raise ValueError
    if (retrieval["threshold_policy"] == "disabled") != (retrieval["minimum_score"] == 0):
        raise ValueError


def _validate_privacy(privacy: Any) -> None:
    _exact(
        privacy,
        frozenset(
            {
                "removed_classes",
                "retention",
                "retention_hours",
                "vector_export",
                "debug_dumps",
                "log_bodies",
            }
        ),
    )
    classes = privacy["removed_classes"]
    if type(classes) is not list or len(classes) > len(_REMOVED_CLASSES):
        raise ValueError
    seen: set[str] = set()
    for item in classes:
        _enum(item, _REMOVED_CLASSES)
        if item in seen:
            raise ValueError
        seen.add(item)
    _enum(privacy["retention"], ("disabled", "bounded"))
    privacy["retention_hours"] = _integer(privacy["retention_hours"], 8760, 0)
    if (privacy["retention"] == "disabled") != (privacy["retention_hours"] == 0):
        raise ValueError
    for key in ("vector_export", "debug_dumps", "log_bodies"):
        _bool(privacy[key])


def _validate_lifecycle(lifecycle: Any) -> None:
    _exact(
        lifecycle,
        frozenset(
            {
                "index_hours",
                "cache_hours",
                "replica_hours",
                "backup_hours",
                "tombstones",
                "orphan_detection",
                "rebuild",
                "restore_namespace",
            }
        ),
    )
    for key in ("index_hours", "cache_hours", "replica_hours", "backup_hours"):
        lifecycle[key] = _integer(lifecycle[key], 8760)
    for key in ("tombstones", "orphan_detection", "restore_namespace"):
        _bool(lifecycle[key])
    _enum(lifecycle["rebuild"], ("accepted_lineage", "all_sources"))
    if lifecycle["backup_hours"] < lifecycle["index_hours"]:
        raise ValueError


def _validate_poisoning(poisoning: Any) -> None:
    _exact(
        poisoning,
        frozenset(
            {
                "trust_tiers",
                "anomaly",
                "near_duplicate",
                "contributions_per_source",
                "rate_per_minute",
                "chunk_provenance",
                "recovery",
            }
        ),
    )
    _enum(poisoning["trust_tiers"], ("enforced", "uniform"))
    for key in ("anomaly", "near_duplicate", "chunk_provenance"):
        _bool(poisoning[key])
    poisoning["contributions_per_source"] = _integer(poisoning["contributions_per_source"], 100000)
    poisoning["rate_per_minute"] = _integer(poisoning["rate_per_minute"], 100000)
    _enum(poisoning["recovery"], ("accepted_lineage", "unrestricted"))
    if poisoning["rate_per_minute"] > poisoning["contributions_per_source"]:
        raise ValueError


def _validate_operations(operations: Any) -> None:
    _exact(
        operations,
        frozenset(
            {
                "storage_partition",
                "cache_partition",
                "cache_scope",
                "cache_model",
                "cache_index",
                "concurrency",
                "storage_mb",
                "timeout_seconds",
                "audit_events",
                "failure_scope",
            }
        ),
    )
    for key in (
        "storage_partition",
        "cache_partition",
        "cache_scope",
        "cache_model",
        "cache_index",
    ):
        _bool(operations[key])
    operations["concurrency"] = _integer(operations["concurrency"], 1024)
    operations["storage_mb"] = _integer(operations["storage_mb"], 1000000)
    operations["timeout_seconds"] = _integer(operations["timeout_seconds"], 86400)
    _enum(operations["audit_events"], ("opaque", "disabled", "bodies"))
    _enum(operations["failure_scope"], ("closed", "global"))


def _public(value: str, operation: str) -> Any:
    result: Any = None
    text: str | None = None
    failed = False
    try:
        if operation == "schema":
            if type(value) is not str or len(value.encode("utf-8")) > MAX_MANIFEST_BYTES:
                raise ValueError
            raw = load_json_strict(value)
            expected = _schema_document()
            if json.dumps(raw, sort_keys=True) != json.dumps(expected, sort_keys=True):
                raise ValueError
            result = expected
        elif operation == "text":
            result = _audit(value)
        else:
            text = read_stable_regular_file(value, max_bytes=MAX_MANIFEST_BYTES).decode("utf-8")
            result = text if operation == "load" else _audit(text)
    except (
        ConfigError, ValueError, TypeError, OSError, RecursionError,
        UnicodeDecodeError, InvalidOperation,
    ):
        failed = True
    if failed:
        raw = expected = {}
        del value, result, text, raw, expected
        _raise_error("llm08_manifest_invalid")
    return result


def audit_manifest_text(text: str) -> VectorAuditResult:
    try:
        result: VectorAuditResult = _public(text, "text")
    finally:
        del text
    return result


def audit_manifest_file(path: str) -> VectorAuditResult:
    try:
        result: VectorAuditResult = _public(path, "audit")
    finally:
        del path
    return result


def load_manifest_file(path: str) -> str:
    try:
        result: str = _public(path, "load")
    finally:
        del path
    return result


def load_schema_text(text: str) -> dict[str, object]:
    try:
        result: dict[str, object] = _public(text, "schema")
    finally:
        del text
    return result


def _schema_document() -> dict[str, object]:
    ref = {
        "type": "string", "minLength": 3, "maxLength": 64,
        "pattern": "^" + _REF.pattern + r"(?![\s\S])",
    }

    def closed(properties: dict[str, object]) -> dict[str, object]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(properties),
            "properties": properties,
        }

    schema = closed(
        {
            "schema_version": {"const": MANIFEST_SCHEMA_VERSION},
            "scope": closed(
                {
                    "tenant_ref": ref,
                    "context_ref": ref,
                    "collection_ref": ref,
                    "query_context_ref": ref,
                    "server_bound": {"type": "boolean"},
                    "cross_context_fallback": {"type": "boolean"},
                    "global_search": {"type": "boolean"},
                }
            ),
            "ingestion": closed(
                {
                    "source_refs": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_SOURCE_REFS,
                        "uniqueItems": True,
                        "items": ref,
                    },
                    "lineage": {
                        "type": "string",
                        "enum": ["digest", "signature", "immutable", "none"],
                    },
                    "quarantine": {"type": "boolean"},
                    "duplicate_policy": {
                        "type": "string",
                        "enum": ["reject", "digest_upsert", "unchecked"],
                    },
                    "atomic_promotion": {"type": "boolean"},
                }
            ),
            "embedding": closed(
                {
                    "model_ref": ref,
                    "version_ref": ref,
                    "index_version_ref": ref,
                    "rollback_ref": ref,
                    "pinned": {"type": "boolean"},
                    "dimensions": {"type": "integer", "minimum": 1, "maximum": 65536},
                    "index_dimensions": {"type": "integer", "minimum": 1, "maximum": 65536},
                    "normalization": {"type": "string", "enum": ["unit", "none"]},
                    "distance": {"type": "string", "enum": ["cosine", "dot", "euclidean"]},
                    "migration": {"type": "string", "enum": ["reindex", "blocked", "in_place"]},
                    "reject_incompatible": {"type": "boolean"},
                    "rollback_metadata": {"type": "boolean"},
                }
            ),
            "retrieval": closed(
                {
                    "top_k": {"type": "integer", "minimum": 1, "maximum": 10000},
                    "candidates": {"type": "integer", "minimum": 1, "maximum": 100000},
                    "threshold_policy": {"type": "string", "enum": ["minimum", "disabled"]},
                    "minimum_score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "metadata_filters": {"type": "string", "enum": ["exact", "none"]},
                    "empty_filter": {"type": "string", "enum": ["reject", "global"]},
                    "query_bytes": {"type": "integer", "minimum": 1, "maximum": 10000000},
                    "result_bytes": {"type": "integer", "minimum": 1, "maximum": 10000000},
                }
            ),
            "privacy": closed(
                {
                    "removed_classes": {
                        "type": "array",
                        "maxItems": 3,
                        "uniqueItems": True,
                        "items": {"type": "string", "enum": list(_REMOVED_CLASSES)},
                    },
                    "retention": {"type": "string", "enum": ["disabled", "bounded"]},
                    "retention_hours": {"type": "integer", "minimum": 0, "maximum": 8760},
                    "vector_export": {"type": "boolean"},
                    "debug_dumps": {"type": "boolean"},
                    "log_bodies": {"type": "boolean"},
                }
            ),
            "lifecycle": closed(
                {
                    "index_hours": {"type": "integer", "minimum": 1, "maximum": 8760},
                    "cache_hours": {"type": "integer", "minimum": 1, "maximum": 8760},
                    "replica_hours": {"type": "integer", "minimum": 1, "maximum": 8760},
                    "backup_hours": {"type": "integer", "minimum": 1, "maximum": 8760},
                    "tombstones": {"type": "boolean"},
                    "orphan_detection": {"type": "boolean"},
                    "rebuild": {"type": "string", "enum": ["accepted_lineage", "all_sources"]},
                    "restore_namespace": {"type": "boolean"},
                }
            ),
            "poisoning": closed(
                {
                    "trust_tiers": {"type": "string", "enum": ["enforced", "uniform"]},
                    "anomaly": {"type": "boolean"},
                    "near_duplicate": {"type": "boolean"},
                    "contributions_per_source": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100000,
                    },
                    "rate_per_minute": {"type": "integer", "minimum": 1, "maximum": 100000},
                    "chunk_provenance": {"type": "boolean"},
                    "recovery": {"type": "string", "enum": ["accepted_lineage", "unrestricted"]},
                }
            ),
            "operations": closed(
                {
                    "storage_partition": {"type": "boolean"},
                    "cache_partition": {"type": "boolean"},
                    "cache_scope": {"type": "boolean"},
                    "cache_model": {"type": "boolean"},
                    "cache_index": {"type": "boolean"},
                    "concurrency": {"type": "integer", "minimum": 1, "maximum": 1024},
                    "storage_mb": {"type": "integer", "minimum": 1, "maximum": 1000000},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 86400},
                    "audit_events": {"type": "string", "enum": ["opaque", "disabled", "bodies"]},
                    "failure_scope": {"type": "string", "enum": ["closed", "global"]},
                }
            ),
        }
    )
    schema["allOf"] = [
        {
            "if": {"properties": {"embedding": {"properties": {"distance": {"const": "dot"}}}}},
            "then": {
                "properties": {"embedding": {"properties": {"normalization": {"const": "unit"}}}}
            },
        },
        *[
            {
                "if": {"properties": {section: {"properties": {policy: {"const": "disabled"}}}}},
                "then": {"properties": {section: {"properties": {number: {"const": 0}}}}},
                "else": {"properties": {section: {"properties": {number: {"minimum": 1}}}}},
            }
            for section, policy, number in (
                ("retrieval", "threshold_policy", "minimum_score"),
                ("privacy", "retention", "retention_hours"),
            )
        ],
    ]
    schema.update(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://electricentropy.com/schemas/ai-scan-vector-v1",
            "$comment": (
                "Draft 2020-12 structural preflight; finite integral JSON numbers are integers. "
                "Runtime validation additionally enforces distinct tenant/context/collection refs, "
                "query_context_ref == context_ref, dimensions == index_dimensions, "
                "candidates >= top_k, result_bytes >= query_bytes, backup_hours >= index_hours, "
                "and rate_per_minute <= contributions_per_source. Strict JSON parsing and "
                "bounded stable-file input checks are mandatory outside this schema."
            ),
        }
    )
    return schema


def render_json(result: VectorAuditResult) -> str:
    return json.dumps(result.to_dict(), sort_keys=True, indent=2, allow_nan=False)


def render_text(result: VectorAuditResult) -> str:
    doc = result.to_dict()
    return "\n".join(
        [
            "LLM08 Vector and Embedding Weaknesses offline declaration assessment",
            str(doc["message"]),
            "status: " + result.status,
            "manifest_sha256: " + result.manifest_sha256,
            *(json.dumps(f.to_dict(), sort_keys=True) for f in result.findings),
            *_LIMITATIONS,
        ]
    )
