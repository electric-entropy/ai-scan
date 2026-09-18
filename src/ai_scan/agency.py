"""Inert LLM06 declaration assessment; never resolves declared tool references."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, NoReturn

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.core.safe_file import read_stable_regular_file

MANIFEST_SCHEMA_VERSION = "ai-scan-agency-manifest-v1"
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TOOLS = 2000
_REF = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}", re.ASCII)
_REF_FIELDS = ("id", "resource_ref", "destination_ref", "object_ref")
_BOOL_FIELDS = (
    "side_effecting",
    "least_functionality",
    "precondition",
    "read_back",
    "cleanup_verified",
    "error_isolation",
    "operation_commitment",
    "request_commitment",
    "result_commitment",
)
_ENUMS = {
    "operation": ("read", "update", "delete", "send"),
    "resource_scope": ("fixed", "dynamic"),
    "parameter_shape": ("closed_typed", "open"),
    "destination_boundary": ("fixed", "dynamic"),
    "object_boundary": ("fixed", "dynamic"),
    "execution_identity": ("dedicated_least_privilege", "shared", "privileged"),
    "isolation": ("none", "process", "container"),
    "idempotency": ("none", "stable_operation_key", "per_attempt_key"),
    "cleanup": ("none", "best_effort", "deterministic_compensation"),
    "unresolved_state": ("not_applicable", "continue", "halt_and_reconcile"),
    "response_schema": ("closed_typed", "open"),
    "result_trust": ("untrusted", "trusted"),
    "output_to_action": ("separated", "direct"),
    "event_identity": ("opaque_sequence", "raw_content", "none"),
}
_LIMIT_MAX = {
    "steps": 10000,
    "side_effects": 10000,
    "concurrency": 256,
    "duration_seconds": 86400,
    "recursion_depth": 32,
    "delegation_depth": 32,
    "retries": 16,
    "output_bytes": 10000000,
}
_TOOL_KEYS = frozenset((*_REF_FIELDS, *_BOOL_FIELDS, *_ENUMS, "max_calls"))
LIMITATIONS = (
    "Partial offline declaration assessment only; no full LLM06 coverage or compliance claim.",
    "No tool execution, permission enforcement, deployed identity, isolation, cleanup, "
    "runtime behavior, or absence of excessive agency was verified.",
    "Declared objects, artifacts, URLs, code, workflows, callbacks, and plugins are never "
    "opened, imported, deserialized, connected to, or executed.",
    "Commitments are declarations of tamper evidence, not verified cryptographic signing.",
)


class AgencyManifestError(ValueError):
    """Fixed nonsecret error at the public declaration boundary."""


def _raise_error(code: str) -> NoReturn:
    raise AgencyManifestError(code)


@dataclass(frozen=True)
class AgencyFinding:
    tool_ref: str
    rule: str

    def to_dict(self) -> dict[str, str]:
        return {
            "tool_ref": self.tool_ref,
            "rule_id": "llm06." + self.rule,
            "field_path": "limits" if self.rule == "autonomy_bounds" else "tools[]." + self.rule,
            "reason_code": "llm06_" + self.rule + "_unsafe",
            "remediation_code": "llm06.remediate." + self.rule,
        }


@dataclass(frozen=True)
class AgencyAuditResult:
    """Only opaque identities and fixed rule identifiers survive assessment."""

    manifest_sha256: str
    tool_refs: tuple[str, ...]
    findings: tuple[AgencyFinding, ...]

    @property
    def status(self) -> str:
        return "not_applicable" if not self.tool_refs else "finding" if self.findings else "passed"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "ai-scan-agency-audit-result-v1",
            "owasp_category": "LLM06",
            "scope": "partial_offline_declaration_assessment",
            "manifest_sha256": self.manifest_sha256,
            "status": self.status,
            "message": {
                "passed": "declaration checks passed",
                "finding": "declaration findings",
                "not_applicable": "no tools declared",
            }[self.status],
            "tool_refs": list(self.tool_refs),
            "findings": [finding.to_dict() for finding in self.findings],
            "network_requests": 0,
            "executions": 0,
            "limitations": list(LIMITATIONS),
        }


def _audit(text: str) -> AgencyAuditResult:
    if type(text) is not str or len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ValueError
    raw = load_json_strict(text)
    _validate(raw)
    refs = tuple(
        "llm06-tool-"
        + hashlib.sha256(("ai-scan-llm06-tool-ref-v1\0" + item["id"]).encode("ascii")).hexdigest()
        for item in raw["tools"]
    )
    findings = tuple(
        AgencyFinding(ref, rule)
        for item, ref in zip(raw["tools"], refs, strict=True)
        for rule in _rules(item, raw["limits"])
    )
    return AgencyAuditResult(hashlib.sha256(text.encode("utf-8")).hexdigest(), refs, findings)


def _rules(item: dict[str, Any], limits: dict[str, int]) -> tuple[str, ...]:
    expected: dict[str, object] = {
        "least_functionality": True,
        "resource_scope": "fixed",
        "parameter_shape": "closed_typed",
        "destination_boundary": "fixed",
        "object_boundary": "fixed",
        "execution_identity": "dedicated_least_privilege",
        "response_schema": "closed_typed",
        "result_trust": "untrusted",
        "output_to_action": "separated",
        "error_isolation": True,
        "operation_commitment": True,
        "request_commitment": True,
        "result_commitment": True,
        "event_identity": "opaque_sequence",
    }
    high_risk = item["operation"] in {"delete", "send"}
    if item["side_effecting"]:
        expected.update(
            {
                "idempotency": "stable_operation_key",
                "precondition": True,
                "read_back": True,
                "cleanup": "deterministic_compensation",
                "cleanup_verified": True,
                "unresolved_state": "halt_and_reconcile",
            }
        )
    rules = [key for key, value in expected.items() if item[key] != value]
    if item["isolation"] == "none" or (high_risk and item["isolation"] != "container"):
        rules.append("isolation")
    ceilings = {
        "steps": 32 if high_risk else 100,
        "side_effects": 8 if high_risk else 16,
        "concurrency": 1 if high_risk else 4,
        "duration_seconds": 60 if high_risk else 300,
        "recursion_depth": 1 if high_risk else 4,
        "delegation_depth": 1 if high_risk else 4,
        "retries": 1 if high_risk else 2,
        "output_bytes": 65536 if high_risk else 1000000,
    }
    if any(limits[key] > ceiling for key, ceiling in ceilings.items()):
        rules.append("autonomy_bounds")
    return tuple(sorted(rules))


def _exact(value: Any, keys: frozenset[str]) -> None:
    if type(value) is not dict or frozenset(value) != keys:
        raise ValueError


def _integer(value: Any, maximum: int) -> None:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError


def _validate(raw: Any) -> None:
    _exact(raw, frozenset({"schema_version", "limits", "tools"}))
    if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError
    limits = raw["limits"]
    _exact(limits, frozenset(_LIMIT_MAX))
    for key, maximum in _LIMIT_MAX.items():
        _integer(limits[key], maximum)
    if (
        any(
            limits[k] > limits["steps"]
            for k in ("concurrency", "recursion_depth", "delegation_depth")
        )
        or limits["retries"] >= limits["steps"]
    ):
        raise ValueError
    if limits["side_effects"] > limits["steps"] * (limits["retries"] + 1):
        raise ValueError
    tools = raw["tools"]
    if type(tools) is not list or len(tools) > MAX_TOOLS:
        raise ValueError
    ids: set[str] = set()
    for item in tools:
        _exact(item, _TOOL_KEYS)
        for key in _REF_FIELDS:
            value = item[key]
            if type(value) is not str or len(value) > 128 or not _REF.fullmatch(value):
                raise ValueError
        if item["id"] in ids:
            raise ValueError
        ids.add(item["id"])
        for key in _BOOL_FIELDS:
            if type(item[key]) is not bool:
                raise ValueError
        for key, choices in _ENUMS.items():
            if type(item[key]) is not str or item[key] not in choices:
                raise ValueError
        _integer(item["max_calls"], limits["steps"])
        side = item["operation"] != "read"
        if item["side_effecting"] != side:
            raise ValueError
        if not side and (
            item["idempotency"] != "none"
            or item["cleanup"] != "none"
            or item["unresolved_state"] != "not_applicable"
            or any(item[k] for k in ("precondition", "read_back", "cleanup_verified"))
        ):
            raise ValueError
        if side and (
            item["unresolved_state"] == "not_applicable"
            or item["max_calls"] * (limits["retries"] + 1) > limits["side_effects"]
        ):
            raise ValueError
        if item["cleanup_verified"] and item["cleanup"] == "none":
            raise ValueError


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

    except (ConfigError, ValueError, TypeError, OSError, RecursionError):
        failed = True
    if failed:
        # Drop all submitted values before creating a fresh exception graph.
        raw = expected = {}
        del value, result, text, raw, expected
        _raise_error("llm06_manifest_invalid")
    return result


def audit_manifest_text(text: str) -> AgencyAuditResult:
    try:
        result: AgencyAuditResult = _public(text, "text")
    finally:
        del text
    return result


def audit_manifest_file(path: str) -> AgencyAuditResult:
    try:
        result: AgencyAuditResult = _public(path, "audit")
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
    def closed(properties: dict[str, object]) -> dict[str, object]:
        return {
            "type": "object",
            "additionalProperties": False,
            "required": sorted(properties),
            "properties": properties,
        }

    properties: dict[str, object] = {
        key: {
            "type": "string",
            "minLength": 3,
            "maxLength": 128,
            "pattern": "^" + _REF.pattern + "$",
        }
        for key in _REF_FIELDS
    }
    properties.update({key: {"type": "boolean"} for key in _BOOL_FIELDS})
    properties.update(
        {key: {"type": "string", "enum": list(values)} for key, values in _ENUMS.items()}
    )
    properties["max_calls"] = {"type": "integer", "minimum": 1, "maximum": 10000}
    schema = closed(
        {
            "schema_version": {"const": MANIFEST_SCHEMA_VERSION},
            "limits": closed(
                {
                    key: {"type": "integer", "minimum": 1, "maximum": maximum}
                    for key, maximum in _LIMIT_MAX.items()
                }
            ),
            "tools": {"type": "array", "maxItems": MAX_TOOLS, "items": closed(properties)},
        }
    )
    schema.update(
        {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://electricentropy.com/schemas/ai-scan-agency-v1",
            "$comment": "Structural schema only; agency semantic validation is mandatory.",
        }
    )
    return schema


def render_json(result: AgencyAuditResult) -> str:
    return json.dumps(result.to_dict(), sort_keys=True, indent=2, allow_nan=False)


def render_human(result: AgencyAuditResult) -> str:
    doc = result.to_dict()
    return "\n".join(
        [
            "LLM06 Excessive Agency offline declaration assessment",
            str(doc["message"]),
            "status: " + result.status,
            "manifest_sha256: " + result.manifest_sha256,
            *(json.dumps(f.to_dict(), sort_keys=True) for f in result.findings),
            *LIMITATIONS,
        ]
    )
