"""Offline OWASP LLM05 output-handling declaration assessment.

Only the supplied manifest bytes are inspected. Declared implementation references are
opaque labels: this module never opens, imports, executes, renders, deserializes, or
connects to anything named by a sink declaration.
"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Literal, NoReturn, cast

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.core.safe_file import SafeFileError, read_stable_regular_file

MANIFEST_SCHEMA_VERSION = "ai-scan-output-handling-manifest-v1"
RESULT_SCHEMA_VERSION = "ai-scan-output-handling-audit-result-v1"
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_SINKS = 2000
MAX_ID_CHARS = 128
MAX_TEXT_CHARS = 2048
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 50_000
MAX_DECLARED_OUTPUT_CHARS = 10_000_000
SAFE_OUTPUT_LIMIT = 1_000_000

AuditStatus = Literal["passed", "finding", "not_applicable"]
SinkType = Literal[
    "html_dom", "markdown", "sql", "shell_process", "code_template", "logging", "structured_api"
]

_TOP_LEVEL_KEYS = frozenset({"schema_version", "sinks"})
_SINK_KEYS = frozenset(
    {
        "id",
        "type",
        "context",
        "implementation_ref",
        "trust_boundary",
        "encoding",
        "parameterized",
        "string_concatenation",
        "schema_validation",
        "allowlist_validation",
        "active_content",
        "interpreter_behavior",
        "error_isolation",
        "output_isolation",
        "max_output_chars",
    }
)
_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}$")
_CONTEXT_ENCODING: dict[str, dict[str, str]] = {
    "html_dom": {"html_text": "html_escape", "html_attribute": "html_attribute_escape"},
    "markdown": {"markdown": "markdown_escape"},
    "sql": {"query": "parameterized_query"},
    "shell_process": {"argv": "argv_array"},
    "code_template": {"template": "sandboxed_template"},
    "logging": {"log_record": "structured_log"},
    "structured_api": {"json": "schema_serializer"},
}
_PARAMETERIZED_TYPES = frozenset({"sql", "shell_process", "code_template", "structured_api"})
_ACTIVE_CONTENT_TYPES = frozenset({"html_dom", "markdown", "code_template"})
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


def _schema_document() -> dict[str, object]:
    sink_properties: dict[str, object] = {
        "id": {
            "type": "string",
            "minLength": 3,
            "maxLength": MAX_ID_CHARS,
            "pattern": _ID_RE.pattern,
        },
        "type": {"type": "string", "enum": sorted(_CONTEXT_ENCODING)},
        "context": {
            "type": "string",
            "enum": sorted(
                {context for contexts in _CONTEXT_ENCODING.values() for context in contexts}
            ),
        },
        "implementation_ref": {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_TEXT_CHARS,
        },
        "trust_boundary": {
            "type": "string",
            "enum": ["trusted_internal", "untrusted_model_output"],
        },
        "encoding": {"type": "string", "minLength": 1, "maxLength": 64},
        "parameterized": {"type": "boolean"},
        "string_concatenation": {"type": "boolean"},
        "schema_validation": {"type": "boolean"},
        "allowlist_validation": {"type": "boolean"},
        "active_content": {
            "type": "string",
            "enum": ["allowed", "disabled", "sanitized"],
        },
        "interpreter_behavior": {
            "type": "string",
            "enum": ["direct", "disabled", "sandboxed"],
        },
        "error_isolation": {"type": "boolean"},
        "output_isolation": {"type": "boolean"},
        "max_output_chars": {
            "type": "integer",
            "minimum": 1,
            "maximum": MAX_DECLARED_OUTPUT_CHARS,
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://electricentropy.com/schemas/ai-scan-output-handling-v1",
        "title": "AI-Scan LLM05 output-handling declaration manifest v1",
        "type": "object",
        "additionalProperties": False,
        "required": ["schema_version", "sinks"],
        "properties": {
            "schema_version": {"const": MANIFEST_SCHEMA_VERSION},
            "sinks": {
                "type": "array",
                "maxItems": MAX_SINKS,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": sorted(_SINK_KEYS),
                    "properties": sink_properties,
                },
            },
        },
    }


class OutputHandlingManifestError(ValueError):
    """A fixed, non-echoing LLM05 manifest validation failure."""


def _raise_public_manifest_error(code: str) -> NoReturn:
    """Raise from a frame that has never held submitted manifest data."""
    raise OutputHandlingManifestError(code)


def _load_manifest_file(path: str) -> str:
    try:
        raw = read_stable_regular_file(path, max_bytes=MAX_MANIFEST_BYTES)
    except SafeFileError as exc:
        codes = {
            "safe_open_unavailable": "llm05_safe_open_unavailable",
            "invalid_path": "llm05_manifest_invalid_path",
            "not_regular": "llm05_manifest_not_regular",
            "too_large": "llm05_manifest_too_large",
            "changed": "llm05_manifest_changed",
        }
        raise OutputHandlingManifestError(
            codes.get(str(exc), "llm05_manifest_changed")
        ) from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OutputHandlingManifestError("llm05_manifest_invalid_utf8") from exc


def load_manifest_file(path: str) -> str:
    """Read one stable bounded regular non-symlink UTF-8 manifest."""
    text: str | None = None
    error_code: str | None = None
    try:
        text = _load_manifest_file(path)
    except OutputHandlingManifestError as exc:
        error_code = str(exc)
    if error_code is not None:
        del path, text
        _raise_public_manifest_error(error_code)
    assert text is not None
    return text


def _load_schema_text(text: str) -> dict[str, object]:
    try:
        raw = load_json_strict(text)
    except (ConfigError, ValueError, TypeError) as exc:
        raise OutputHandlingManifestError("llm05_schema_invalid_json") from exc
    expected = _schema_document()
    if raw != expected:
        raise OutputHandlingManifestError("llm05_schema_semantic_mismatch")
    return expected


def load_schema_text(text: str) -> dict[str, object]:
    """Authenticate the packaged schema by exact semantic contract comparison."""
    schema: dict[str, object] | None = None
    error_code: str | None = None
    try:
        schema = _load_schema_text(text)
    except OutputHandlingManifestError as exc:
        error_code = str(exc)
    if error_code is not None:
        del text, schema
        _raise_public_manifest_error(error_code)
    assert schema is not None
    return schema


@dataclass(frozen=True)
class _Sink:
    id: str
    type: SinkType
    context: str
    encoding: str
    trust_boundary: str
    parameterized: bool
    string_concatenation: bool
    schema_validation: bool
    allowlist_validation: bool
    active_content: str
    interpreter_behavior: str
    error_isolation: bool
    output_isolation: bool
    max_output_chars: int


@dataclass(frozen=True)
class OutputHandlingAuditResult:
    """Secret-free result for the bounded declaration-only assessment."""

    manifest_sha256: str
    status: AuditStatus
    applicability: Literal["applicable", "not_applicable"]
    sinks: tuple[dict[str, object], ...]
    findings: tuple[dict[str, object], ...]
    limitations: tuple[str, ...]

    @property
    def summary(self) -> dict[str, int]:
        return {"sinks": len(self.sinks), "findings": len(self.findings)}

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": RESULT_SCHEMA_VERSION,
            "owasp_category": "LLM05",
            "scope": "partial_offline_declaration_assessment",
            "applicability": self.applicability,
            "status": self.status,
            "manifest_sha256": self.manifest_sha256,
            "network_requests": 0,
            "executions": 0,
            "sinks": list(self.sinks),
            "findings": list(self.findings),
            "summary": self.summary,
            "limitations": list(self.limitations),
        }


_LIMITATIONS = (
    "Partial offline declaration assessment only; declaration checks passed does not prove "
    "safe runtime behavior.",
    "No model output, command, template, query, HTML, JavaScript, payload, plugin, or "
    "declared implementation reference is opened, rendered, deserialized, imported, or "
    "executed.",
    "Runtime rendering and execution, browser behavior, database or process effects, prompt "
    "injection, and downstream implementation verification remain out of scope.",
    "AI-Scan does not claim full LLM05 coverage or OWASP compliance from this assessment.",
)

_RULES: dict[str, tuple[str, str, str]] = {
    "llm05.untrusted_boundary": (
        "sinks[].trust_boundary",
        "llm05_trust_boundary_not_untrusted",
        "llm05.remediate.untrusted_boundary",
    ),
    "llm05.contextual_encoding": (
        "sinks[].encoding",
        "llm05_contextual_encoding_missing",
        "llm05.remediate.contextual_encoding",
    ),
    "llm05.parameterization": (
        "sinks[].parameterized",
        "llm05_parameterization_missing",
        "llm05.remediate.parameterization",
    ),
    "llm05.string_concatenation": (
        "sinks[].string_concatenation",
        "llm05_string_concatenation_enabled",
        "llm05.remediate.string_concatenation",
    ),
    "llm05.schema_validation": (
        "sinks[].schema_validation",
        "llm05_schema_validation_missing",
        "llm05.remediate.schema_validation",
    ),
    "llm05.allowlist_validation": (
        "sinks[].allowlist_validation",
        "llm05_allowlist_validation_missing",
        "llm05.remediate.allowlist_validation",
    ),
    "llm05.active_content": (
        "sinks[].active_content",
        "llm05_active_content_allowed",
        "llm05.remediate.active_content",
    ),
    "llm05.interpreter_behavior": (
        "sinks[].interpreter_behavior",
        "llm05_dangerous_interpreter_behavior",
        "llm05.remediate.interpreter_behavior",
    ),
    "llm05.error_isolation": (
        "sinks[].error_isolation",
        "llm05_error_isolation_missing",
        "llm05.remediate.error_isolation",
    ),
    "llm05.output_isolation": (
        "sinks[].output_isolation",
        "llm05_output_isolation_missing",
        "llm05.remediate.output_isolation",
    ),
    "llm05.fixed_size_limit": (
        "sinks[].max_output_chars",
        "llm05_fixed_size_limit_unsafe",
        "llm05.remediate.fixed_size_limit",
    ),
}


def _audit_manifest_text(text: str) -> OutputHandlingAuditResult:
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OutputHandlingManifestError("llm05_manifest_invalid_text") from exc
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise OutputHandlingManifestError("llm05_manifest_too_large")
    try:
        raw = load_json_strict(text)
    except (ConfigError, ValueError, TypeError, RecursionError) as exc:
        raise OutputHandlingManifestError("llm05_manifest_invalid_json") from exc
    _check_json_bounds(raw)
    if not isinstance(raw, dict):
        raise OutputHandlingManifestError("llm05_manifest_invalid_document")
    _require_exact_keys(raw, _TOP_LEVEL_KEYS, "llm05_manifest_invalid_top_level")
    if raw.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise OutputHandlingManifestError("llm05_manifest_unsupported_schema")
    raw_sinks = raw.get("sinks")
    if not isinstance(raw_sinks, list):
        raise OutputHandlingManifestError("llm05_manifest_invalid_sinks")
    if len(raw_sinks) > MAX_SINKS:
        raise OutputHandlingManifestError("llm05_manifest_too_many_sinks")

    manifest_sha256 = hashlib.sha256(encoded).hexdigest()
    if not raw_sinks:
        return OutputHandlingAuditResult(
            manifest_sha256,
            "not_applicable",
            "not_applicable",
            (),
            (),
            _LIMITATIONS,
        )

    sinks = tuple(_parse_sink(value) for value in raw_sinks)
    ids = [sink.id for sink in sinks]
    if len(ids) != len(set(ids)):
        raise OutputHandlingManifestError("llm05_manifest_duplicate_id")

    sink_docs: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    for sink in sinks:
        ref = _sink_ref(sink.id)
        sink_docs.append(
            {
                "sink_ref": ref,
                "manifest_sha256": manifest_sha256,
                "applicability": "applicable",
            }
        )
        findings.extend(_findings_for_sink(sink, ref, manifest_sha256))
    return OutputHandlingAuditResult(
        manifest_sha256,
        "finding" if findings else "passed",
        "applicable",
        tuple(sink_docs),
        tuple(findings),
        _LIMITATIONS,
    )


def audit_manifest_text(text: str) -> OutputHandlingAuditResult:
    """Validate and assess strict JSON without touching declared references."""
    result: OutputHandlingAuditResult | None = None
    error_code: str | None = None
    try:
        result = _audit_manifest_text(text)
    except OutputHandlingManifestError as exc:
        error_code = str(exc)
    if error_code is not None:
        del text, result
        _raise_public_manifest_error(error_code)
    assert result is not None
    return result


def audit_manifest_file(path: str) -> OutputHandlingAuditResult:
    """Load and assess only the explicitly supplied manifest file."""
    text: str | None = None
    result: OutputHandlingAuditResult | None = None
    error_code: str | None = None
    try:
        text = _load_manifest_file(path)
        result = _audit_manifest_text(text)
    except OutputHandlingManifestError as exc:
        error_code = str(exc)
    if error_code is not None:
        del path, text, result
        _raise_public_manifest_error(error_code)
    assert result is not None
    return result


def render_json(result: OutputHandlingAuditResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True, allow_nan=False)


def render_human(result: OutputHandlingAuditResult) -> str:
    lines = [
        "LLM05 Improper Output Handling offline declaration assessment",
        "scope: partial_offline_declaration_assessment",
        f"applicability: {result.applicability}",
        f"status: {result.status}",
        f"manifest_sha256: {result.manifest_sha256}",
        f"sinks: {result.summary['sinks']}",
        f"findings: {result.summary['findings']}",
        "network_requests: 0",
        "executions: 0",
    ]
    for finding in result.findings:
        lines.append(
            f"- finding {finding['rule_id']} sink={finding['sink_ref']} "
            f"path={finding['field_path']} reason={finding['reason_code']} "
            f"remediation={finding['remediation_code']}"
        )
    lines.append("limitations:")
    lines.extend(f"- {limitation}" for limitation in result.limitations)
    return "\n".join(lines)


def _parse_sink(value: Any) -> _Sink:
    if not isinstance(value, dict):
        raise OutputHandlingManifestError("llm05_manifest_invalid_sink")
    _require_exact_keys(value, _SINK_KEYS, "llm05_manifest_invalid_sink_fields")
    sink_id = _string(value, "id", MAX_ID_CHARS)
    if not _ID_RE.fullmatch(sink_id):
        raise OutputHandlingManifestError("llm05_manifest_invalid_sink_id")
    sink_type = _string(value, "type", 32)
    if sink_type not in _CONTEXT_ENCODING:
        raise OutputHandlingManifestError("llm05_manifest_invalid_sink_type")
    context = _string(value, "context", 32)
    expected = _CONTEXT_ENCODING[sink_type]
    if context not in expected:
        raise OutputHandlingManifestError("llm05_manifest_invalid_sink_context")
    _string(value, "implementation_ref", MAX_TEXT_CHARS)
    trust_boundary = _enum_string(
        value, "trust_boundary", frozenset({"untrusted_model_output", "trusted_internal"})
    )
    encoding = _string(value, "encoding", 64)
    active_content = _enum_string(
        value, "active_content", frozenset({"disabled", "sanitized", "allowed"})
    )
    interpreter_behavior = _enum_string(
        value, "interpreter_behavior", frozenset({"disabled", "sandboxed", "direct"})
    )
    max_output_chars = value.get("max_output_chars")
    if (
        isinstance(max_output_chars, bool)
        or not isinstance(max_output_chars, int)
        or max_output_chars <= 0
        or max_output_chars > MAX_DECLARED_OUTPUT_CHARS
    ):
        raise OutputHandlingManifestError("llm05_manifest_invalid_size_limit")
    return _Sink(
        id=sink_id,
        type=cast(SinkType, sink_type),
        context=context,
        encoding=encoding,
        trust_boundary=trust_boundary,
        parameterized=_bool(value, "parameterized"),
        string_concatenation=_bool(value, "string_concatenation"),
        schema_validation=_bool(value, "schema_validation"),
        allowlist_validation=_bool(value, "allowlist_validation"),
        active_content=active_content,
        interpreter_behavior=interpreter_behavior,
        error_isolation=_bool(value, "error_isolation"),
        output_isolation=_bool(value, "output_isolation"),
        max_output_chars=max_output_chars,
    )


def _findings_for_sink(
    sink: _Sink, sink_ref: str, manifest_sha256: str
) -> list[dict[str, object]]:
    rules: list[str] = []
    if sink.trust_boundary != "untrusted_model_output":
        rules.append("llm05.untrusted_boundary")
    if sink.encoding != _CONTEXT_ENCODING[sink.type][sink.context]:
        rules.append("llm05.contextual_encoding")
    if sink.type in _PARAMETERIZED_TYPES and not sink.parameterized:
        rules.append("llm05.parameterization")
    if sink.string_concatenation:
        rules.append("llm05.string_concatenation")
    if not sink.schema_validation:
        rules.append("llm05.schema_validation")
    if not sink.allowlist_validation:
        rules.append("llm05.allowlist_validation")
    if sink.type in _ACTIVE_CONTENT_TYPES and sink.active_content == "allowed":
        rules.append("llm05.active_content")
    elif sink.active_content == "allowed":
        rules.append("llm05.active_content")
    safe_interpreter = sink.interpreter_behavior == "disabled" or (
        sink.type == "code_template" and sink.interpreter_behavior == "sandboxed"
    )
    if not safe_interpreter:
        rules.append("llm05.interpreter_behavior")
    if not sink.error_isolation:
        rules.append("llm05.error_isolation")
    if not sink.output_isolation:
        rules.append("llm05.output_isolation")
    if sink.max_output_chars > SAFE_OUTPUT_LIMIT:
        rules.append("llm05.fixed_size_limit")
    return [_finding(rule_id, sink_ref, manifest_sha256) for rule_id in rules]


def _finding(rule_id: str, sink_ref: str, manifest_sha256: str) -> dict[str, object]:
    field_path, reason_code, remediation_code = _RULES[rule_id]
    return {
        "rule_id": rule_id,
        "status": "finding",
        "owasp_category": "LLM05",
        "applicability": "applicable",
        "manifest_sha256": manifest_sha256,
        "sink_ref": sink_ref,
        "field_path": field_path,
        "reason_code": reason_code,
        "remediation_code": remediation_code,
    }


def _sink_ref(sink_id: str) -> str:
    digest = hashlib.sha256(
        ("ai-scan-llm05-output-sink-ref-v1\0" + sink_id).encode("utf-8")
    ).hexdigest()
    return f"llm05-sink-{digest}"


def _require_exact_keys(raw: dict[str, Any], allowed: frozenset[str], code: str) -> None:
    if frozenset(raw) != allowed:
        raise OutputHandlingManifestError(code)


def _check_json_bounds(raw: Any) -> None:
    stack: list[tuple[Any, int]] = [(raw, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise OutputHandlingManifestError("llm05_manifest_too_many_values")
        if depth > MAX_JSON_DEPTH:
            raise OutputHandlingManifestError("llm05_manifest_too_deep")
        if isinstance(value, str):
            if len(value) > MAX_TEXT_CHARS:
                raise OutputHandlingManifestError("llm05_manifest_string_too_long")
        elif isinstance(value, dict):
            for key, child in value.items():
                if len(key) > MAX_TEXT_CHARS:
                    raise OutputHandlingManifestError("llm05_manifest_string_too_long")
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)


def _string(raw: dict[str, Any], key: str, max_chars: int) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise OutputHandlingManifestError("llm05_manifest_invalid_string")
    if value != unicodedata.normalize("NFC", value):
        raise OutputHandlingManifestError("llm05_manifest_invalid_string")
    if any(unicodedata.category(ch) in _FORBIDDEN_CATEGORIES for ch in value):
        raise OutputHandlingManifestError("llm05_manifest_invalid_string")
    return value


def _enum_string(raw: dict[str, Any], key: str, allowed: frozenset[str]) -> str:
    value = _string(raw, key, 64)
    if value not in allowed:
        raise OutputHandlingManifestError("llm05_manifest_invalid_enum")
    return value


def _bool(raw: dict[str, Any], key: str) -> bool:
    value = raw.get(key)
    if value is not True and value is not False:
        raise OutputHandlingManifestError("llm05_manifest_invalid_boolean")
    return value


__all__ = [
    "OutputHandlingAuditResult",
    "OutputHandlingManifestError",
    "audit_manifest_file",
    "audit_manifest_text",
    "load_manifest_file",
    "load_schema_text",
    "render_human",
    "render_json",
]
