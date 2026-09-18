"""Inert comparisons of supplied counters and declarations, not runtime enforcement."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, NoReturn

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.core.safe_file import read_stable_regular_file

MANIFEST_SCHEMA_VERSION = "ai-scan-consumption-manifest-v1"
MAX_MANIFEST_BYTES = 262144
MAX_SCENARIOS = 32
MAX_COUNTER = 1_000_000_000
MAX_AGGREGATE = 10_000_000_000
COUNTERS = ("requests", "input_tokens", "output_tokens", "total_tokens", "duration_ms",
            "peak_concurrency", "queue_depth", "retries", "tool_steps", "request_bytes",
            "response_bytes")
CONTROLS = ("deadline_enforced", "cancellation_enforced", "backpressure", "circuit_breaker",
            "cleanup_enforced", "per_scope_limits", "fail_closed_on_exhaustion")
EVENTS = ("cancellation_observed", "exhaustion_observed", "cleanup_observed",
          "work_after_cancellation", "work_after_exhaustion")
_REF = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}", re.ASCII)
RULES = {"request_volume": "high", "token_budget": "high", "deadline": "high",
         "concurrency": "high", "retry_tool_budget": "high", "byte_budget": "medium",
         "termination": "high", "isolation": "medium"}
_LIMITATIONS = (
    "Partial offline LLM10 bounded-consumption evidence only; not full coverage or compliance.",
    "Workload observations, resource ceilings and controls are operator-supplied, not verified.",
    "No target execution, load generation, network, imports, plugins, reference dereferencing, "
    "URL/archive/document/model loading, LLM judge, model scoring or billing/cost assessment.",
    "Passing does not prove runtime enforcement; only the submitted fixed comparisons passed.",
)


class ConsumptionManifestError(ValueError):
    """Fixed nonsecret public error."""


def _raise_error() -> NoReturn:
    raise ConsumptionManifestError("llm10_manifest_invalid")


@dataclass(frozen=True)
class ConsumptionFinding:
    context_ref: str
    scenario_ref: str
    finding_ref: str
    rule: str

    def to_dict(self) -> dict[str, str]:
        return {"context_ref": self.context_ref, "scenario_ref": self.scenario_ref,
                "finding_ref": self.finding_ref, "rule_id": "llm10." + self.rule,
                "severity": RULES[self.rule], "reason_code": "llm10_" + self.rule,
                "remediation_code": "llm10.remediate." + self.rule}


@dataclass(frozen=True)
class ConsumptionAuditResult:
    manifest_sha256: str
    context_ref: str
    scenario_refs: tuple[str, ...]
    findings: tuple[ConsumptionFinding, ...]

    @property
    def status(self) -> str:
        return "finding" if self.findings else "passed"

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": "ai-scan-consumption-audit-result-v1",
                "owasp_category": "LLM10", "scope": "partial_offline_bounded_consumption",
                "manifest_sha256": self.manifest_sha256, "context_ref": self.context_ref,
                "scenario_refs": list(self.scenario_refs), "status": self.status,
                "findings": [f.to_dict() for f in self.findings],
                "network_requests": 0, "executions": 0, "limitations": list(_LIMITATIONS)}


def _opaque(domain: str, identity: tuple[str, ...]) -> str:
    canonical = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return "llm10-" + domain + "-" + hashlib.sha256(
        ("ai-scan-llm10-" + domain + "-ref-v1\0" + canonical).encode("ascii")
    ).hexdigest()


def _rules(scenario: dict[str, Any]) -> tuple[str, ...]:
    ceilings, observed = scenario["ceilings"], scenario["observations"]
    controls, events = scenario["controls"], scenario["events"]

    def exceeds(*fields: str) -> bool:
        return any(observed[field] > ceilings[field] for field in fields)

    triggered = (
        exceeds("requests"),
        exceeds("input_tokens", "output_tokens", "total_tokens") or
        observed["total_tokens"] != observed["input_tokens"] + observed["output_tokens"],
        exceeds("duration_ms") or not controls["deadline_enforced"],
        exceeds("peak_concurrency", "queue_depth") or not controls["backpressure"],
        exceeds("retries", "tool_steps"),
        exceeds("request_bytes", "response_bytes"),
        not all(controls[k] for k in ("cancellation_enforced", "cleanup_enforced",
                                     "fail_closed_on_exhaustion")) or
        ((events["cancellation_observed"] or events["exhaustion_observed"])
         and not events["cleanup_observed"]) or
        events["work_after_cancellation"] or events["work_after_exhaustion"],
        not controls["circuit_breaker"] or not controls["per_scope_limits"],
    )
    return tuple(rule for rule, active in zip(RULES, triggered, strict=True) if active)


def _exact(value: Any, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        raise ValueError


def _ref(value: Any) -> None:
    if type(value) is not str or not 3 <= len(value) <= 64 or not _REF.fullmatch(value):
        raise ValueError


def _validate(raw: Any) -> None:
    _exact(raw, {"schema_version", "context_ref", "scenarios"})
    if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError
    _ref(raw["context_ref"])
    scenarios = raw["scenarios"]
    if type(scenarios) is not list or not 1 <= len(scenarios) <= MAX_SCENARIOS:
        raise ValueError
    seen: set[str] = set()
    aggregate = 0
    for scenario in scenarios:
        _exact(scenario, {"scenario_ref", "ceilings", "observations", "controls", "events"})
        _ref(scenario["scenario_ref"])
        if scenario["scenario_ref"] in seen:
            raise ValueError
        seen.add(scenario["scenario_ref"])
        for group in ("ceilings", "observations"):
            _exact(scenario[group], set(COUNTERS))
            for value in scenario[group].values():
                if type(value) is not int or not 0 <= value <= MAX_COUNTER:
                    raise ValueError
                aggregate += value
        if aggregate > MAX_AGGREGATE:
            raise ValueError
        for group, fields in (("controls", CONTROLS), ("events", EVENTS)):
            _exact(scenario[group], set(fields))
            if any(type(value) is not bool for value in scenario[group].values()):
                raise ValueError
        ceilings, events = scenario["ceilings"], scenario["events"]
        if ceilings["total_tokens"] != ceilings["input_tokens"] + ceilings["output_tokens"]:
            raise ValueError
        if (events["work_after_cancellation"] and not events["cancellation_observed"] or
                events["work_after_exhaustion"] and not events["exhaustion_observed"] or
                events["cleanup_observed"] and not
                (events["cancellation_observed"] or events["exhaustion_observed"])):
            raise ValueError


def _audit(text: str) -> ConsumptionAuditResult:
    if type(text) is not str or len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ValueError
    raw = load_json_strict(text)
    _validate(raw)
    context = _opaque("context", (raw["context_ref"],))
    scenarios: list[str] = []
    findings: list[ConsumptionFinding] = []
    for scenario in sorted(raw["scenarios"], key=lambda s: s["scenario_ref"]):
        identity = (raw["context_ref"], scenario["scenario_ref"])
        ref = _opaque("scenario", identity)
        scenarios.append(ref)
        for rule in _rules(scenario):
            findings.append(ConsumptionFinding(
                context, ref, _opaque("finding", (*identity, rule)), rule,
            ))
    return ConsumptionAuditResult(hashlib.sha256(text.encode("utf-8")).hexdigest(),
                                  context, tuple(scenarios), tuple(findings))


def _public(value: str, operation: str) -> Any:
    result: Any = None
    text: str | None = None
    failed = False
    try:
        if type(value) is not str:
            raise ValueError
        if operation == "schema":
            if len(value.encode("utf-8")) > MAX_MANIFEST_BYTES:
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
        raw = expected = {}
        del value, text, result, raw, expected
        _raise_error()
    return result


def audit_manifest_text(text: str) -> ConsumptionAuditResult:
    try:
        result: ConsumptionAuditResult = _public(text, "text")
    finally:
        del text
    return result


def audit_manifest_file(path: str) -> ConsumptionAuditResult:
    try:
        result: ConsumptionAuditResult = _public(path, "audit")
    finally:
        del path
    return result


def load_manifest_file(path: str) -> str:
    try:
        result: str = _public(path, "load")
    finally:
        del path
    return result


def render_json(result: ConsumptionAuditResult) -> str:
    return json.dumps(result.to_dict(), sort_keys=True, indent=2, allow_nan=False)


def load_schema_text(text: str) -> dict[str, object]:
    try:
        result: dict[str, object] = _public(text, "schema")
    finally:
        del text
    return result


def _schema_document() -> dict[str, object]:
    def closed(properties: dict[str, object]) -> dict[str, object]:
        return {"type": "object", "additionalProperties": False,
                "required": sorted(properties), "properties": properties}

    ref = {"type": "string", "minLength": 3, "maxLength": 64,
           "pattern": "^" + _REF.pattern + r"(?![\s\S])"}
    counters = closed({key: {"type": "integer", "minimum": 0, "maximum": MAX_COUNTER}
                       for key in COUNTERS})
    events = closed({key: {"type": "boolean"} for key in EVENTS})
    events["allOf"] = [
        {"if": {"properties": {"work_after_" + event: {"const": True}}},
         "then": {"properties": {event + "_observed": {"const": True}}}}
        for event in ("cancellation", "exhaustion")
    ] + [{"if": {"properties": {"cleanup_observed": {"const": True}}},
          "then": {"anyOf": [{"properties": {event + "_observed": {"const": True}}}
                             for event in ("cancellation", "exhaustion")]}}]
    scenario = closed({"scenario_ref": ref, "ceilings": counters, "observations": counters,
                       "controls": closed({key: {"type": "boolean"} for key in CONTROLS}),
                       "events": events})
    schema = closed({"schema_version": {"const": MANIFEST_SCHEMA_VERSION}, "context_ref": ref,
                     "scenarios": {"type": "array", "minItems": 1, "maxItems": MAX_SCENARIOS,
                                   "uniqueItems": True, "items": scenario}})
    schema.update({"$schema": "https://json-schema.org/draft/2020-12/schema",
                   "$id": "https://electricentropy.com/schemas/ai-scan-consumption-v1",
                   "$comment": "Structural preflight only. Runtime requires exact lexical "
                   "integers (not 1.0), unique scenario_ref identities, sum of all numeric "
                   "values <= 10000000000, ceiling total_tokens = input_tokens + output_tokens, "
                   "strict duplicate/nonfinite JSON rejection and bounded stable-file checks. "
                   "Observed token arithmetic inconsistencies are findings; references are inert."})
    return schema


def render_text(result: ConsumptionAuditResult) -> str:
    return "LLM10 Unbounded Consumption offline bounded-workload comparison\n" + render_json(result)
