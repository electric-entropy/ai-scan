"""Inert comparisons of operator-supplied claim digests, not truth verification."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, NoReturn

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.core.safe_file import read_stable_regular_file

MANIFEST_SCHEMA_VERSION = "ai-scan-misinformation-manifest-v1"
MAX_MANIFEST_BYTES = 262144
MAX_CASES = 32
MAX_CLAIMS = 64
MAX_TOTAL_CLAIMS = 1024
_REF = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+){1,15}", re.ASCII)
_DIGEST = re.compile(r"[0-9a-f]{64}", re.ASCII)
_LIMITATIONS = (
    "Partial offline structured-claim comparison only; not general truth verification, "
    "full LLM09 coverage, or a compliance assessment.",
    "Ground truth, sources, citations, snapshots, and observed claims are operator-supplied "
    "and are not independently verified.",
    "No model scoring, LLM judge, target execution, network, reference dereferencing, "
    "document loading, or runtime behavior verification occurs.",
    "Passing means only that the submitted structured claims match under the fixed rules.",
)
_RULE_META = {
    "missing_claim": "high",
    "value_mismatch": "high",
    "source_integrity": "medium",
    "unexpected_claim": "medium",
    "snapshot_mismatch": "medium",
}


class MisinformationManifestError(ValueError):
    """Fixed nonsecret public error."""


def _raise_error() -> NoReturn:
    raise MisinformationManifestError("llm09_manifest_invalid")


@dataclass(frozen=True)
class MisinformationFinding:
    context_ref: str
    case_ref: str
    finding_ref: str
    rule: str

    def to_dict(self) -> dict[str, str]:
        return {
            "context_ref": self.context_ref, "case_ref": self.case_ref,
            "finding_ref": self.finding_ref, "rule_id": "llm09." + self.rule,
            "severity": _RULE_META[self.rule], "reason_code": "llm09_" + self.rule,
            "remediation_code": "llm09.remediate." + self.rule,
        }


@dataclass(frozen=True)
class MisinformationAuditResult:
    manifest_sha256: str
    context_ref: str
    case_refs: tuple[str, ...]
    findings: tuple[MisinformationFinding, ...]

    @property
    def status(self) -> str:
        return "finding" if self.findings else "passed"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "ai-scan-misinformation-audit-result-v1",
            "owasp_category": "LLM09", "scope": "partial_offline_structured_claim_comparison",
            "manifest_sha256": self.manifest_sha256, "context_ref": self.context_ref,
            "case_refs": list(self.case_refs), "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "network_requests": 0, "executions": 0, "limitations": list(_LIMITATIONS),
        }


def _opaque(domain: str, identity: tuple[str, ...]) -> str:
    canonical = json.dumps(identity, ensure_ascii=True, separators=(",", ":"))
    return "llm09-" + domain + "-" + hashlib.sha256(
        ("ai-scan-llm09-" + domain + "-ref-v1\0" + canonical).encode("ascii")
    ).hexdigest()


def _audit(text: str) -> MisinformationAuditResult:
    if type(text) is not str or len(text.encode("utf-8")) > MAX_MANIFEST_BYTES:
        raise ValueError
    raw = load_json_strict(text)
    _validate(raw)
    context = _opaque("context", (raw["context_ref"],))
    cases: list[str] = []
    findings: list[MisinformationFinding] = []
    for case in sorted(raw["cases"], key=lambda c: c["case_ref"]):
        identity = (raw["context_ref"], case["case_ref"],
                    case["ground_truth_snapshot_ref"], case["observed_snapshot_ref"])
        case_ref = _opaque("case", identity)
        cases.append(case_ref)
        for rule, claim in _rules(case):
            findings.append(MisinformationFinding(
                context, case_ref, _opaque("finding", (*identity, claim, rule)), rule,
            ))
    return MisinformationAuditResult(
        hashlib.sha256(text.encode("utf-8")).hexdigest(), context, tuple(cases), tuple(findings),
    )


def _rules(case: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    expected = {c["claim_ref"]: c for c in case["expected_claims"]}
    observed = {c["claim_ref"]: c for c in case["observed_claims"]}
    findings: list[tuple[str, str]] = []
    for ref, claim in expected.items():
        if ref not in observed:
            findings.append(("missing_claim", ref))
            continue
        actual = observed[ref]
        if actual["value_sha256"] != claim["value_sha256"]:
            findings.append(("value_mismatch", ref))
    for ref, actual in observed.items():
        if not actual["citation_present"] or (
            ref in expected and actual["source_ref"] != expected[ref]["source_ref"]
        ):
            findings.append(("source_integrity", ref))
    findings.extend(("unexpected_claim", ref) for ref in observed.keys() - expected.keys())
    if case["ground_truth_snapshot_ref"] != case["observed_snapshot_ref"]:
        findings.append(("snapshot_mismatch", ""))
    return tuple(sorted(findings))


def _exact(value: Any, keys: set[str]) -> None:
    if type(value) is not dict or set(value) != keys:
        raise ValueError


def _ref(value: Any) -> None:
    if type(value) is not str or not 3 <= len(value) <= 64 or not _REF.fullmatch(value):
        raise ValueError


def _claims(values: Any, *, observed: bool) -> None:
    if type(values) is not list or not (0 if observed else 1) <= len(values) <= MAX_CLAIMS:
        raise ValueError
    seen: set[str] = set()
    for claim in values:
        _exact(claim, {"claim_ref", "value_sha256", "source_ref"} |
               ({"citation_present"} if observed else set()))
        _ref(claim["claim_ref"])
        _ref(claim["source_ref"])
        value = claim["value_sha256"]
        if type(value) is not str or not _DIGEST.fullmatch(value):
            raise ValueError
        if observed and type(claim["citation_present"]) is not bool:
            raise ValueError
        if claim["claim_ref"] in seen:
            raise ValueError
        seen.add(claim["claim_ref"])


def _validate(raw: Any) -> None:
    _exact(raw, {"schema_version", "context_ref", "cases"})
    if raw["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError
    _ref(raw["context_ref"])
    cases = raw["cases"]
    if type(cases) is not list or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError
    seen: set[str] = set()
    total = 0
    for case in cases:
        _exact(case, {"case_ref", "ground_truth_snapshot_ref", "observed_snapshot_ref",
                      "expected_claims", "observed_claims"})
        for key in ("case_ref", "ground_truth_snapshot_ref", "observed_snapshot_ref"):
            _ref(case[key])
        if case["case_ref"] in seen:
            raise ValueError
        seen.add(case["case_ref"])
        _claims(case["expected_claims"], observed=False)
        _claims(case["observed_claims"], observed=True)
        total += len(case["expected_claims"]) + len(case["observed_claims"])
        if total > MAX_TOTAL_CLAIMS:
            raise ValueError


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


def audit_manifest_text(text: str) -> MisinformationAuditResult:
    try:
        result: MisinformationAuditResult = _public(text, "text")
    finally:
        del text
    return result


def audit_manifest_file(path: str) -> MisinformationAuditResult:
    try:
        result: MisinformationAuditResult = _public(path, "audit")
    finally:
        del path
    return result


def load_manifest_file(path: str) -> str:
    try:
        result: str = _public(path, "load")
    finally:
        del path
    return result


def render_json(result: MisinformationAuditResult) -> str:
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

    def array(item: dict[str, object], minimum: int, maximum: int) -> dict[str, object]:
        return {"type": "array", "minItems": minimum, "maxItems": maximum,
                "uniqueItems": True, "items": item}

    ref = {"type": "string", "minLength": 3, "maxLength": 64,
           "pattern": "^" + _REF.pattern + r"(?![\s\S])"}
    claim: dict[str, object] = {
        "claim_ref": ref, "source_ref": ref,
        "value_sha256": {"type": "string", "minLength": 64, "maxLength": 64,
                         "pattern": r"^[0-9a-f]{64}(?![\s\S])"},
    }
    case = closed({
        "case_ref": ref, "ground_truth_snapshot_ref": ref, "observed_snapshot_ref": ref,
        "expected_claims": array(closed(claim), 1, MAX_CLAIMS),
        "observed_claims": array(closed({**claim, "citation_present": {"type": "boolean"}}),
                                 0, MAX_CLAIMS),
    })
    schema = closed({"schema_version": {"const": MANIFEST_SCHEMA_VERSION},
                     "context_ref": ref, "cases": array(case, 1, MAX_CASES)})
    schema.update({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://electricentropy.com/schemas/ai-scan-misinformation-v1",
        "$comment": "Structural preflight only. Runtime additionally enforces unique case_ref "
        "identities, unique claim_ref identities separately in each claim array, and at most "
        "1024 total expected plus observed claims. Strict JSON, bounded stable-file checks, "
        "and deterministic comparisons are runtime requirements; references are never resolved.",
    })
    return schema


def render_text(result: MisinformationAuditResult) -> str:
    return "LLM09 Misinformation offline structured-claim comparison\n" + render_json(result)
