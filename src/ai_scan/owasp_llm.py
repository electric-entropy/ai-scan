"""Strict loader and domain model for the shipped OWASP LLM 2025 matrix."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from importlib import resources
from typing import Any, Literal, cast

from ai_scan.core.config import load_json_strict
from ai_scan.core.errors import ConfigError

CategoryId = Literal[
    "LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10"
]
Outcome = Literal["tested", "not_tested", "blocked", "inconclusive", "finding", "not_applicable"]

CATEGORY_NAMES_2025: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_ALLOWED_OUTCOMES = frozenset(
    {"tested", "not_tested", "blocked", "inconclusive", "finding", "not_applicable"}
)
_ACTIVE_CATEGORIES = frozenset({"LLM01", "LLM02"})
# Phase 2A is a contract only. Even categories with current active coverage are
# partial scenario coverage, so no category may claim full/comprehensive coverage.
_FULL_CLAIM_ALLOWED = False
_ID_RE = re.compile(r"^ai-scan\.owasp\.LLM(?:0[1-9]|10)\.[a-z0-9][a-z0-9-]{1,48}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")


class CoverageError(ValueError):
    """OWASP coverage matrix is malformed or semantically impossible."""


@dataclass(frozen=True)
class Scenario:
    """One scenario family within an OWASP category."""

    id: str
    name: str
    active_cli: bool
    status: Outcome
    evidence: str
    controls: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_identifier("scenario id", self.id, prefix="scenario.")
        _require_non_empty("scenario name", self.name)
        _require_exact_bool("scenario active_cli", self.active_cli)
        _require_outcome(self.status)
        _require_non_empty("scenario evidence", self.evidence)
        _require_str_tuple("scenario controls", self.controls, min_items=1)
        if self.active_cli and self.status in {"not_tested", "not_applicable"}:
            raise CoverageError("active scenario cannot be not_tested/not_applicable")
        if not self.active_cli and self.status == "finding":
            raise CoverageError("inactive scenario cannot allow a finding outcome")


@dataclass(frozen=True)
class ModeBreadth:
    """Scenario breadth by product mode; safety semantics are not represented here."""

    reliable: tuple[str, ...]
    kitchen_sink: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_str_tuple("mode_breadth.reliable", self.reliable, min_items=1)
        _require_str_tuple("mode_breadth.kitchen_sink", self.kitchen_sink, min_items=1)


@dataclass(frozen=True)
class Category:
    """Strict category contract for one OWASP LLM Top 10 entry."""

    id: CategoryId
    name: str
    target_capabilities: tuple[str, ...]
    prerequisites: tuple[str, ...]
    not_applicable_when: tuple[str, ...]
    deterministic_evidence: tuple[str, ...]
    required_controls: tuple[str, ...]
    supported_scenarios: tuple[Scenario, ...]
    known_limitations: tuple[str, ...]
    coverage_denominator: str
    allowed_outcomes: tuple[Outcome, ...]
    reserved_remediation_id: str
    reserved_report_ids: tuple[str, ...]
    reserved_sarif_rule_id: str
    current_active_cli_coverage: bool
    active_coverage_source: str
    scaffolding_only: bool
    phase_2b_planned: bool
    full_coverage_claim_allowed: bool
    mode_breadth: ModeBreadth

    def __post_init__(self) -> None:
        if self.id not in CATEGORY_NAMES_2025:
            raise CoverageError(f"unknown OWASP category id {self.id!r}")
        if self.name != CATEGORY_NAMES_2025[self.id]:
            raise CoverageError(f"wrong OWASP category name for {self.id}: {self.name!r}")
        for name, value in (
            ("target_capabilities", self.target_capabilities),
            ("prerequisites", self.prerequisites),
            ("not_applicable_when", self.not_applicable_when),
            ("deterministic_evidence", self.deterministic_evidence),
            ("required_controls", self.required_controls),
            ("known_limitations", self.known_limitations),
            ("reserved_report_ids", self.reserved_report_ids),
        ):
            _require_str_tuple(name, value, min_items=1)
        _require_non_empty("coverage_denominator", self.coverage_denominator)
        _require_outcome_tuple(self.allowed_outcomes)
        for ident in (
            self.reserved_remediation_id,
            self.reserved_sarif_rule_id,
            *self.reserved_report_ids,
        ):
            _require_ai_scan_id(ident)
        _require_unique("reserved_report_ids", self.reserved_report_ids)
        _require_exact_bool("current_active_cli_coverage", self.current_active_cli_coverage)
        _require_exact_bool("scaffolding_only", self.scaffolding_only)
        _require_exact_bool("phase_2b_planned", self.phase_2b_planned)
        _require_exact_bool("full_coverage_claim_allowed", self.full_coverage_claim_allowed)
        _require_non_empty("active_coverage_source", self.active_coverage_source)
        if not isinstance(self.mode_breadth, ModeBreadth):
            raise CoverageError("mode_breadth must be a ModeBreadth")
        if not self.supported_scenarios:
            raise CoverageError("supported_scenarios must be non-empty")
        scenario_ids = tuple(s.id for s in self.supported_scenarios)
        _require_unique("supported_scenarios.id", scenario_ids)
        if self.full_coverage_claim_allowed is not _FULL_CLAIM_ALLOWED:
            raise CoverageError("Phase 2A forbids per-category full coverage claims")
        if self.current_active_cli_coverage != (self.id in _ACTIVE_CATEGORIES):
            raise CoverageError(f"{self.id} current active CLI coverage contradicts shipped wiring")
        if self.id not in _ACTIVE_CATEGORIES:
            if not self.scaffolding_only:
                raise CoverageError(f"{self.id} must be marked scaffolding/planned only")
            if "finding" in self.allowed_outcomes:
                raise CoverageError(f"{self.id} cannot allow finding without active CLI coverage")
        if self.id in _ACTIVE_CATEGORIES and "finding" not in self.allowed_outcomes:
            raise CoverageError(f"{self.id} active coverage must allow findings under controls")
        lowered_denominator = self.coverage_denominator.lower()
        if "full" in lowered_denominator or "comprehensive" in lowered_denominator:
            raise CoverageError("coverage denominator must not imply full/comprehensive coverage")


@dataclass(frozen=True)
class CoverageArithmetic:
    """Aggregate denominator and summary arithmetic semantics."""

    denominator_categories: int
    not_applicable_excluded_from_tested_coverage: bool
    blocked_inconclusive_not_tested_do_not_count_as_tested: bool
    minimum_active_cli_categories_for_full_claim: int
    aggregate_full_coverage_claim_allowed: bool
    rule: str

    def __post_init__(self) -> None:
        _require_positive_int("denominator_categories", self.denominator_categories)
        _require_exact_bool(
            "not_applicable_excluded_from_tested_coverage",
            self.not_applicable_excluded_from_tested_coverage,
        )
        _require_exact_bool(
            "blocked_inconclusive_not_tested_do_not_count_as_tested",
            self.blocked_inconclusive_not_tested_do_not_count_as_tested,
        )
        _require_positive_int(
            "minimum_active_cli_categories_for_full_claim",
            self.minimum_active_cli_categories_for_full_claim,
        )
        _require_exact_bool(
            "aggregate_full_coverage_claim_allowed", self.aggregate_full_coverage_claim_allowed
        )
        _require_non_empty("coverage rule", self.rule)
        if self.denominator_categories != 10:
            raise CoverageError("coverage denominator must be exactly ten OWASP categories")
        if self.minimum_active_cli_categories_for_full_claim != 10:
            raise CoverageError("full claim threshold must require all ten categories")
        if self.aggregate_full_coverage_claim_allowed:
            raise CoverageError("Phase 2A cannot allow aggregate full coverage claims")


@dataclass(frozen=True)
class CoverageMatrix:
    """Loaded OWASP LLM coverage matrix."""

    schema_version: str
    standard: str
    standard_year: int
    matrix_version: str
    categories: tuple[Category, ...]
    coverage_arithmetic: CoverageArithmetic
    content_sha256: str

    def __post_init__(self) -> None:
        if self.schema_version != "owasp-llm-coverage-v1":
            raise CoverageError("unsupported OWASP matrix schema_version")
        if self.standard != "OWASP Top 10 for LLM Applications":
            raise CoverageError("unsupported OWASP standard binding")
        if self.standard_year != 2025:
            raise CoverageError("unsupported OWASP standard year")
        if not _VERSION_RE.fullmatch(self.matrix_version):
            raise CoverageError("matrix_version must be semantic version x.y.z")
        if len(self.categories) != 10:
            raise CoverageError("matrix must contain exactly ten categories")
        ids = tuple(c.id for c in self.categories)
        if ids != tuple(CATEGORY_NAMES_2025):
            raise CoverageError("categories must be unique LLM01-LLM10 in order")
        if not isinstance(self.coverage_arithmetic, CoverageArithmetic):
            raise CoverageError("coverage_arithmetic must be CoverageArithmetic")
        if self.coverage_arithmetic.denominator_categories != len(self.categories):
            raise CoverageError("coverage denominator contradicts category count")
        if not re.fullmatch(r"[0-9a-f]{64}", self.content_sha256):
            raise CoverageError("content_sha256 must be lowercase SHA-256 hex")
        all_report_ids = [
            identifier for c in self.categories for identifier in c.reserved_report_ids
        ]
        _require_unique("category report ids", tuple(all_report_ids))
        _require_unique(
            "category sarif ids", tuple(c.reserved_sarif_rule_id for c in self.categories)
        )
        if any(c.full_coverage_claim_allowed for c in self.categories):
            raise CoverageError("category full coverage claim conflicts with aggregate contract")


def load_coverage_matrix() -> CoverageMatrix:
    """Load the packaged OWASP LLM Top 10 2025 coverage matrix."""
    text = resources.files("ai_scan.owasp").joinpath("llm-top10-2025-v1.json").read_text(
        encoding="utf-8"
    )
    return load_coverage_matrix_text(text)


def load_coverage_matrix_text(text: str) -> CoverageMatrix:
    """Load and validate an OWASP matrix from strict JSON text."""
    try:
        raw = load_json_strict(text)
    except ConfigError as exc:
        raise CoverageError(str(exc)) from exc
    if not isinstance(raw, dict):
        raise CoverageError("matrix document must be an object")
    _reject_unknown("matrix", raw, _TOP_LEVEL_KEYS)
    digest = raw.get("content_sha256")
    if not isinstance(digest, str):
        raise CoverageError("content_sha256 must be a string")
    expected = _content_digest(raw)
    if digest != expected:
        raise CoverageError("OWASP matrix content digest mismatch")
    matrix = _matrix_from_raw(raw)
    # Validate again after construction so re-digested semantically impossible
    # states fail even when the SHA-256 value matches their modified bytes.
    if matrix.content_sha256 != expected:
        raise CoverageError("OWASP matrix digest changed during domain construction")
    return matrix


def coverage_summary(matrix: CoverageMatrix | None = None) -> dict[str, object]:
    """Return deterministic aggregate coverage arithmetic for the shipped matrix."""
    matrix = matrix or load_coverage_matrix()
    active = [c for c in matrix.categories if c.current_active_cli_coverage]
    blocked = [c for c in matrix.categories if "blocked" in c.allowed_outcomes]
    not_tested = [c for c in matrix.categories if "not_tested" in c.allowed_outcomes]
    finding = [c for c in matrix.categories if "finding" in c.allowed_outcomes]
    return {
        "standard": f"{matrix.standard} {matrix.standard_year}",
        "matrix_version": matrix.matrix_version,
        "categories_total": len(matrix.categories),
        "denominator_categories": matrix.coverage_arithmetic.denominator_categories,
        "active_end_to_end_categories": len(active),
        "tested_coverage_categories": len(active),
        "finding_capable_categories": len(finding),
        "blocked_categories": len(blocked),
        "not_tested_categories": len(not_tested),
        "not_applicable_excluded_from_tested_coverage": (
            matrix.coverage_arithmetic.not_applicable_excluded_from_tested_coverage
        ),
        "full_coverage_claim_allowed": (
            matrix.coverage_arithmetic.aggregate_full_coverage_claim_allowed
        ),
    }


def render_coverage_summary(matrix: CoverageMatrix | None = None) -> str:
    """Render a deterministic operator-facing summary; no target or transport."""
    matrix = matrix or load_coverage_matrix()
    summary = coverage_summary(matrix)
    lines = [
        f"{matrix.standard} {matrix.standard_year} coverage matrix v{matrix.matrix_version}",
        "AI-Scan does not claim full OWASP coverage or compliance from this partial matrix.",
        (
            "Active end-to-end CLI categories: "
            f"{summary['active_end_to_end_categories']}/{summary['denominator_categories']}"
        ),
        "Blocked, inconclusive, not_tested, and not_applicable outcomes do not "
        "inflate tested coverage.",
    ]
    for category in matrix.categories:
        active = "active-cli" if category.current_active_cli_coverage else "not-active-cli"
        outcomes = ",".join(category.allowed_outcomes)
        lines.append(f"{category.id} {category.name}: {active}; outcomes={outcomes}")
    return "\n".join(lines)


def matrix_document(matrix: CoverageMatrix | None = None) -> dict[str, object]:
    """Return a deterministic JSON-serializable representation of the matrix."""
    matrix = matrix or load_coverage_matrix()
    return _matrix_to_raw(matrix)


_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "standard",
        "standard_year",
        "matrix_version",
        "coverage_arithmetic",
        "categories",
        "content_sha256",
    }
)
_ARITHMETIC_KEYS = frozenset(
    {
        "denominator_categories",
        "not_applicable_excluded_from_tested_coverage",
        "blocked_inconclusive_not_tested_do_not_count_as_tested",
        "minimum_active_cli_categories_for_full_claim",
        "aggregate_full_coverage_claim_allowed",
        "rule",
    }
)
_CATEGORY_KEYS = frozenset(
    {
        "id",
        "name",
        "target_capabilities",
        "prerequisites",
        "not_applicable_when",
        "deterministic_evidence",
        "required_controls",
        "supported_scenarios",
        "known_limitations",
        "coverage_denominator",
        "allowed_outcomes",
        "reserved_remediation_id",
        "reserved_report_ids",
        "reserved_sarif_rule_id",
        "current_active_cli_coverage",
        "active_coverage_source",
        "scaffolding_only",
        "phase_2b_planned",
        "full_coverage_claim_allowed",
        "mode_breadth",
    }
)
_SCENARIO_KEYS = frozenset({"id", "name", "active_cli", "status", "evidence", "controls"})
_MODE_BREADTH_KEYS = frozenset({"reliable", "kitchen_sink"})


def _matrix_from_raw(raw: dict[str, Any]) -> CoverageMatrix:
    arithmetic_raw = _object(raw.get("coverage_arithmetic"), "coverage_arithmetic")
    _reject_unknown("coverage_arithmetic", arithmetic_raw, _ARITHMETIC_KEYS)
    categories_raw = _list(raw.get("categories"), "categories")
    categories = tuple(_category_from_raw(_object(item, "category")) for item in categories_raw)
    return CoverageMatrix(
        schema_version=_string(raw.get("schema_version"), "schema_version"),
        standard=_string(raw.get("standard"), "standard"),
        standard_year=_int(raw.get("standard_year"), "standard_year"),
        matrix_version=_string(raw.get("matrix_version"), "matrix_version"),
        categories=categories,
        coverage_arithmetic=CoverageArithmetic(
            denominator_categories=_int(
                arithmetic_raw.get("denominator_categories"), "denominator_categories"
            ),
            not_applicable_excluded_from_tested_coverage=_bool(
                arithmetic_raw.get("not_applicable_excluded_from_tested_coverage"),
                "not_applicable_excluded_from_tested_coverage",
            ),
            blocked_inconclusive_not_tested_do_not_count_as_tested=_bool(
                arithmetic_raw.get("blocked_inconclusive_not_tested_do_not_count_as_tested"),
                "blocked_inconclusive_not_tested_do_not_count_as_tested",
            ),
            minimum_active_cli_categories_for_full_claim=_int(
                arithmetic_raw.get("minimum_active_cli_categories_for_full_claim"),
                "minimum_active_cli_categories_for_full_claim",
            ),
            aggregate_full_coverage_claim_allowed=_bool(
                arithmetic_raw.get("aggregate_full_coverage_claim_allowed"),
                "aggregate_full_coverage_claim_allowed",
            ),
            rule=_string(arithmetic_raw.get("rule"), "rule"),
        ),
        content_sha256=_string(raw.get("content_sha256"), "content_sha256"),
    )


def _category_from_raw(raw: dict[str, Any]) -> Category:
    _reject_unknown("category", raw, _CATEGORY_KEYS)
    breadth_raw = _object(raw.get("mode_breadth"), "mode_breadth")
    _reject_unknown("mode_breadth", breadth_raw, _MODE_BREADTH_KEYS)
    scenarios = tuple(
        _scenario_from_raw(_object(item, "scenario"))
        for item in _list(raw.get("supported_scenarios"), "supported_scenarios")
    )
    return Category(
        id=_category_id(raw.get("id")),
        name=_string(raw.get("name"), "name"),
        target_capabilities=_str_tuple(raw.get("target_capabilities"), "target_capabilities"),
        prerequisites=_str_tuple(raw.get("prerequisites"), "prerequisites"),
        not_applicable_when=_str_tuple(raw.get("not_applicable_when"), "not_applicable_when"),
        deterministic_evidence=_str_tuple(
            raw.get("deterministic_evidence"), "deterministic_evidence"
        ),
        required_controls=_str_tuple(raw.get("required_controls"), "required_controls"),
        supported_scenarios=scenarios,
        known_limitations=_str_tuple(raw.get("known_limitations"), "known_limitations"),
        coverage_denominator=_string(raw.get("coverage_denominator"), "coverage_denominator"),
        allowed_outcomes=_outcome_tuple(raw.get("allowed_outcomes"), "allowed_outcomes"),
        reserved_remediation_id=_string(
            raw.get("reserved_remediation_id"), "reserved_remediation_id"
        ),
        reserved_report_ids=_str_tuple(raw.get("reserved_report_ids"), "reserved_report_ids"),
        reserved_sarif_rule_id=_string(
            raw.get("reserved_sarif_rule_id"), "reserved_sarif_rule_id"
        ),
        current_active_cli_coverage=_bool(
            raw.get("current_active_cli_coverage"), "current_active_cli_coverage"
        ),
        active_coverage_source=_string(raw.get("active_coverage_source"), "active_coverage_source"),
        scaffolding_only=_bool(raw.get("scaffolding_only"), "scaffolding_only"),
        phase_2b_planned=_bool(raw.get("phase_2b_planned"), "phase_2b_planned"),
        full_coverage_claim_allowed=_bool(
            raw.get("full_coverage_claim_allowed"), "full_coverage_claim_allowed"
        ),
        mode_breadth=ModeBreadth(
            reliable=_str_tuple(breadth_raw.get("reliable"), "mode_breadth.reliable"),
            kitchen_sink=_str_tuple(
                breadth_raw.get("kitchen_sink"), "mode_breadth.kitchen_sink"
            ),
        ),
    )


def _scenario_from_raw(raw: dict[str, Any]) -> Scenario:
    _reject_unknown("scenario", raw, _SCENARIO_KEYS)
    return Scenario(
        id=_string(raw.get("id"), "scenario.id"),
        name=_string(raw.get("name"), "scenario.name"),
        active_cli=_bool(raw.get("active_cli"), "scenario.active_cli"),
        status=_outcome(raw.get("status"), "scenario.status"),
        evidence=_string(raw.get("evidence"), "scenario.evidence"),
        controls=_str_tuple(raw.get("controls"), "scenario.controls"),
    )


def _matrix_to_raw(matrix: CoverageMatrix) -> dict[str, object]:
    return {
        "schema_version": matrix.schema_version,
        "standard": matrix.standard,
        "standard_year": matrix.standard_year,
        "matrix_version": matrix.matrix_version,
        "coverage_arithmetic": {
            "denominator_categories": matrix.coverage_arithmetic.denominator_categories,
            "not_applicable_excluded_from_tested_coverage": (
                matrix.coverage_arithmetic.not_applicable_excluded_from_tested_coverage
            ),
            "blocked_inconclusive_not_tested_do_not_count_as_tested": (
                matrix.coverage_arithmetic.blocked_inconclusive_not_tested_do_not_count_as_tested
            ),
            "minimum_active_cli_categories_for_full_claim": (
                matrix.coverage_arithmetic.minimum_active_cli_categories_for_full_claim
            ),
            "aggregate_full_coverage_claim_allowed": (
                matrix.coverage_arithmetic.aggregate_full_coverage_claim_allowed
            ),
            "rule": matrix.coverage_arithmetic.rule,
        },
        "categories": [
            {
                "id": c.id,
                "name": c.name,
                "target_capabilities": list(c.target_capabilities),
                "prerequisites": list(c.prerequisites),
                "not_applicable_when": list(c.not_applicable_when),
                "deterministic_evidence": list(c.deterministic_evidence),
                "required_controls": list(c.required_controls),
                "supported_scenarios": [
                    {
                        "id": s.id,
                        "name": s.name,
                        "active_cli": s.active_cli,
                        "status": s.status,
                        "evidence": s.evidence,
                        "controls": list(s.controls),
                    }
                    for s in c.supported_scenarios
                ],
                "known_limitations": list(c.known_limitations),
                "coverage_denominator": c.coverage_denominator,
                "allowed_outcomes": list(c.allowed_outcomes),
                "reserved_remediation_id": c.reserved_remediation_id,
                "reserved_report_ids": list(c.reserved_report_ids),
                "reserved_sarif_rule_id": c.reserved_sarif_rule_id,
                "current_active_cli_coverage": c.current_active_cli_coverage,
                "active_coverage_source": c.active_coverage_source,
                "scaffolding_only": c.scaffolding_only,
                "phase_2b_planned": c.phase_2b_planned,
                "full_coverage_claim_allowed": c.full_coverage_claim_allowed,
                "mode_breadth": {
                    "reliable": list(c.mode_breadth.reliable),
                    "kitchen_sink": list(c.mode_breadth.kitchen_sink),
                },
            }
            for c in matrix.categories
        ],
        "content_sha256": matrix.content_sha256,
    }


def _content_digest(raw: dict[str, Any]) -> str:
    clone = dict(raw)
    clone.pop("content_sha256", None)
    encoded = json.dumps(clone, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _reject_unknown(path: str, raw: dict[str, Any], allowed: frozenset[str]) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise CoverageError(f"{path}: unknown fields {unknown}")
    missing = sorted(allowed - set(raw))
    if missing:
        raise CoverageError(f"{path}: missing fields {missing}")


def _object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageError(f"{name} must be an object")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise CoverageError(f"{name} must be a list")
    return value


def _string(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise CoverageError(f"{name} must be a string")
    _require_non_empty(name, value)
    return value


def _bool(value: Any, name: str) -> bool:
    if value is not True and value is not False:
        raise CoverageError(f"{name} must be a boolean")
    return value


def _int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CoverageError(f"{name} must be an integer")
    return value


def _category_id(value: Any) -> CategoryId:
    if value not in CATEGORY_NAMES_2025:
        raise CoverageError(f"unknown category id {value!r}")
    return cast(CategoryId, value)


def _str_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CoverageError(f"{name} must be a list")
    result = tuple(_string(item, name) for item in value)
    _require_str_tuple(name, result, min_items=1)
    return result


def _outcome(value: Any, name: str) -> Outcome:
    if value not in _ALLOWED_OUTCOMES:
        raise CoverageError(f"{name} has invalid outcome {value!r}")
    return cast(Outcome, value)


def _outcome_tuple(value: Any, name: str) -> tuple[Outcome, ...]:
    if not isinstance(value, list):
        raise CoverageError(f"{name} must be a list")
    result: tuple[Outcome, ...] = tuple(_outcome(item, name) for item in value)
    _require_outcome_tuple(result)
    return result


def _require_non_empty(name: str, value: str) -> None:
    if not value.strip():
        raise CoverageError(f"{name} must be non-empty")


def _require_exact_bool(name: str, value: object) -> None:
    if value is not True and value is not False:
        raise CoverageError(f"{name} must be a boolean")


def _require_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CoverageError(f"{name} must be an integer")
    if value <= 0:
        raise CoverageError(f"{name} must be positive")


def _require_str_tuple(name: str, value: object, *, min_items: int) -> None:
    if not isinstance(value, tuple):
        raise CoverageError(f"{name} must be an immutable tuple")
    if len(value) < min_items:
        raise CoverageError(f"{name} must have at least {min_items} item(s)")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise CoverageError(f"{name} items must be non-empty strings")


def _require_outcome(value: object) -> None:
    if value not in _ALLOWED_OUTCOMES:
        raise CoverageError(f"invalid outcome {value!r}")


def _require_outcome_tuple(value: object) -> None:
    if not isinstance(value, tuple) or not value:
        raise CoverageError("allowed_outcomes must be a non-empty tuple")
    for item in value:
        _require_outcome(item)
    _require_unique("allowed_outcomes", value)


def _require_identifier(name: str, value: str, *, prefix: str) -> None:
    if not value.startswith(prefix) or not re.fullmatch(r"[a-z0-9_.-]+", value):
        raise CoverageError(f"{name} is malformed: {value!r}")


def _require_ai_scan_id(value: str) -> None:
    if not _ID_RE.fullmatch(value):
        raise CoverageError(f"malformed AI-Scan OWASP identifier: {value!r}")


def _require_unique(name: str, values: tuple[object, ...]) -> None:
    if len(set(values)) != len(values):
        raise CoverageError(f"{name} values must be unique")


__all__ = [
    "CATEGORY_NAMES_2025",
    "Category",
    "CoverageArithmetic",
    "CoverageError",
    "CoverageMatrix",
    "ModeBreadth",
    "Scenario",
    "coverage_summary",
    "load_coverage_matrix",
    "load_coverage_matrix_text",
    "matrix_document",
    "render_coverage_summary",
]
