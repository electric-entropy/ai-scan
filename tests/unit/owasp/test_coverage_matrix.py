"""OWASP LLM 2025 applicability/evidence matrix contract."""

from __future__ import annotations

import json
from dataclasses import replace
from importlib import resources
from typing import cast

import pytest

from ai_scan.orchestration import compile_plan
from ai_scan.owasp_llm import (
    CATEGORY_NAMES_2025,
    CoverageError,
    coverage_summary,
    load_coverage_matrix,
    load_coverage_matrix_text,
    render_coverage_summary,
)
from ai_scan.targets import normalize_target

EXPECTED_NAMES = {
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


def _doc() -> dict[str, object]:
    text = resources.files("ai_scan.owasp").joinpath("llm-top10-2025-v1.json").read_text(
        encoding="utf-8"
    )
    parsed = json.loads(text)
    assert isinstance(parsed, dict)
    return parsed


def _load_mutated(mutator) -> None:  # type: ignore[no-untyped-def]
    doc = _doc()
    mutator(doc)
    load_coverage_matrix_text(json.dumps(doc, sort_keys=True, allow_nan=False))


def test_packaged_matrix_loads_all_official_2025_categories() -> None:
    matrix = load_coverage_matrix()
    assert matrix.standard == "OWASP Top 10 for LLM Applications"
    assert matrix.standard_year == 2025
    assert matrix.matrix_version == "1.0.0"
    assert {c.id: c.name for c in matrix.categories} == EXPECTED_NAMES
    assert CATEGORY_NAMES_2025 == EXPECTED_NAMES


def test_current_state_is_honest_about_active_end_to_end_coverage() -> None:
    matrix = load_coverage_matrix()
    categories = {c.id: c for c in matrix.categories}
    assert categories["LLM01"].current_active_cli_coverage is True
    inactive_ids = ("LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10")
    for category_id in inactive_ids:
        category = categories[category_id]
        assert category.current_active_cli_coverage is False
        assert category.full_coverage_claim_allowed is False
        assert any(
            "Phase 2B" in item or "unsupported" in item
            for item in category.known_limitations
        )
    assert "capability-gated" in categories["LLM06"].active_coverage_source
    assert "current public CLI" in categories["LLM06"].active_coverage_source
    assert "capability-gated" in categories["LLM07"].active_coverage_source
    assert "current public CLI" in categories["LLM07"].active_coverage_source


def test_matrix_identifiers_are_reserved_not_runtime_mappings() -> None:
    matrix = load_coverage_matrix()
    category = matrix.categories[0]
    assert category.reserved_remediation_id.startswith("ai-scan.owasp.LLM01.")
    assert category.reserved_report_ids
    assert category.reserved_sarif_rule_id.startswith("ai-scan.owasp.LLM01.")
    categories_raw = _doc()["categories"]
    assert isinstance(categories_raw, list)
    raw = categories_raw[0]
    assert isinstance(raw, dict)
    assert "reserved_remediation_id" in raw
    assert "reserved_report_ids" in raw
    assert "reserved_sarif_rule_id" in raw
    assert "remediation_id" not in raw
    assert "report_ids" not in raw
    assert "sarif_rule_id" not in raw


def test_reliable_and_kitchen_sink_breadth_differ_without_full_claims() -> None:
    matrix = load_coverage_matrix()
    for category in matrix.categories:
        assert category.full_coverage_claim_allowed is False
    summary = coverage_summary(matrix)
    assert summary["categories_total"] == 10
    assert summary["full_coverage_claim_allowed"] is False
    assert summary["active_end_to_end_categories"] < summary["categories_total"]


def test_llm01_active_breadth_is_bound_to_public_compiled_plans() -> None:
    target = normalize_target("http://127.0.0.1:8080/chat")
    plans = {
        mode: compile_plan(target, mode)
        for mode in ("reliable", "kitchen-sink")
    }
    expected_entry = (
        "direct-injection-reliable only: 12 compiled cases covering "
        "encoding, instruction_conflict, role_confusion, and system_boundary"
    )
    matrix = load_coverage_matrix()
    llm01 = next(c for c in matrix.categories if c.id == "LLM01")

    for plan in plans.values():
        assert {pack_id for pack_id, _version, _digest in plan.packs} == {
            "direct-injection-reliable"
        }
        assert len(plan.cases) == 12
        assert tuple(sorted({case.family for case in plan.attack_cases()})) == (
            "encoding",
            "instruction_conflict",
            "role_confusion",
            "system_boundary",
        )

    assert llm01.active_coverage_source == (
        "public Reliable and Kitchen Sink plans currently compile only the "
        "direct-injection-reliable pack: 12 cases across encoding, "
        "instruction_conflict, role_confusion, and system_boundary"
    )
    assert llm01.mode_breadth.reliable == (expected_entry,)
    assert llm01.mode_breadth.kitchen_sink == (expected_entry,)
    categories_raw = cast(list[object], _doc()["categories"])
    llm01_text = json.dumps(categories_raw[0], sort_keys=True).lower()
    for term in ("indirect", "adaptive", "multilingual", "direct plus"):
        assert term not in llm01.active_coverage_source.lower()
        assert term not in " ".join(llm01.mode_breadth.reliable).lower()
        assert term not in " ".join(llm01.mode_breadth.kitchen_sink).lower()
        assert term not in llm01_text or "phase 2b" in llm01_text


def test_coverage_arithmetic_does_not_inflate_from_gaps_or_not_applicable() -> None:
    matrix = load_coverage_matrix()
    summary = coverage_summary(matrix)
    assert summary["denominator_categories"] == 10
    assert summary["tested_coverage_categories"] == summary["active_end_to_end_categories"]
    assert summary["blocked_categories"] >= 1
    assert summary["not_tested_categories"] >= 1
    assert summary["not_applicable_excluded_from_tested_coverage"] is True


def test_deterministic_summary_rendering() -> None:
    matrix = load_coverage_matrix()
    first = render_coverage_summary(matrix)
    second = render_coverage_summary(matrix)
    assert first == second
    assert "OWASP Top 10 for LLM Applications 2025" in first
    assert "does not claim full OWASP coverage or compliance" in first
    assert "LLM01 Prompt Injection" in first
    assert "LLM10 Unbounded Consumption" in first


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("standard", "Wrong"),
        ("standard_year", 2024),
        ("schema_version", "owasp-llm-coverage-v2"),
        ("matrix_version", "2025"),
    ],
)
def test_top_level_binding_is_strict(field: str, value: object) -> None:
    with pytest.raises(CoverageError):
        _load_mutated(lambda doc: doc.__setitem__(field, value))


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(CoverageError):
        _load_mutated(lambda doc: doc.__setitem__("unexpected", True))


def test_missing_and_duplicate_categories_are_rejected() -> None:
    with pytest.raises(CoverageError):
        _load_mutated(lambda doc: doc.__setitem__("categories", doc["categories"][:-1]))
    with pytest.raises(CoverageError):
        _load_mutated(lambda doc: doc["categories"].append(dict(doc["categories"][0])))  # type: ignore[index,union-attr]


def test_wrong_official_name_is_rejected() -> None:
    with pytest.raises(CoverageError):
        _load_mutated(lambda doc: doc["categories"][0].__setitem__("name", "Jailbreaks"))  # type: ignore[index]


def test_duplicate_scenarios_and_identifiers_are_rejected() -> None:
    def duplicate_scenario(doc: dict[str, object]) -> None:
        cat = doc["categories"][0]  # type: ignore[index]
        cat["supported_scenarios"].append(dict(cat["supported_scenarios"][0]))  # type: ignore[index]

    def duplicate_report_id(doc: dict[str, object]) -> None:
        doc["categories"][1]["reserved_report_ids"][0] = doc["categories"][0][  # type: ignore[index]
            "reserved_report_ids"
        ][0]

    with pytest.raises(CoverageError):
        _load_mutated(duplicate_scenario)
    with pytest.raises(CoverageError):
        _load_mutated(duplicate_report_id)


@pytest.mark.parametrize(
    "bad_id",
    ["owasp.llm01", "AI_SCAN_LLM01", "ai-scan.llm11", "ai-scan.owasp.LLM01 finding"],
)
def test_malformed_reserved_remediation_report_or_sarif_ids_are_rejected(bad_id: str) -> None:
    def mutate(doc: dict[str, object]) -> None:
        doc["categories"][0]["reserved_sarif_rule_id"] = bad_id  # type: ignore[index]

    with pytest.raises(CoverageError):
        _load_mutated(mutate)


def test_invalid_enums_and_types_are_rejected() -> None:
    def invalid_outcome(doc: dict[str, object]) -> None:
        doc["categories"][0].__setitem__("allowed_outcomes", ["finding", "passed"])  # type: ignore[index]

    def bool_as_int(doc: dict[str, object]) -> None:
        doc["categories"][0].__setitem__("current_active_cli_coverage", 1)  # type: ignore[index]

    def invalid_arithmetic(doc: dict[str, object]) -> None:
        doc["coverage_arithmetic"].__setitem__(  # type: ignore[attr-defined]
            "minimum_active_cli_categories_for_full_claim", True
        )

    with pytest.raises(CoverageError):
        _load_mutated(invalid_outcome)
    with pytest.raises(CoverageError):
        _load_mutated(bool_as_int)
    with pytest.raises(CoverageError):
        _load_mutated(invalid_arithmetic)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity", "1e999"])
def test_non_finite_numbers_are_rejected(literal: str) -> None:
    text = resources.files("ai_scan.owasp").joinpath("llm-top10-2025-v1.json").read_text(
        encoding="utf-8"
    )
    text = text.replace("2025", literal, 1)
    with pytest.raises(CoverageError):
        load_coverage_matrix_text(text)


def test_duplicate_json_keys_are_rejected() -> None:
    text = resources.files("ai_scan.owasp").joinpath("llm-top10-2025-v1.json").read_text(
        encoding="utf-8"
    )
    text = text.replace('"schema_version"', '"schema_version", "schema_version"', 1)
    with pytest.raises(CoverageError):
        load_coverage_matrix_text(text)


def test_contradictory_active_or_full_states_are_rejected() -> None:
    def unsupported_marked_active(doc: dict[str, object]) -> None:
        cat = doc["categories"][2]  # LLM03 supply chain
        cat["current_active_cli_coverage"] = True

    def full_claim_from_partial(doc: dict[str, object]) -> None:
        cat = doc["categories"][0]
        cat["full_coverage_claim_allowed"] = True

    def finding_without_active_coverage(doc: dict[str, object]) -> None:
        cat = doc["categories"][2]
        cat["allowed_outcomes"] = ["finding", "tested"]

    for mutator in (
        unsupported_marked_active,
        full_claim_from_partial,
        finding_without_active_coverage,
    ):
        with pytest.raises(CoverageError):
            _load_mutated(mutator)


def test_digest_mismatch_and_redigested_semantic_tamper_are_rejected() -> None:
    with pytest.raises(CoverageError):
        _load_mutated(lambda doc: doc.__setitem__("matrix_version", "1.0.1"))

    doc = _doc()
    doc["content_sha256"] = "0" * 64
    with pytest.raises(CoverageError):
        load_coverage_matrix_text(json.dumps(doc, sort_keys=True, allow_nan=False))


def test_domain_objects_are_immutable_and_defensively_typed() -> None:
    matrix = load_coverage_matrix()
    with pytest.raises(CoverageError):
        replace(matrix.categories[0], current_active_cli_coverage=1)  # type: ignore[arg-type]
    with pytest.raises(CoverageError):
        replace(matrix.categories[0], allowed_outcomes=("finding", "passed"))  # type: ignore[arg-type]
