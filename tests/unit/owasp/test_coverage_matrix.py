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
    assert matrix.matrix_version == "1.2.0"
    assert {c.id: c.name for c in matrix.categories} == EXPECTED_NAMES
    assert CATEGORY_NAMES_2025 == EXPECTED_NAMES


def test_current_state_is_honest_about_active_end_to_end_coverage() -> None:
    matrix = load_coverage_matrix()
    categories = {c.id: c for c in matrix.categories}
    assert categories["LLM01"].current_active_cli_coverage is True
    assert categories["LLM02"].current_active_cli_coverage is True
    assert categories["LLM03"].current_active_cli_coverage is True
    assert categories["LLM04"].current_active_cli_coverage is True
    assert categories["LLM05"].current_active_cli_coverage is True
    assert categories["LLM03"].scaffolding_only is False
    assert categories["LLM02"].scaffolding_only is False
    assert categories["LLM04"].scaffolding_only is False
    assert categories["LLM05"].scaffolding_only is False
    inactive_ids = ("LLM06", "LLM07", "LLM08", "LLM09", "LLM10")
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
    assert summary["active_end_to_end_categories"] == 5
    assert summary["active_end_to_end_categories"] < summary["categories_total"]


def test_llm01_active_breadth_is_bound_to_public_compiled_plans() -> None:
    target = normalize_target("http://127.0.0.1:8080/chat")
    plans = {
        mode: compile_plan(target, mode)
        for mode in ("reliable", "kitchen-sink")
    }
    reliable_entry = (
        "direct-injection-reliable only: 12 compiled cases covering "
        "encoding, instruction_conflict, role_confusion, and system_boundary"
    )
    kitchen_entry = (
        "direct-injection-reliable plus direct-injection-kitchen: 24 compiled "
        "cases adding bounded direct LLM01 payload_splitting, markdown_injection, "
        "encoded_envelope, multilingual_directive, role_play_boundary, and "
        "bounded_adaptive_retry families"
    )
    matrix = load_coverage_matrix()
    llm01 = next(c for c in matrix.categories if c.id == "LLM01")

    assert {pack_id for pack_id, _version, _digest in plans["reliable"].packs} == {
        "direct-injection-reliable",
        "prompt-disclosure-reliable",
    }
    assert {pack_id for pack_id, _version, _digest in plans["kitchen-sink"].packs} == {
        "direct-injection-reliable",
        "direct-injection-kitchen",
        "prompt-disclosure-reliable",
        "prompt-disclosure-kitchen",
    }
    assert len(plans["reliable"].cases) == 16
    assert len(plans["kitchen-sink"].cases) == 32
    assert tuple(sorted({case.family for case in plans["reliable"].attack_cases()})) == (
        "encoding",
        "instruction_conflict",
        "prompt_disclosure_debug_config",
        "prompt_disclosure_system_text",
        "role_confusion",
        "system_boundary",
    )
    assert tuple(sorted({case.family for case in plans["kitchen-sink"].attack_cases()})) == (
        "bounded_adaptive_retry",
        "encoded_envelope",
        "encoding",
        "instruction_conflict",
        "markdown_injection",
        "multilingual_directive",
        "payload_splitting",
        "prompt_disclosure_boundary",
        "prompt_disclosure_debug_config",
        "prompt_disclosure_system_text",
        "prompt_disclosure_translation",
        "role_confusion",
        "role_play_boundary",
        "system_boundary",
    )

    assert llm01.active_coverage_source == (
        "public Reliable plans compile direct-injection-reliable only; Kitchen "
        "Sink public plans additionally compile direct-injection-kitchen for "
        "bounded direct LLM01 breadth. Both use exact final-assistant canary "
        "execution, matched clean controls, repeatability, plan-bound request "
        "accounting, and mode-specific limits."
    )
    assert llm01.mode_breadth.reliable == (reliable_entry,)
    assert llm01.mode_breadth.kitchen_sink == (kitchen_entry,)
    categories_raw = cast(list[object], _doc()["categories"])
    llm01_text = json.dumps(categories_raw[0], sort_keys=True).lower()
    assert "indirect" not in llm01.active_coverage_source.lower()
    assert "multi-turn" not in llm01.active_coverage_source.lower()
    assert "multilingual_directive" in llm01_text
    assert "bounded_adaptive_retry" in llm01_text


def test_llm03_active_claim_is_limited_to_offline_manifest_cli() -> None:
    matrix = load_coverage_matrix()
    llm03 = next(c for c in matrix.categories if c.id == "LLM03")

    assert llm03.current_active_cli_coverage is True
    assert llm03.scaffolding_only is False
    assert "finding" in llm03.allowed_outcomes
    assert "partial offline LLM03 manifest assessment" in llm03.active_coverage_source
    assert "constructs no transport" in llm03.active_coverage_source
    assert "never imports, deserializes, loads, hashes, or executes model artifacts" in (
        llm03.active_coverage_source
    )
    limitations = " ".join(llm03.known_limitations).lower()
    for gap in (
        "no live target/model behavior execution",
        "registry lookup",
        "signature or attestation",
        "dataset-content inspection",
        "runtime dependency loading",
    ):
        assert gap in limitations
    assert llm03.mode_breadth.reliable == (
        "supply-chain-audit: bounded offline manifest validation for declared model, "
        "dataset, plugin, and dependency provenance fields",
    )


def test_llm04_active_claim_is_limited_to_external_retrieval_protocol_cli() -> None:
    matrix = load_coverage_matrix()
    llm04 = next(c for c in matrix.categories if c.id == "LLM04")

    assert llm04.current_active_cli_coverage is True
    assert llm04.scaffolding_only is False
    assert "finding" in llm04.allowed_outcomes
    assert "partial active LLM04 controlled retrieval-poisoning protocol" in (
        llm04.active_coverage_source
    )
    assert "exact --target URL" in llm04.active_coverage_source
    assert "scope-safe transport" in llm04.active_coverage_source
    assert "independently running service implements state" in llm04.active_coverage_source
    limitations = " ".join(llm04.known_limitations).lower()
    assert "explicit service-side or operator reconciliation" in limitations
    for gap in (
        "model-weight poisoning",
        "fine-tuning poisoning",
        "production rag",
        "embeddings",
        "real target/model behavior beyond the controlled protocol",
    ):
        assert gap in limitations
    assert llm04.mode_breadth.reliable == (
        "data-poisoning-audit: active fixed HTTP retrieval fixture protocol with "
        "scanner-generated marker, strict operation order, clean controls, namespace "
        "isolation, and verified cleanup",
    )


def test_llm05_active_claim_is_limited_to_offline_declaration_assessment() -> None:
    matrix = load_coverage_matrix()
    llm05 = next(c for c in matrix.categories if c.id == "LLM05")

    assert llm05.current_active_cli_coverage is True
    assert llm05.scaffolding_only is False
    assert "finding" in llm05.allowed_outcomes
    assert "partial offline LLM05 declaration assessment" in llm05.active_coverage_source
    assert "output-handling-audit" in llm05.active_coverage_source
    assert "never opens or executes declared implementation references" in (
        llm05.active_coverage_source
    )
    limitations = " ".join(llm05.known_limitations).lower()
    for gap in (
        "runtime rendering or execution",
        "browser behavior",
        "database or process effects",
        "prompt injection",
        "downstream implementation verification",
        "no full llm05 coverage",
    ):
        assert gap in limitations
    assert llm05.mode_breadth.reliable == (
        "output-handling-audit: bounded offline declaration checks for HTML/DOM, Markdown, "
        "SQL, shell/process, code/template, logging/observability, and structured/API sinks",
    )


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
        cat = doc["categories"][5]  # LLM06 excessive agency
        cat["current_active_cli_coverage"] = True

    def full_claim_from_partial(doc: dict[str, object]) -> None:
        cat = doc["categories"][0]
        cat["full_coverage_claim_allowed"] = True

    def finding_without_active_coverage(doc: dict[str, object]) -> None:
        cat = doc["categories"][5]
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
