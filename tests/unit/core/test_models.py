"""Milestone 1: core domain status/severity types and finding skeleton."""

from __future__ import annotations

import json

import pytest

from ai_scan.core.models import (
    DeterminismClass,
    Finding,
    FindingStatus,
    PackTrust,
    Severity,
)


def test_finding_status_has_seven_distinct_states() -> None:
    values = {
        FindingStatus.CONFIRMED,
        FindingStatus.LIKELY,
        FindingStatus.SUSPECTED,
        FindingStatus.NOT_OBSERVED,
        FindingStatus.INCONCLUSIVE,
        FindingStatus.BLOCKED,
        FindingStatus.NOT_TESTED,
    }
    assert len(values) == 7
    assert {s.value for s in values} == {
        "confirmed",
        "likely",
        "suspected",
        "not_observed",
        "inconclusive",
        "blocked",
        "not_tested",
    }


def test_severity_has_five_distinct_levels() -> None:
    values = {
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFORMATIONAL,
    }
    assert len(values) == 5
    assert {s.value for s in values} == {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }


def test_determinism_classes() -> None:
    assert {d.value for d in DeterminismClass} == {
        "deterministic",
        "statistical",
        "heuristic",
        "judge",
    }


def test_pack_trust_levels() -> None:
    assert {p.value for p in PackTrust} == {"builtin", "signed", "local_approved"}


def test_status_and_severity_are_independent() -> None:
    # Confidence (status) and severity are orthogonal: a suspected lead may carry
    # a critical severity without being a confirmed critical vulnerability.
    finding = Finding(
        id="f-1",
        attack_id="attack.example",
        title="Example",
        status=FindingStatus.SUSPECTED,
        severity=Severity.CRITICAL,
        summary="lead",
        evidence_ids=("e-1",),
    )
    data = finding.to_dict()
    assert data["status"] == "suspected"
    assert data["severity"] == "critical"
    # The two fields serialize under distinct keys and do not constrain each other.
    assert data["status"] != data["severity"]
    json.dumps(data)


def test_finding_is_frozen() -> None:
    finding = Finding(
        id="f-1",
        attack_id="a",
        title="t",
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        summary="s",
        evidence_ids=(),
    )
    import dataclasses

    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        finding.status = FindingStatus.NOT_OBSERVED  # type: ignore[misc]


def _valid_finding(**overrides):
    kwargs = dict(
        id="f-1",
        attack_id="a",
        title="t",
        status=FindingStatus.CONFIRMED,
        severity=Severity.HIGH,
        summary="s",
        evidence_ids=(),
    )
    kwargs.update(overrides)
    return Finding(**kwargs)


def test_finding_normalizes_evidence_ids_to_tuple() -> None:
    f = _valid_finding(evidence_ids=["e-1", "e-2"])
    assert f.evidence_ids == ("e-1", "e-2")
    assert isinstance(f.evidence_ids, tuple)


def test_finding_rejects_invalid_evidence_ids() -> None:
    from ai_scan.core.errors import ValidationError

    with pytest.raises(ValidationError):
        _valid_finding(evidence_ids=["ok", ""])  # empty id
    with pytest.raises(ValidationError):
        _valid_finding(evidence_ids=[1, 2])  # non-string
    with pytest.raises(ValidationError):
        _valid_finding(evidence_ids="e-1")  # a bare string is not an id list


@pytest.mark.parametrize("field_name", ["id", "attack_id", "title"])
def test_finding_rejects_empty_strings(field_name: str) -> None:
    from ai_scan.core.errors import ValidationError

    with pytest.raises(ValidationError):
        _valid_finding(**{field_name: ""})
    with pytest.raises(ValidationError):
        _valid_finding(**{field_name: 123})


def test_finding_rejects_wrong_enum_types() -> None:
    from ai_scan.core.errors import ValidationError

    with pytest.raises(ValidationError):
        _valid_finding(status=Severity.HIGH)  # severity where status expected
    with pytest.raises(ValidationError):
        _valid_finding(severity=FindingStatus.CONFIRMED)
    with pytest.raises(ValidationError):
        _valid_finding(status="confirmed")  # raw string, not enum


def test_legacy_models_reexport_core_types() -> None:
    # The legacy `ai_scan.models` path re-exports the shared core types during
    # the refactor, without breaking existing legacy symbols.
    from ai_scan import models as legacy

    assert legacy.FindingStatus is FindingStatus
    assert legacy.Severity is Severity
    assert legacy.Finding is Finding
    # Existing legacy types remain importable.
    assert hasattr(legacy, "FingerprintResult")
    assert hasattr(legacy, "Probe")
