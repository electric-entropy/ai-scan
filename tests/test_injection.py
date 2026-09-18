"""Tests for the safe, canary-based prompt-injection engine."""

from __future__ import annotations

import json

import pytest

from ai_scan.injection import (
    ExchangeOutcome,
    InjectionCase,
    InjectionError,
    InjectionStatus,
    generate_canary,
    load_payloads,
)
from tests.trusted_engines import run_injection


def _execute_responder():
    """Simulates a target that FOLLOWS the injection: emits only the canary."""

    def respond(case: InjectionCase) -> ExchangeOutcome:
        import re

        m = re.search(r"AISCAN-[0-9A-F]+", case.rendered_prompt)
        token = m.group(0) if m else ""
        return ExchangeOutcome(body=f"{token}")

    return respond


def _echo_responder():
    """Simulates a target that merely REFLECTS the submitted prompt verbatim."""

    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"You said: {case.rendered_prompt}")

    return respond


def _resistant_responder():
    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="I can't help with that request.")

    return respond


def test_load_payloads_has_versioned_families() -> None:
    pack = load_payloads("safe")
    assert pack.version
    assert len(pack.families) >= 4
    names = {f.name for f in pack.families}
    assert {"instruction_conflict", "encoding", "role_confusion", "system_boundary"} <= names


def test_canary_is_unique_per_run() -> None:
    a = generate_canary()
    b = generate_canary()
    assert a != b
    assert a.startswith("AISCAN-")
    assert len(a) >= 16


def test_payloads_contain_no_real_secret_requests() -> None:
    pack = load_payloads("safe")
    banned = ["password", "api_key", "api key", "ssn", "credit card", "private key", "/etc/passwd"]
    for family in pack.families:
        for template in family.templates:
            low = template.lower()
            for term in banned:
                assert term not in low, f"payload requests real secret: {term!r}"


# --- Finding 3: profile allowlist --------------------------------------------


@pytest.mark.parametrize(
    "profile",
    [
        "../safe",
        "/etc/passwd",
        "safe/../safe",
        "packs/safe",
        "aggressive",
        "",
        "safe.json",
    ],
)
def test_profile_allowlist_rejects_paths_and_unknowns(profile: str) -> None:
    with pytest.raises(InjectionError):
        load_payloads(profile)


def test_profile_allowlist_accepts_known_profile() -> None:
    assert load_payloads("safe").version


# --- Finding 5: execution vs. reflection -------------------------------------


def test_single_shot_execution_is_only_potential() -> None:
    canary = generate_canary()
    result = run_injection(
        load_payloads("safe"), _execute_responder(), canary=canary, goal="g"
    )
    assert result.status == InjectionStatus.POTENTIAL
    assert all(f.status == InjectionStatus.POTENTIAL for f in result.findings)
    assert all(f.proof is None for f in result.findings)


def test_mere_reflection_is_not_confirmed() -> None:
    # The echo target reflects the canary but did NOT follow the instruction.
    canary = generate_canary()
    result = run_injection(
        load_payloads("safe"), _echo_responder(), canary=canary, goal="g"
    )
    assert result.status != InjectionStatus.CONFIRMED
    assert all(f.status != InjectionStatus.CONFIRMED for f in result.findings)


def test_resistant_target_not_confirmed() -> None:
    canary = generate_canary()
    result = run_injection(
        load_payloads("safe"), _resistant_responder(), canary=canary, goal="g"
    )
    assert result.status != InjectionStatus.CONFIRMED


def test_wrong_canary_is_not_confirmed() -> None:
    canary = generate_canary()

    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="AISCAN-DEADBEEFDEADBEEF")

    result = run_injection(load_payloads("safe"), respond, canary=canary, goal="x")
    assert result.status != InjectionStatus.CONFIRMED


# --- Finding 6: transport outcome drives classification ----------------------


def test_redirect_outcome_is_inconclusive_not_observed() -> None:
    canary = generate_canary()

    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="", status=302, redirected=True)

    result = run_injection(load_payloads("safe"), respond, canary=canary, goal="x")
    assert result.status == InjectionStatus.INCONCLUSIVE
    assert all(f.status == InjectionStatus.INCONCLUSIVE for f in result.findings)


def test_http_error_outcome_is_inconclusive() -> None:
    canary = generate_canary()

    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="forbidden", status=403)

    result = run_injection(load_payloads("safe"), respond, canary=canary, goal="x")
    assert result.status == InjectionStatus.INCONCLUSIVE


def test_truncated_outcome_is_inconclusive() -> None:
    canary = generate_canary()

    def respond(case: InjectionCase) -> ExchangeOutcome:
        # Even if the canary is present, a truncated response can't confirm.
        return ExchangeOutcome(body=canary, status=200, truncated=True)

    result = run_injection(load_payloads("safe"), respond, canary=canary, goal="x")
    assert result.status == InjectionStatus.INCONCLUSIVE


def test_transport_failure_is_inconclusive() -> None:
    canary = generate_canary()

    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="", transport_ok=False)

    result = run_injection(load_payloads("safe"), respond, canary=canary, goal="x")
    assert result.status == InjectionStatus.INCONCLUSIVE


# --- Finding 7: physical request accounting ----------------------------------


def test_request_count_uses_trusted_fixture_ledger_not_outcome_metadata() -> None:
    canary = generate_canary()

    def respond(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body="no", attempts=2)  # simulate one retry each

    pack = load_payloads("safe")
    result = run_injection(pack, respond, canary=canary, goal="x")
    logical = sum(len(f.templates) for f in pack.families)
    assert result.request_count == logical


def test_total_requests_are_bounded() -> None:
    canary = generate_canary()
    calls = {"n": 0}

    def respond(case: InjectionCase) -> ExchangeOutcome:
        calls["n"] += 1
        return ExchangeOutcome(body="no")

    result = run_injection(
        load_payloads("safe"), respond, canary=canary, goal="x", max_cases=3
    )
    assert calls["n"] <= 3
    assert result.request_count <= 3


def test_statuses_are_distinct_values() -> None:
    values = {
        InjectionStatus.CONFIRMED,
        InjectionStatus.POTENTIAL,
        InjectionStatus.NOT_OBSERVED,
        InjectionStatus.INCONCLUSIVE,
    }
    assert len(values) == 4


def test_result_serializes() -> None:
    canary = generate_canary()
    result = run_injection(load_payloads("safe"), _execute_responder(), canary=canary, goal="x")
    data = result.to_dict()
    json.dumps(data)
    assert data["status"] == "potential"
