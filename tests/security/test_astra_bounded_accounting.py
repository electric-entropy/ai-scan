"""Failed standalone trials retain the trusted physical ledger delta."""
import pytest

from ai_scan import injection
from ai_scan.injection import ExchangeOutcome, generate_canary, run_injection_pack
from tests.security.test_architecture_accounting import _Counter, _pack


@pytest.mark.parametrize("acquisitions", [0, 1, 3])
@pytest.mark.parametrize("raises", [False, True])
@pytest.mark.parametrize("failed_kind", ["control", "attack"])
def test_failed_pack_trial_exact_delta(monkeypatch, acquisitions, raises, failed_kind):
    counter = _Counter()
    token = generate_canary()
    control_evidence = []
    original = injection.control_result

    def observe(outcomes, canary, minimum):
        control_evidence.extend(outcomes)
        return original(outcomes, canary, minimum)

    monkeypatch.setattr(injection, "control_result", observe)

    def responder(case):
        kind = "attack" if "{canary}" in case.template else "control"
        if kind == failed_kind:
            for _ in range(acquisitions):
                counter.count += 1  # retry acquisitions, including full exhaustion
            if raises:
                raise RuntimeError("offline exhausted")
            return ExchangeOutcome(body="", transport_ok=False, attempts=999)
        counter.count += 1
        return ExchangeOutcome(body=token if kind == "attack" else "benign", attempts=999)

    result = run_injection_pack(_pack(), responder, canary=token, goal="offline",
                                physical_request_count=counter)
    attacks = [trial for finding in result.findings for trial in finding.evidence]
    assert len(control_evidence) == len(attacks) == 1
    failed = control_evidence if failed_kind == "control" else attacks
    assert failed[0].attempts == acquisitions
    assert not failed[0].transport_ok
    assert result.request_count == counter.count == acquisitions + 1
    assert sum(o.attempts for o in control_evidence + attacks) == result.request_count
    assert all(f.status.value != "confirmed" for f in result.findings)
