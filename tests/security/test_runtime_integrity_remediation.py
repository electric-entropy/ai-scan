"""Runtime-integrity regressions from the bounded Ollama run."""

from __future__ import annotations

import hashlib
import json
import re

import pytest

from ai_scan import cli
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import (
    compile_plan,
    load_checkpoint,
    plan_to_json,
)
from ai_scan.orchestration.checkpoint import CheckpointError
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from ai_scan.transport import BudgetExceededError, HttpResponse, TransportError
from ai_scan.transport.redaction import REDACTED, scrub_provider_envelope
from tests.trusted_engines import run_plan

_CANARY = "AISCAN-RUNTIMEINTEGRITY"


def _plan():  # type: ignore[no-untyped-def]
    return compile_plan(normalize_target("http://127.0.0.1:8000/chat"), "reliable")


def _executing_outcome(case) -> ExchangeOutcome:  # type: ignore[no-untyped-def]
    match = re.search(r"AISCAN-[A-Z0-9_-]+", case.rendered_prompt)
    token = match.group(0) if match else _CANARY
    body = f"executed result: {token}" if "{canary}" in case.template else "benign"
    return ExchangeOutcome(body=body, known_secrets=frozenset({token}))


def test_completed_checkpoint_rejects_resume_with_substituted_canary(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "completed.ckpt"

    live = run_plan(plan, _executing_outcome, canary=_CANARY, checkpoint_path=str(path))
    persisted = path.read_text(encoding="utf-8")

    assert live.findings
    assert _CANARY not in persisted
    restored = load_checkpoint(
        str(path), expected_plan_digest=plan.digest, plan=plan
    )
    assert restored.completed
    assert any(record["status"] == "confirmed" for record in restored.completed.values())
    calls = 0

    def must_not_run(case):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return _executing_outcome(case)

    mismatched = run_plan(
        plan,
        must_not_run,
        canary="AISCAN-IGNOREDONRESUME",
        checkpoint_path=str(path),
    )
    assert calls == 0
    assert not mismatched.findings
    assert mismatched.request_count == live.request_count
    assert load_checkpoint(
        str(path), expected_plan_digest=plan.digest, plan=plan
    ).request_count == live.request_count


def test_checkpoint_does_not_rewrite_unrelated_persistence_marker(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "alternate-token.ckpt"

    run_plan(
        plan,
        lambda _case: ExchangeOutcome("literal AISCAN-PERSISTED-CANARY label"),
        canary=_CANARY,
        checkpoint_path=str(path),
    )

    persisted = path.read_text(encoding="utf-8")
    assert "literal AISCAN-PERSISTED-CANARY label" in persisted
    load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


def test_cli_failed_retries_reconcile_controller_checkpoint_and_report(
    tmp_path, monkeypatch
) -> None:
    target = normalize_target("http://127.0.0.1:8000/chat")
    plan = compile_plan(target, "reliable")
    plan_path = tmp_path / "plan.json"
    checkpoint_path = tmp_path / "run.ckpt"
    report_path = tmp_path / "report.json"
    plan_path.write_text(plan_to_json(plan), encoding="utf-8")

    class FullyFailingTransport:
        def __init__(self, controller) -> None:  # type: ignore[no-untyped-def]
            self.controller = controller

        def send_prepared(self, _target, _prepared):  # type: ignore[no-untyped-def]
            for _ in range(3):
                self.controller.acquire()
            raise TransportError("offline transport failure", attempts=3)

    monkeypatch.setattr(cli, "_make_transport", FullyFailingTransport)
    result = cli.main(
        [
            "run",
            "--target",
            target.url,
            "--plan",
            str(plan_path),
            "--checkpoint",
            str(checkpoint_path),
            "--out",
            str(report_path),
        ]
    )

    assert result == cli.EXIT_INCONCLUSIVE
    report = json.loads(report_path.read_text(encoding="utf-8"))
    restored = load_checkpoint(
        str(checkpoint_path), expected_plan_digest=plan.digest, plan=plan
    )
    assert report["request_budget"]["used"] == restored.request_count
    assert report["request_budget"]["runner_count"] == restored.request_count
    assert report["injection"]["request_count"] == restored.request_count
    assert restored.request_count > 0
    assert all(
        trial["attempts"] == 3
        for record in restored.completed.values()
        for trial in record["trials"]
    )


def test_untrusted_interrupt_attempts_never_become_ledger_facts(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "interrupted.ckpt"

    baseline_calls = 0

    def baseline(_case):  # type: ignore[no-untyped-def]
        nonlocal baseline_calls
        baseline_calls += 1
        return ExchangeOutcome("benign")

    run_plan(plan, baseline, canary=_CANARY)

    class CountedInterrupt(KeyboardInterrupt):
        attempts = 3

    interrupted = run_plan(
        plan,
        lambda _case: (_ for _ in ()).throw(CountedInterrupt()),
        canary=_CANARY,
        checkpoint_path=str(path),
    )
    assert interrupted.request_count == 0
    pending = load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
    assert pending.in_flight is not None
    assert pending.in_flight["attempts"] == 0

    resumed_calls = 0

    def resumed(_case):  # type: ignore[no-untyped-def]
        nonlocal resumed_calls
        resumed_calls += 1
        return ExchangeOutcome("benign")

    with pytest.raises(CheckpointError, match="unresolved"):
        run_plan(plan, resumed, canary=_CANARY, checkpoint_path=str(path))
    assert resumed_calls == 0


@pytest.mark.parametrize("attempts", [True, 0, -1, 1.5, 73])
def test_exception_attempt_attribute_is_never_trusted(tmp_path, attempts) -> None:  # type: ignore[no-untyped-def]
    plan = _plan()
    path = tmp_path / "forged.ckpt"

    class Forged(RuntimeError):
        pass

    exc = Forged("offline")
    exc.attempts = attempts  # type: ignore[attr-defined]
    with pytest.raises(Forged):
        run_plan(
            plan,
            lambda _case: (_ for _ in ()).throw(exc),
            canary=_CANARY,
            checkpoint_path=str(path),
        )
    restored = load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
    assert restored.request_count == 0
    assert restored.in_flight is not None
    assert restored.in_flight["attempts"] == 0


@pytest.mark.parametrize(
    "error_type",
    [RuntimeError, TransportError, BudgetExceededError, KeyboardInterrupt, SystemExit],
)
@pytest.mark.parametrize(
    "totals",
    [
        True,
        {"total": True},
        {"total": 0},
        {"total": -1},
        {"total": 1.5},
        {"total": 10**100},
        {"total": 2, "attack": 2, "control": 2},
    ],
)
def test_exception_totals_never_become_ledger_facts(
    tmp_path, error_type, totals
) -> None:  # type: ignore[no-untyped-def]
    plan = _plan()
    path = tmp_path / "forged-totals.ckpt"
    error = error_type("offline")
    error.totals = totals  # type: ignore[attr-defined]

    if issubclass(error_type, (KeyboardInterrupt, SystemExit)):
        result = run_plan(
            plan,
            lambda _case: (_ for _ in ()).throw(error),
            canary=_CANARY,
            checkpoint_path=str(path),
        )
        assert result.request_count == 0
    else:
        with pytest.raises(error_type):
            run_plan(
                plan,
                lambda _case: (_ for _ in ()).throw(error),
                canary=_CANARY,
                checkpoint_path=str(path),
            )

    restored = load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
    assert restored.request_count == 0
    assert restored.in_flight is not None
    assert restored.in_flight["attempts"] == 0
    calls = 0

    def must_not_reissue(_case):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return ExchangeOutcome("benign")

    with pytest.raises(CheckpointError, match="unresolved"):
        run_plan(plan, must_not_reissue, canary=_CANARY, checkpoint_path=str(path))
    assert calls == 0


def test_forged_exception_totals_cannot_override_partial_trusted_consumption(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "trusted-partial.ckpt"

    class TrustedCounter:
        count = 0

    trusted = TrustedCounter()

    class ForgedTransportError(TransportError):
        pass

    def responder(_case):  # type: ignore[no-untyped-def]
        trusted.count += 2
        raise ForgedTransportError(
            "offline", totals={"total": 10**100, "attack": -1}, attempts=10**100
        )

    with pytest.raises(ForgedTransportError):
        run_plan(
            plan,
            responder,
            canary=_CANARY,
            checkpoint_path=str(path),
            physical_request_count=trusted,
        )

    restored = load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
    assert restored.in_flight is not None
    assert trusted.count == restored.request_count == restored.in_flight["attempts"] == 2


@pytest.mark.parametrize("bad_after", [True, -1, 1.5, 10**100])
def test_malformed_trusted_counter_after_issue_preserves_zero_unresolved_intent(
    tmp_path, bad_after
) -> None:  # type: ignore[no-untyped-def]
    plan = _plan()
    path = tmp_path / "malformed-counter.ckpt"
    values = iter([0, bad_after])

    class SequenceCounter:
        @property
        def count(self):  # type: ignore[no-untyped-def]
            return next(values)

    with pytest.raises(Exception, match="counter|ledger"):
        run_plan(
            plan,
            lambda _case: ExchangeOutcome("benign"),
            canary=_CANARY,
            checkpoint_path=str(path),
            physical_request_count=SequenceCounter(),
        )

    restored = load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
    assert restored.request_count == 0
    assert restored.in_flight is not None
    assert restored.in_flight["attempts"] == 0


def test_decreasing_trusted_counter_preserves_zero_unresolved_intent(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "decreasing-counter.ckpt"
    values = iter([2, 1])

    class SequenceCounter:
        @property
        def count(self):  # type: ignore[no-untyped-def]
            return next(values)

    with pytest.raises(Exception, match="counter|ledger"):
        run_plan(
            plan,
            lambda _case: ExchangeOutcome("benign"),
            canary=_CANARY,
            checkpoint_path=str(path),
            physical_request_count=SequenceCounter(),
        )

    restored = load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
    assert restored.request_count == 0
    assert restored.in_flight is not None
    assert restored.in_flight["attempts"] == 0


def test_checkpoint_v2_rejects_missing_null_semantic_and_unsupported_version(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "strict-current.ckpt"
    run_plan(
        plan,
        lambda _case: ExchangeOutcome("benign"),
        canary=_CANARY,
        checkpoint_path=str(path),
    )
    document = json.loads(path.read_text(encoding="utf-8"))
    trial = next(iter(document["completed"].values()))["trials"][0]
    assert trial["semantic"] is None
    trial.pop("semantic")
    document.pop("digest")
    document["digest"] = compute_digest(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(CheckpointError):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)

    document["checkpoint_version"] = 99
    document.pop("digest")
    document["digest"] = compute_digest(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(CheckpointError, match="unsupported"):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


@pytest.mark.parametrize(
    "payload",
    [
        '{"message":{"role":"assistant","Content":"fragment"},"done":true}',
        '{"metadata":{"unknown_split":["left","right"]},"done":true}',
        '{"message":{"role":"assistant","content":"x"},"error":"raw"}',
        '{"message":{"role":"assistant","content":"x"},"usage":{"prompt_tokens":NaN}}',
        '{"message":{"role":"assistant","content":"x"},"usage":{"prompt_tokens":1e999}}',
        '{"message":{"role":"assistant","content":"x","content":"y"}}',
        'not-json raw model text',
    ],
)
def test_provider_persistence_is_strict_metadata_allowlist(payload: str) -> None:
    persisted = scrub_provider_envelope(payload, frozenset({"fragment"}))
    assert "fragment" not in persisted
    assert "left" not in persisted
    assert "right" not in persisted
    assert '"raw"' not in persisted
    if persisted != REDACTED:
        doc = json.loads(persisted)
        assert set(doc) <= {
            "audit_version", "role", "completion_state", "model", "usage", "raw_body"
        }


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        '{"x":1,"x":2}',
        '{"usage":{"prompt_tokens":NaN}}',
        '{"usage":{"prompt_tokens":Infinity}}',
        '{"usage":{"prompt_tokens":1e999}}',
        "[]",
        "1",
        '{"error":"failure","message":{"role":"assistant"},"done":true}',
    ],
)
def test_malformed_provider_body_retains_only_exact_opaque_commitment(payload: str) -> None:
    raw = payload.encode("utf-8")
    persisted = scrub_provider_envelope(
        payload,
        raw_body_digest=hashlib.sha256(raw).hexdigest(),
        raw_body_length=len(raw),
    )
    assert json.loads(persisted) == {
        "audit_version": 1,
        "raw_body": {"sha256": hashlib.sha256(raw).hexdigest(), "length": len(raw)},
    }


@pytest.mark.parametrize(
    ("digest", "length"),
    [
        (None, 1),
        ("0" * 64, None),
        (True, 1),
        ("0" * 63, 1),
        ("G" * 64, 1),
        ("0" * 64, True),
        ("0" * 64, -1),
        ("0" * 64, 1.5),
        ("0" * 64, 10**100),
    ],
)
def test_invalid_provider_raw_identity_fails_closed(digest, length) -> None:  # type: ignore[no-untyped-def]
    assert scrub_provider_envelope(
        "not-json", raw_body_digest=digest, raw_body_length=length
    ) == REDACTED


def test_real_ollama_cli_persistence_scrubs_envelope_but_classifies_content(
    tmp_path, monkeypatch
) -> None:
    target = normalize_target("http://127.0.0.1:8000/api/chat")
    plan = compile_plan(target, "reliable", adapter="ollama")
    plan_path = tmp_path / "ollama-plan.json"
    checkpoint_path = tmp_path / "ollama.ckpt"
    report_path = tmp_path / "ollama-report.json"
    plan_path.write_text(plan_to_json(plan), encoding="utf-8")
    observed_canaries: set[str] = set()

    class OllamaFixtureTransport:
        def __init__(self, controller) -> None:  # type: ignore[no-untyped-def]
            self.controller = controller

        def send_prepared(self, _target, prepared):  # type: ignore[no-untyped-def]
            self.controller.acquire()
            request = json.loads(prepared.body)
            prompt = request["messages"][0]["content"]
            match = re.search(r"AISCAN-[A-Z0-9_-]+", prompt)
            canary = match.group(0) if match else None
            if canary is not None:
                observed_canaries.add(canary)
            content = canary if canary is not None else "benign"
            fragment = canary[-8:] if canary is not None else "benign"
            envelope = json.dumps(
                {
                    "model": "fixture",
                    "message": {
                        "role": "assistant",
                        "content": content,
                        "thinking": f"private fragment {fragment}",
                        "reasoning": {"nested": [fragment]},
                    },
                    "done": True,
                    "done_reason": "stop",
                }
            )
            return HttpResponse(
                status=200,
                body=envelope,
                headers={"Content-Type": "application/json"},
                redirected=False,
                redirect_location=None,
                truncated=False,
                request_line={"method": "POST", "url": target.url},
            )

    monkeypatch.setattr(cli, "_make_transport", OllamaFixtureTransport)
    result = cli.main(
        [
            "run",
            "--target",
            target.url,
            "--plan",
            str(plan_path),
            "--model",
            "fixture",
            "--checkpoint",
            str(checkpoint_path),
            "--out",
            str(report_path),
        ]
    )

    assert result == cli.EXIT_CONFIRMED_FINDING
    report_text = report_path.read_text(encoding="utf-8")
    checkpoint_text = checkpoint_path.read_text(encoding="utf-8")
    assert observed_canaries
    for canary in observed_canaries:
        assert canary not in report_text
        assert canary not in checkpoint_text
        assert canary[-8:] not in report_text
    report = json.loads(report_text)
    for exchange in report["evidence"]:
        envelope = json.loads(exchange["response"]["body"])
        assert set(envelope) <= {
            "audit_version",
            "role",
            "completion_state",
            "model",
            "usage",
            "raw_body",
        }
        assert envelope["audit_version"] == 1
        assert envelope["role"] == "assistant"
        assert envelope["completion_state"] == "complete"
        assert len(envelope["raw_body"]["sha256"]) == 64
    restored = load_checkpoint(
        str(checkpoint_path), expected_plan_digest=plan.digest, plan=plan
    )
    assert any(record["status"] == "confirmed" for record in restored.completed.values())


def test_redigested_checkpoint_rejects_unsubstantiated_request_count(tmp_path) -> None:
    plan = _plan()
    path = tmp_path / "inflated.ckpt"
    run_plan(plan, _executing_outcome, canary=_CANARY, checkpoint_path=str(path))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["request_count"] += 1
    document.pop("digest")
    document["digest"] = compute_digest(document)
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CheckpointError, match="does not equal"):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)


@pytest.mark.parametrize("relationship", ["same_family", "different_family", "attack_control"])
def test_redigested_trial_transplants_reject_exact_case_binding(tmp_path, relationship) -> None:  # type: ignore[no-untyped-def]
    plan = _plan()
    path = tmp_path / f"transplant-{relationship}.ckpt"
    run_plan(plan, _executing_outcome, canary=_CANARY, checkpoint_path=str(path))
    document = json.loads(path.read_text(encoding="utf-8"))
    cases = {case.case_id: case for case in plan.cases}
    records = document["completed"]
    source_id = next(case_id for case_id, record in records.items() if record["kind"] == "attack")
    source = cases[source_id]
    if relationship == "same_family":
        target_id = next(
            case_id
            for case_id, record in records.items()
            if case_id != source_id
            and record["kind"] == "attack"
            and cases[case_id].pack_id == source.pack_id
            and cases[case_id].family == source.family
        )
    elif relationship == "different_family":
        target_id = next(
            case_id
            for case_id, record in records.items()
            if record["kind"] == "attack" and cases[case_id].family != source.family
        )
    else:
        target_id = next(
            case_id for case_id, record in records.items() if record["kind"] == "control"
        )
    records[target_id]["trials"] = records[source_id]["trials"]
    document.pop("digest")
    document["digest"] = compute_digest(document)
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(CheckpointError, match="commitment|more trials"):
        load_checkpoint(str(path), expected_plan_digest=plan.digest, plan=plan)
