"""Durable, table-driven regressions for the runtime-integrity closure (B1-B4).

Each test locks a whole invariant *class*, not one reproduction:

* B1 - a completed LLM02 checkpoint canonicalizes its trials with the full run
  secret set before committing, so it re-loads its own persisted evidence
  offline (idempotent scrub), even when the disclosure marker never appears in a
  trial's own ``known_secrets``.
* B2 - the disclosure-marker *state* is bound into checkpoint identity, so every
  substitution (old->new, marker->missing, missing->marker) fails closed before
  any request and never relabels prior evidence.
* B3 - every public engine derives physical-request counts exclusively from the
  trusted request-controller ledger; forged responder/exception ``attempts``
  never drive accounting, and engine counts reconcile with ``request_budget``.
* B4 - provider audit persistence is identity-only for any truncated, invalid,
  or replacement-decoded body, validated from the exact raw-byte identity rather
  than a caller-supplied flag.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ai_scan import cli
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import compile_plan
from ai_scan.orchestration.checkpoint import CheckpointError, load_checkpoint
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse, TransportError
from tests.trusted_engines import run_plan

_TARGET = "http://127.0.0.1:8000/chat"
_CANARY = "AISCAN-CLOSURE-RUN-IDENTITY"
_MARKER = "AISCAN-CLOSURE-DISCLOSURE-MARKER"
_OTHER_MARKER = "AISCAN-CLOSURE-DISCLOSURE-OTHER"


def _plan():  # type: ignore[no-untyped-def]
    return compile_plan(normalize_target(_TARGET), "reliable")


def _rendered_cases(plan, canary):  # type: ignore[no-untyped-def]
    from ai_scan.orchestration.evidence import rendered_prompt

    return {rendered_prompt(case, canary): case for case in plan.cases}


# --- B3: forged accounting is ignored across every public engine ----------------


class _ForgedFailureTransport:
    """A transport whose failures forge inflated retry accounting and never touch
    the trusted controller (so the honest trusted delta is zero)."""

    forged_attempts = 73

    def __init__(self, controller) -> None:  # type: ignore[no-untyped-def]
        self.controller = controller

    def send_prepared(self, _target, _prepared):  # type: ignore[no-untyped-def]
        error = TransportError(
            "sanitized", totals={"total": self.forged_attempts}, attempts=self.forged_attempts
        )
        error.nested = {"attempts": 10**9, "totals": {"total": 10**9}}
        raise error


@pytest.mark.parametrize("forged", [1, 73, 10**9, True, 0, -5])
@pytest.mark.parametrize("command", ["inject", "assess", "fingerprint"])
def test_forged_attempts_never_drive_engine_accounting(
    tmp_path, monkeypatch, command, forged
) -> None:  # type: ignore[no-untyped-def]
    transport_cls = type(
        "_Forged", (_ForgedFailureTransport,), {"forged_attempts": forged}
    )
    monkeypatch.setattr(cli, "_make_transport", transport_cls)
    report_path = Path(tmp_path) / f"{command}.json"
    args = [command, "--target", _TARGET, "--out", str(report_path)]
    if command == "inject":
        args.extend(["--goal", "offline closure review"])

    code = cli.main(args)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    # The forged transport never reaches the trusted controller, so the honest
    # physical count is zero — never the forged value or an "all budget spent"
    # fabrication — and the engine count reconciles with the trusted budget.
    assert code == cli.EXIT_INCONCLUSIVE
    assert report["request_budget"]["used"] == 0
    injection = report.get("injection")
    if injection is not None:
        assert injection["request_count"] == 0
        assert injection["request_count"] == report["request_budget"]["used"]


# A transport that consumes REAL controller budget but lies that it made 999
# retries: the trusted ledger delta (one per exchange), not the forged claim,
# must drive the count. (The positive "every real attempt is counted" class is
# also covered by tests/security/test_m3_accounting.py.)
class _RealBudgetTransport:
    def __init__(self, controller) -> None:  # type: ignore[no-untyped-def]
        self.controller = controller

    def send_prepared(self, target, prepared):  # type: ignore[no-untyped-def]
        self.controller.acquire()
        return HttpResponse(
            status=200,
            body='{"message":{"role":"assistant","content":"benign"},"done":true}',
            headers={"Content-Type": "application/json"},
            redirected=False,
            redirect_location=None,
            truncated=False,
            request_line={"method": "POST", "url": target.origin},
            attempts=999,
        )


def test_trusted_ledger_delta_counts_not_responder_claims(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cli, "_make_transport", _RealBudgetTransport)
    report_path = Path(tmp_path) / "inject.json"
    cli.main(["inject", "--target", _TARGET, "--goal", "g", "--out", str(report_path)])
    report = json.loads(report_path.read_text(encoding="utf-8"))

    used = report["request_budget"]["used"]
    # One real physical request per exchange (the ledger), never the forged 999.
    assert used == report["injection"]["request_count"]
    assert 0 < used < 999


# --- B4: provider audit persistence is identity-only for non-faithful bodies ----


def _provider_audit(raw: bytes, *, truncated: bool, decode_valid: bool) -> dict:  # type: ignore[no-untyped-def]
    response = HttpResponse(
        status=200,
        body=raw.decode("utf-8", errors="replace"),
        headers={},
        redirected=False,
        redirect_location=None,
        truncated=truncated,
        request_line={"method": "POST", "url": "http://127.0.0.1/provider"},
        raw_body_digest=hashlib.sha256(raw).hexdigest(),
        raw_body_length=len(raw),
        decode_valid=decode_valid,
    )
    return json.loads(response.evidence(redact_provider_text=True)["response"]["body"])


_VALID = (
    b'{"message":{"role":"assistant","content":"safe"},"done":true,"done_reason":"stop"}'
)
_INVALID_UTF8 = (
    b'{"message":{"role":"assistant","content":"\xff"},"done":true,"done_reason":"stop"}'
)
_ERROR_BODY = (
    b'{"error":"nope","message":{"role":"assistant","content":"safe"},'
    b'"done":true,"done_reason":"stop"}'
)
_NON_OBJECT = b'["assistant","done"]'


@pytest.mark.parametrize(
    "raw,truncated,decode_valid",
    [
        (_VALID, True, True),  # truncated -> identity only
        (_INVALID_UTF8, False, False),  # invalid utf-8 -> identity only
        (_INVALID_UTF8, False, True),  # lying flag can't bypass raw-identity check
        (_ERROR_BODY, False, True),  # provider error body -> identity only
        (_NON_OBJECT, False, True),  # non-object body -> identity only
    ],
)
def test_provider_audit_is_identity_only_for_non_semantic_bodies(
    raw, truncated, decode_valid
) -> None:  # type: ignore[no-untyped-def]
    audit = _provider_audit(raw, truncated=truncated, decode_valid=decode_valid)
    assert set(audit) == {"audit_version", "raw_body"}
    assert audit["raw_body"] == {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "length": len(raw),
    }


def test_provider_audit_keeps_only_allowlisted_metadata_for_faithful_body() -> None:
    audit = _provider_audit(_VALID, truncated=False, decode_valid=True)
    assert audit["audit_version"] == 1
    assert audit["role"] == "assistant"
    assert audit["completion_state"] == "complete"
    # Only the bounded, non-semantic allowlist plus raw identity — never content.
    assert set(audit) <= {"audit_version", "role", "completion_state", "usage", "raw_body"}
    assert "safe" not in json.dumps(audit)


# --- B1: a completed LLM02 checkpoint re-loads its own committed evidence --------


def _disclosing_responder(marker, *, mark_secret):  # type: ignore[no-untyped-def]
    """A responder where only the LLM02 *attack* templates emit the whole marker
    (controls stay benign, so the disclosure confirms). ``mark_secret`` controls
    whether the marker is reported in the exchange's own ``known_secrets`` — the
    B1 self-invalidation trigger is precisely ``mark_secret=False``, where the
    marker reaches persistence only via the cumulative run secret set."""
    plan = _plan()

    def responder(case):  # type: ignore[no-untyped-def]
        secrets = frozenset({marker}) if mark_secret else frozenset()
        if "pre-provisioned" in case.template or "preconfigurada" in case.template:
            return ExchangeOutcome(body=marker, known_secrets=secrets)
        return ExchangeOutcome(
            body="benign answer without the synthetic marker", known_secrets=secrets
        )

    return plan, responder


@pytest.mark.parametrize("mark_secret", [True, False])
def test_completed_llm02_checkpoint_reloads_offline_with_zero_calls(
    tmp_path, mark_secret
) -> None:  # type: ignore[no-untyped-def]
    plan, responder = _disclosing_responder(_MARKER, mark_secret=mark_secret)
    path = str(Path(tmp_path) / "run.ckpt")
    first = run_plan(
        plan, responder, canary=_CANARY, disclosure_marker=_MARKER, checkpoint_path=path
    )
    confirmed = [
        f for f in first.findings
        if f.family.startswith("prompt_disclosure") and f.status.value == "confirmed"
    ]
    assert confirmed  # LLM02 confirmed on the live run

    # Re-loading the checkpoint under the SAME identity binds and re-derives its
    # own persisted evidence with no responder call (idempotent scrub: the outer
    # persistence scrub cannot mutate an already-committed trial).
    calls = {"n": 0}

    def must_not_call(case):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return ExchangeOutcome(body="benign")

    resumed = run_plan(
        plan, must_not_call, canary=_CANARY, disclosure_marker=_MARKER, checkpoint_path=path
    )
    assert calls["n"] == 0
    assert [f.status for f in resumed.findings] == [f.status for f in first.findings]
    # The checkpoint also loads and binds directly, offline.
    restored = load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan,
                               disclosure_marker=_MARKER)
    assert restored.completed


def test_completed_checkpoint_persists_no_raw_marker_or_canary(tmp_path) -> None:  # type: ignore[no-untyped-def]
    plan, responder = _disclosing_responder(_MARKER, mark_secret=False)
    path = Path(tmp_path) / "run.ckpt"
    run_plan(
        plan, responder, canary=_CANARY, disclosure_marker=_MARKER,
        checkpoint_path=str(path),
    )
    on_disk = path.read_text(encoding="utf-8")
    assert _CANARY not in on_disk
    assert _MARKER not in on_disk


# --- B2: disclosure-marker identity substitution fails closed -------------------


@pytest.mark.parametrize(
    "first_marker,resume_marker",
    [
        (_MARKER, _OTHER_MARKER),  # old -> new
        (_MARKER, None),  # marker -> missing
        (None, _MARKER),  # missing -> marker
    ],
)
def test_marker_substitution_fails_closed_without_calls(
    tmp_path, first_marker, resume_marker
) -> None:  # type: ignore[no-untyped-def]
    plan, responder = _disclosing_responder(
        first_marker if first_marker is not None else _MARKER, mark_secret=True
    )
    path = str(Path(tmp_path) / "run.ckpt")
    run_plan(
        plan, responder, canary=_CANARY, disclosure_marker=first_marker, checkpoint_path=path
    )

    calls = {"n": 0}

    def must_not_call(case):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        return ExchangeOutcome(body="benign")

    with pytest.raises(CheckpointError, match="disclosure marker"):
        run_plan(
            plan,
            must_not_call,
            canary=_CANARY,
            disclosure_marker=resume_marker,
            checkpoint_path=path,
        )
    assert calls["n"] == 0


def test_legacy_empty_checkpoint_without_marker_commitment_fails_closed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Even empty legacy documents must not bypass the exact run-identity schema."""
    from ai_scan.orchestration.checkpoint import (
        Checkpoint,
        canary_commitment,
        write_checkpoint_atomic,
    )
    from ai_scan.packs.signatures import compute_digest

    plan, responder = _disclosing_responder(_MARKER, mark_secret=False)
    path = Path(tmp_path) / "legacy.ckpt"

    # An empty, valid v2 checkpoint that predates the marker-commitment field.
    empty = Checkpoint(
        plan_digest=plan.digest,
        state="validated",
        canary=_CANARY,
        canary_commitment=canary_commitment(plan.digest, _CANARY),
    )
    write_checkpoint_atomic(str(path), empty)
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("marker_commitment", None)  # emulate the pre-field on-disk shape
    data.pop("digest", None)
    data["digest"] = compute_digest(data)
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(CheckpointError):
        run_plan(
            plan, responder, canary=_CANARY,
            disclosure_marker=_MARKER, checkpoint_path=str(path),
        )


def test_same_marker_resume_is_accepted(tmp_path) -> None:  # type: ignore[no-untyped-def]
    plan, responder = _disclosing_responder(_MARKER, mark_secret=True)
    path = str(Path(tmp_path) / "run.ckpt")
    first = run_plan(
        plan, responder, canary=_CANARY, disclosure_marker=_MARKER, checkpoint_path=path
    )

    def must_not_call(case):  # type: ignore[no-untyped-def]
        raise AssertionError("no responder call expected on a matching-identity resume")

    resumed = run_plan(
        plan, must_not_call, canary=_CANARY, disclosure_marker=_MARKER, checkpoint_path=path
    )
    assert [f.status for f in resumed.findings] == [f.status for f in first.findings]
