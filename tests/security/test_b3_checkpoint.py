"""Phase B3 — strict checkpoint integrity and plan-derived records."""

from __future__ import annotations

import json
import re

import pytest

from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import RunState, compile_plan
from ai_scan.orchestration.checkpoint import (
    Checkpoint,
    CheckpointError,
    load_checkpoint,
    write_checkpoint_atomic,
)
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

_URL = "http://127.0.0.1:8000"


def _plan():
    return compile_plan(normalize_target(_URL), "reliable")


def _valid_checkpoint_file(tmp_path, plan) -> str:
    path = str(tmp_path / "run.ckpt")
    write_checkpoint_atomic(
        path, Checkpoint(plan_digest=plan.digest, state="running", request_count=1)
    )
    return path


def _reseal(data: dict) -> dict:
    data = dict(data)
    data.pop("digest", None)
    data["digest"] = compute_digest(data)
    return data


# --- B3.1 strict-load: duplicate keys / non-finite / unknown fields -------------

def test_strict_load_rejects_duplicate_keys(tmp_path) -> None:
    plan = _plan()
    path = _valid_checkpoint_file(tmp_path, plan)
    text = open(path, encoding="utf-8").read()  # noqa: SIM115
    dup = text[:-1] + ', "state": "running"}'
    open(path, "w", encoding="utf-8").write(dup)  # noqa: SIM115
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest)


def test_strict_load_rejects_non_finite_values(tmp_path) -> None:
    plan = _plan()
    path = _valid_checkpoint_file(tmp_path, plan)
    data = json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115
    text = json.dumps(data).replace('"request_count": 1', '"request_count": Infinity')
    open(path, "w", encoding="utf-8").write(text)  # noqa: SIM115
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest)


def test_strict_load_rejects_unknown_field_even_redigested(tmp_path) -> None:
    plan = _plan()
    path = _valid_checkpoint_file(tmp_path, plan)
    data = json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115
    data["surprise"] = "x"
    open(path, "w", encoding="utf-8").write(json.dumps(_reseal(data)))  # noqa: SIM115
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest)


def test_valid_checkpoint_still_loads(tmp_path) -> None:
    plan = _plan()
    path = _valid_checkpoint_file(tmp_path, plan)
    restored = load_checkpoint(path, expected_plan_digest=plan.digest)
    assert restored.state == "running"
    assert restored.plan_digest == plan.digest


# --- B3.2/B3.3 plan-derived record binding + forged confirmed rejection ---------

_CANARY = "AISCAN-B3CANARY"


def _real_checkpoint(tmp_path, plan) -> str:
    """Drive run_plan to produce a real, plan-bound checkpoint with a canary."""
    path = str(tmp_path / "real.ckpt")

    def responder(case):  # type: ignore[no-untyped-def]
        match = re.search(r"AISCAN-\S+", case.rendered_prompt)
        leaked = match.group(0) if match else _CANARY
        # A realistic execution response: the canary embedded in response context
        # (not a bare echo), so a genuine proof carries more than the public canary.
        body = f"model output >> {leaked} << executed" if "{canary}" in case.template else "benign"
        return ExchangeOutcome(body)

    run_plan(plan, responder, canary=_CANARY, goal="", checkpoint_path=path)
    return path


def _load_data(path: str) -> dict:
    return json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115


def _write_data(path: str, data: dict) -> None:
    open(path, "w", encoding="utf-8").write(json.dumps(_reseal(data)))  # noqa: SIM115


def test_plan_bound_checkpoint_loads(tmp_path) -> None:
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    restored = load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)
    assert restored.completed


def test_current_checkpoint_rejects_completed_record_without_trials(tmp_path) -> None:
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    record = next(iter(data["completed"].values()))
    record.pop("trials")
    record["status"] = "not_observed"
    record["proof"] = None
    record["attack_trials"] = 0
    record["successes"] = 0
    _write_data(path, data)

    with pytest.raises(CheckpointError, match="malformed checkpoint"):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_record_for_case_not_in_plan_rejected(tmp_path) -> None:
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    data["completed"]["bogus:family:attack:0"] = {
        "family": "family", "status": "not_observed",
        "prompt": "whatever", "proof": None, "kind": "attack",
    }
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_completed_record_with_unknown_field_rejected(tmp_path) -> None:
    # Each completed record is closed-schema: a re-digested record carrying an
    # extra nested field must be rejected, not silently dropped on normalization.
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    case_id = next(iter(data["completed"]))
    data["completed"][case_id]["surprise"] = "x"
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_completed_record_with_missing_field_rejected(tmp_path) -> None:
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    case_id = next(iter(data["completed"]))
    del data["completed"][case_id]["successes"]
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_altered_prompt_record_rejected(tmp_path) -> None:
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    case_id = next(iter(data["completed"]))
    data["completed"][case_id]["prompt"] = data["completed"][case_id]["prompt"] + " tamper"
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def _non_confirming_checkpoint(tmp_path, plan) -> str:
    """A run where attacks do NOT execute the canary → not_observed records."""
    path = str(tmp_path / "nonconf.ckpt")

    def responder(case):  # type: ignore[no-untyped-def]
        return ExchangeOutcome("benign")  # never leaks the canary

    run_plan(plan, responder, canary=_CANARY, goal="", checkpoint_path=path)
    return path


def test_forged_confirmed_without_canary_proof_rejected(tmp_path) -> None:
    # Flip a completed attack record to 'confirmed' with fabricated proof that
    # lacks the canary, then re-digest: a plan-bound load must reject it.
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    attack_id = next(
        cid for cid, rec in data["completed"].items() if rec["kind"] == "attack"
    )
    data["completed"][attack_id]["status"] = "confirmed"
    data["completed"][attack_id]["proof"] = "totally legit, trust me"  # no canary
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_forged_confirmed_with_copied_canary_proof_rejected(tmp_path) -> None:
    # Crayon's repro: a REAL not_observed attack record, relabeled 'confirmed'
    # with the canary copied into the proof, re-digested. The canary is public
    # (it's in the prompt), so proof-contains-canary is not enough — the record's
    # own trial evidence (successes=0) cannot support confirmation → reject.
    plan = _plan()
    path = _non_confirming_checkpoint(tmp_path, plan)
    data = _load_data(path)
    attack_id = next(
        cid for cid, rec in data["completed"].items()
        if rec["kind"] == "attack" and rec["status"] != "confirmed"
    )
    record = data["completed"][attack_id]
    assert record["successes"] == 0  # started from genuine non-confirmation
    record["status"] = "confirmed"
    record["proof"] = record["prompt"]  # copy the (public) canary-bearing prompt
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_forged_confirmed_with_reflected_prompt_proof_rejected(tmp_path) -> None:
    # A forged confirmation whose proof is just the public rendered prompt is
    # reflection/self-echo (B1 → 'suspected'), even with forged counts meeting
    # policy and a clean control. It must be rejected.
    plan = _plan()
    path = _non_confirming_checkpoint(tmp_path, plan)
    data = _load_data(path)
    attack_id = next(
        cid for cid, rec in data["completed"].items()
        if rec["kind"] == "attack" and rec["status"] != "confirmed"
    )
    record = data["completed"][attack_id]
    record["status"] = "confirmed"
    record["proof"] = record["prompt"]  # reflection: echo the public prompt
    record["attack_trials"] = plan.trial_policy[0]  # forge counts to meet policy
    record["successes"] = plan.trial_policy[1]
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_forged_confirmed_bare_public_canary_proof_rejected(tmp_path) -> None:
    # The canary is public; a proof that is just the bare canary (with forged
    # policy-meeting counts and forged clean control) is not response-derived
    # evidence of execution and must be rejected.
    plan = _plan()
    path = _non_confirming_checkpoint(tmp_path, plan)
    data = _load_data(path)
    attack_id = next(
        cid for cid, rec in data["completed"].items()
        if rec["kind"] == "attack" and rec["status"] != "confirmed"
    )
    record = data["completed"][attack_id]
    record["status"] = "confirmed"
    record["proof"] = _CANARY  # bare, public canary
    record["attack_trials"] = plan.trial_policy[0]
    record["successes"] = plan.trial_policy[1]
    family = record["family"]
    pack_id = attack_id.split(":", 1)[0]
    data["control_results"][f"{pack_id}:{family}"] = "clean"  # forge clean control
    _write_data(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_genuine_confirmed_execution_proof_loads(tmp_path) -> None:
    # The GREEN counterpart: a real confirmation (executed canary, clean control,
    # supported counts, non-reflected proof) loads.
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    restored = load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)
    assert any(r["status"] == "confirmed" for r in restored.completed.values())


# --- B3.4 in-flight case not treated as completed without reconciliation --------

def test_in_flight_case_is_rerun_on_resume(tmp_path) -> None:
    # A case that is NOT in `completed` (in flight at the crash) must be re-run on
    # resume, never silently skipped as done.
    plan = _plan()
    path = _real_checkpoint(tmp_path, plan)
    data = _load_data(path)
    attack_id = next(
        cid for cid, rec in data["completed"].items() if rec["kind"] == "attack"
    )
    template = plan_case_template(plan, attack_id)
    removed = data["completed"].pop(attack_id)
    data["request_count"] -= sum(trial["attempts"] for trial in removed["trials"])
    data["request_count"] += 1
    data["in_flight"] = {
        "case_id": attack_id,
        "kind": "attack",
        "family": removed["family"],
        "prompt": removed["prompt"],
        "attempts": 1,
    }
    data["state"] = RunState.CONFIRMING.value
    _write_data(path, data)

    seen: list[str] = []

    def responder(case):  # type: ignore[no-untyped-def]
        seen.append(case.template)
        match = re.search(r"AISCAN-\S+", case.rendered_prompt)
        leaked = match.group(0) if match else _CANARY
        return ExchangeOutcome(leaked if "{canary}" in case.template else "benign")

    run_plan(plan, responder, canary=_CANARY, goal="", checkpoint_path=path)
    assert template in seen  # the in-flight case was re-run, not skipped


def plan_case_template(plan, case_id: str) -> str:
    return next(c.template for c in plan.cases if c.case_id == case_id)


# --- legacy baseline-format handling (no B3 weakening) ---------------------------

def test_legacy_unredacted_baseline_record_fails_closed(tmp_path) -> None:
    # A legacy checkpoint retains a generated canary and has no evidence-bearing
    # representation. Re-digesting it does not make it safe to load or resume.
    plan = _plan()
    first_attack = plan.attack_cases()[0]
    ckpt = Checkpoint(plan_digest=plan.digest, state=RunState.CONFIRMING.value, request_count=1)
    ckpt.completed[first_attack.case_id] = {
        "family": first_attack.family,
        "status": "not_observed",
        "prompt": first_attack.template.replace("{canary}", _CANARY),
        "proof": None,
        "kind": "attack",
    }
    fam_key = f"{first_attack.pack_id}:{first_attack.family}"
    ckpt.control_results[fam_key] = "clean"  # will be re-serialized as string
    path = str(tmp_path / "legacy.ckpt")
    # Hand-craft the legacy on-disk shape: 5-field record + boolean control result.
    body = ckpt.to_body()
    body["completed"][first_attack.case_id] = {
        "family": first_attack.family,
        "status": "not_observed",
        "prompt": first_attack.template.replace("{canary}", _CANARY),
        "proof": None,
        "kind": "attack",
    }
    body["control_results"] = {fam_key: False}  # legacy boolean
    body.pop("canary", None)  # legacy: no canary field
    body = _reseal(body)
    open(path, "w", encoding="utf-8").write(json.dumps(body))  # noqa: SIM115

    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_legacy_confirmed_without_trial_evidence_rejected(tmp_path) -> None:
    # A legacy 'confirmed' record has no trial counts → not safety-supported →
    # must be rejected, not grandfathered into a confirmation bypass.
    plan = _plan()
    first_attack = plan.attack_cases()[0]
    ckpt = Checkpoint(plan_digest=plan.digest, state=RunState.CONFIRMING.value, request_count=1)
    path = str(tmp_path / "legacy-confirmed.ckpt")
    body = ckpt.to_body()
    body["completed"][first_attack.case_id] = {  # 5-field legacy, confirmed
        "family": first_attack.family,
        "status": "confirmed",
        "prompt": first_attack.template.replace("{canary}", _CANARY),
        "proof": _CANARY,
        "kind": "attack",
    }
    body["control_results"] = {f"{first_attack.pack_id}:{first_attack.family}": False}
    body.pop("canary", None)
    body = _reseal(body)
    open(path, "w", encoding="utf-8").write(json.dumps(body))  # noqa: SIM115
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)
