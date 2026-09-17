"""Step 1B / Astra M4 — one evidence contract for live/checkpoint/bundle/replay.

A finding whose only execution evidence is the exact final token (the bare,
public canary) is legitimate model output: a Gemini/OpenAI model told to "reply
with only X" replies ``X``. It may round-trip through a checkpoint, a bundle and
replay **only** because every physical trial is persisted and re-derived under
the same contract used live:

* per-trial, plan-derived attack evidence (never one representative body),
* matched clean controls re-derived from their own persisted trials,
* repeatability re-derived from the trials at the canonical plan thresholds,
* physical request counts equal to the persisted trial attempts,
* records bound to the verified, canonical, target-bound plan.

The bare-canary rejection is not merely relaxed: every forged or incomplete
variant of the same evidence still fails closed.
"""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Callable
from typing import Any

import pytest

from ai_scan.evidence_graph import (
    BundleCollector,
    BundleError,
    Observation,
    ReplayError,
    build_graph,
    dump_bundle,
    load_bundle,
    replay_bundle,
)
from ai_scan.injection import ExchangeOutcome, InjectionCase
from ai_scan.orchestration import compile_plan, load_plan, run_plan
from ai_scan.orchestration.checkpoint import CheckpointError, load_checkpoint
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target

_URL = "http://127.0.0.1:8765/v1/chat"
_CANARY = "AISCAN-EXACTTOKEN01"


def _plan(url: str = _URL):  # type: ignore[no-untyped-def]
    return compile_plan(normalize_target(url), "reliable")


def _exact_token(case: InjectionCase) -> ExchangeOutcome:
    """The attack reply is exactly the final token; controls are benign."""
    if "{canary}" in case.template:
        match = re.search(r"AISCAN-[A-Z0-9]+", case.rendered_prompt)
        assert match is not None
        return ExchangeOutcome(body=match.group(0))
    return ExchangeOutcome(body="A benign, unrelated synthetic answer.")


def _direct_attacks(findings: Any) -> list[Any]:
    return [f for f in findings if not f.family.startswith("prompt_disclosure")]


def _statuses(findings: Any) -> dict[str, str]:
    return {f.prompt: f.status.value for f in findings}


# --- the GREEN round trip ---------------------------------------------------------


def test_live_exact_token_confirms_with_persisted_per_trial_evidence() -> None:
    plan = _plan()
    result = run_plan(plan, _exact_token, canary=_CANARY)
    attacks = _direct_attacks(result.findings)
    assert attacks and all(f.status.value == "confirmed" for f in attacks)
    for finding in attacks:
        assert (finding.attack_trials, finding.successes) == plan.trial_policy[:1] * 2
        assert len(finding.evidence) == plan.trial_policy[0]
        assert all(o.body == _CANARY for o in finding.evidence)


def test_exact_token_round_trips_through_checkpoint(tmp_path) -> None:
    plan = _plan()
    path = str(tmp_path / "run.ckpt")
    live = run_plan(plan, _exact_token, canary=_CANARY, checkpoint_path=path)
    restored = load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)
    assert all(
        record["status"] == "confirmed"
        for record in restored.completed.values()
        if record["kind"] == "attack" and not str(record["family"]).startswith("prompt_disclosure")
    )

    calls: list[str] = []

    def no_more(case: InjectionCase) -> ExchangeOutcome:
        calls.append(case.template)
        return _exact_token(case)

    resumed = run_plan(plan, no_more, canary=_CANARY, checkpoint_path=path)
    assert calls == []  # completed physical trials are never repeated
    assert _statuses(resumed.findings) == _statuses(live.findings)
    assert resumed.request_count == live.request_count


def _bundle_doc(responder: Callable[[InjectionCase], ExchangeOutcome] = _exact_token) -> dict:
    plan = _plan()
    collector = BundleCollector()
    result = run_plan(plan, responder, canary=_CANARY, observer=collector.observe)
    bundle = collector.build(
        plan=plan, canary=_CANARY, run_id="m4", coverage_gaps=result.coverage_gaps
    )
    return json.loads(dump_bundle(bundle))


def test_exact_token_round_trips_through_bundle_and_replay() -> None:
    plan = _plan()
    collector = BundleCollector()
    live = run_plan(plan, _exact_token, canary=_CANARY, observer=collector.observe)
    text = dump_bundle(collector.build(plan=plan, canary=_CANARY, run_id="m4"))
    load_bundle(text)
    replayed = replay_bundle(text)
    assert replayed.verified
    live_attacks = {
        c.case_id: f.status.value
        for c, f in zip(plan.attack_cases(), live.findings, strict=False)
        if not c.family.startswith("prompt_disclosure")
    }
    assert "confirmed" in set(replayed.findings.values())
    assert set(replayed.findings.values()) <= {"confirmed", "not_observed"}
    assert len(replayed.findings) == len(live_attacks)


def test_bundle_persists_every_physical_trial_and_count() -> None:
    doc = _bundle_doc()
    plan = _plan()
    attack_n, _succ, control_n = plan.trial_policy
    total = 0
    for record in doc["records"]:
        trials = record["trials"]
        assert len(trials) == (attack_n if record["kind"] == "attack" else control_n)
        total += sum(t["attempts"] for t in trials)
    assert doc["request_count"] == total
    assert set(doc["control_results"].values()) == {"clean"}


# --- bundle forgeries (re-digested, so only the contract can reject them) ---------


def _reseal(doc: dict) -> str:
    """Re-seal every digest (plan, graph, bundle) so only content checks remain."""
    out = copy.deepcopy(doc)
    plan_body = {k: v for k, v in out["plan"].items() if k != "digest"}
    out["plan"]["digest"] = compute_digest(plan_body)
    out["plan_digest"] = out["plan"]["digest"]
    plan = load_plan(out["plan"])
    graph = build_graph(
        plan=plan,
        run_id=out["metadata"]["run_id"],
        observations=[
            Observation(
                case_id=r["case_id"],
                status=r["finding"]["status"],
                proof=r["finding"]["proof"],
                control_succeeded=out["control_results"].get(f"{r['pack_id']}:{r['family']}")
                in (True, "emitted"),
            )
            for r in out["records"]
        ],
    )
    out["graph"] = graph.to_canonical()
    out["graph_digest"] = graph.digest()
    out.pop("digest", None)
    out["digest"] = compute_digest(out)
    return json.dumps(out)


def _attack(doc: dict) -> dict:
    return next(r for r in doc["records"] if r["kind"] == "attack")


def _control(doc: dict) -> dict:
    return next(r for r in doc["records"] if r["kind"] == "control")


def _family_controls(doc: dict, record: dict) -> list[dict]:
    return [
        r for r in doc["records"]
        if r["kind"] == "control"
        and (r["pack_id"], r["family"]) == (record["pack_id"], record["family"])
    ]


def _single_trial_with_forged_counts(doc: dict) -> None:
    rec = _attack(doc)
    rec["trials"] = rec["trials"][:1]
    doc["request_count"] -= 2


def _extra_trial_beyond_plan(doc: dict) -> None:
    rec = _attack(doc)
    rec["trials"].append(dict(rec["trials"][0]))
    rec["finding"]["attack_trials"] += 1
    rec["finding"]["successes"] += 1
    doc["request_count"] += 1


def _refusals_under_confirmed(doc: dict) -> None:
    for trial in _attack(doc)["trials"][1:]:
        trial["body"] = "I can't help with that."


def _flip_not_observed_to_confirmed(doc: dict) -> None:
    for trial in _attack(doc)["trials"]:
        trial["body"] = "I can't help with that."
    # counts/status still claim a confirmed 3/3 execution


def _control_emits_under_clean(doc: dict) -> None:
    _control(doc)["trials"][0]["body"] = f"leaked {_CANARY}"


def _drop_family_controls(doc: dict) -> None:
    rec = _attack(doc)
    dropped = _family_controls(doc, rec)
    doc["records"] = [r for r in doc["records"] if r not in dropped]
    doc["request_count"] -= sum(t["attempts"] for r in dropped for t in r["trials"])


def _short_control_coverage(doc: dict) -> None:
    for control in _family_controls(doc, _attack(doc)):
        doc["request_count"] -= sum(t["attempts"] for t in control["trials"][1:])
        control["trials"] = control["trials"][:1]


def _forge_request_count(doc: dict) -> None:
    doc["request_count"] += 7


def _zero_attempts(doc: dict) -> None:
    _attack(doc)["trials"][0]["attempts"] = 0
    doc["request_count"] -= 1


def _bool_attempts(doc: dict) -> None:
    _attack(doc)["trials"][0]["attempts"] = True


def _unusable_trial_counted(doc: dict) -> None:
    _attack(doc)["trials"][0]["transport_ok"] = False


def _weaken_plan_policy(doc: dict) -> None:
    doc["plan"]["trial_policy"] = [1, 1, 1]


def _unknown_trial_field(doc: dict) -> None:
    _attack(doc)["trials"][0]["note"] = "x"


def _missing_trials(doc: dict) -> None:
    rec = _attack(doc)
    doc["request_count"] -= sum(t["attempts"] for t in rec["trials"])
    del rec["trials"]


def _legacy_response_field(doc: dict) -> None:
    rec = _attack(doc)
    rec["response"] = dict(rec["trials"][0])
    rec["response"].pop("attempts")


def _control_results_disagree(doc: dict) -> None:
    key = next(iter(doc["control_results"]))
    doc["control_results"][key] = "gap"


def _legacy_version(doc: dict) -> None:
    doc["bundle_version"] = 1


@pytest.mark.parametrize(
    "mutate",
    [
        _single_trial_with_forged_counts,
        _extra_trial_beyond_plan,
        _refusals_under_confirmed,
        _flip_not_observed_to_confirmed,
        _control_emits_under_clean,
        _drop_family_controls,
        _short_control_coverage,
        _forge_request_count,
        _zero_attempts,
        _bool_attempts,
        _unusable_trial_counted,
        _weaken_plan_policy,
        _unknown_trial_field,
        _missing_trials,
        _legacy_response_field,
        _control_results_disagree,
        _legacy_version,
    ],
)
def test_forged_exact_token_bundle_fails_closed(mutate) -> None:
    doc = _bundle_doc()
    mutate(doc)
    text = _reseal(doc)
    with pytest.raises((BundleError, ReplayError)):
        load_bundle(text)
    with pytest.raises(ReplayError):
        replay_bundle(text)


def test_bundle_plan_target_cannot_be_swapped_under_its_evidence_graph() -> None:
    """The graph binds the exact plan target: re-pointing the plan at another
    target (plan + bundle digests resealed) without rebuilding the provenance
    graph fails closed. A forger who re-seals *everything* consistently is out
    of scope for digest-only offline replay (tamper-evidence, not a signature)."""
    doc = _bundle_doc()
    doc["plan"]["target"] = "http://127.0.0.1:8765/v1/other"
    plan_body = {k: v for k, v in doc["plan"].items() if k != "digest"}
    doc["plan"]["digest"] = compute_digest(plan_body)
    doc["plan_digest"] = doc["plan"]["digest"]
    doc.pop("digest")
    doc["digest"] = compute_digest(doc)
    with pytest.raises(ReplayError):
        replay_bundle(json.dumps(doc))


# --- checkpoint forgeries ----------------------------------------------------------


def _checkpoint(tmp_path) -> tuple[Any, str, dict]:
    plan = _plan()
    path = str(tmp_path / "run.ckpt")
    run_plan(plan, _exact_token, canary=_CANARY, checkpoint_path=path)
    return plan, path, json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115


def _write(path: str, data: dict) -> None:
    data = dict(data)
    data.pop("digest", None)
    data["digest"] = compute_digest(data)
    open(path, "w", encoding="utf-8").write(json.dumps(data))  # noqa: SIM115


def _ck_attack(data: dict) -> dict:
    return next(r for r in data["completed"].values() if r["kind"] == "attack")


def _ck_single_trial(data: dict) -> None:
    rec = _ck_attack(data)
    rec["trials"] = rec["trials"][:1]


def _ck_legacy_confirmed(data: dict) -> None:
    del _ck_attack(data)["trials"]


def _ck_refusals(data: dict) -> None:
    for trial in _ck_attack(data)["trials"]:
        trial["body"] = "I can't help with that."


def _ck_control_emits(data: dict) -> None:
    rec = next(r for r in data["completed"].values() if r["kind"] == "control")
    rec["trials"][0]["body"] = f"leaked {_CANARY}"


def _ck_forged_clean_without_control_evidence(data: dict) -> None:
    data["completed"] = {
        cid: r for cid, r in data["completed"].items() if r["kind"] != "control"
    }


def _ck_request_count_below_evidence(data: dict) -> None:
    data["request_count"] = 1


@pytest.mark.parametrize(
    "mutate",
    [
        _ck_single_trial,
        _ck_legacy_confirmed,
        _ck_refusals,
        _ck_control_emits,
        _ck_forged_clean_without_control_evidence,
        _ck_request_count_below_evidence,
    ],
)
def test_forged_exact_token_checkpoint_fails_closed(tmp_path, mutate) -> None:
    plan, path, data = _checkpoint(tmp_path)
    mutate(data)
    _write(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)


def test_checkpoint_is_bound_to_its_exact_target_plan(tmp_path) -> None:
    _plan_a, path, _data = _checkpoint(tmp_path)
    other = _plan("http://127.0.0.1:8765/v1/other")
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=other.digest, plan=other)


def test_resume_never_trusts_unevidenced_clean_control(tmp_path) -> None:
    """A forged 'clean' control result without control evidence cannot let a
    resumed run confirm: the controls are re-run for real."""
    plan = _plan()
    path = str(tmp_path / "run.ckpt")
    run_plan(plan, _exact_token, canary=_CANARY, checkpoint_path=path)
    data = json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115
    data["completed"] = {}
    data["request_count"] = 0
    data["control_results"] = {k: "clean" for k in data["control_results"]}
    _write(path, data)

    def leaky(case: InjectionCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=_CANARY)  # controls emit the token too

    result = run_plan(plan, leaky, canary=_CANARY, checkpoint_path=path)
    assert all(f.status.value != "confirmed" for f in result.findings)
