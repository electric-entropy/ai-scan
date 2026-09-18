"""Step 1B review corrections.

(1) Plan-bound physical counts: persisted evidence can never claim more physical
    attempts — per trial, per record, or in aggregate — than the canonical
    verified plan's ``max_physical_requests`` budget, through any load path
    (bundle, replay text/bytes/Bundle, checkpoint, public contract objects).
(2) Proof redaction: a known secret that crosses the proof snippet's boundary
    must not leave a fragment on disk; proofs are cut from redacted evidence.
(3) M6 mode policy: plugins run at least the resolved mode trial policy
    (Reliable/Kitchen Sink 3/2/2), never a weaker built-in 1/1/1 declaration.
"""

from __future__ import annotations

import copy
import json
import re
from collections import Counter

import pytest

from ai_scan.attacks import AttackContext, DirectInjectionPlugin
from ai_scan.attacks.base import AttackCase
from ai_scan.core.modes import resolve_policy
from ai_scan.core.run_identity import RunIdentity
from ai_scan.evidence_graph import (
    Bundle,
    BundleCollector,
    BundleError,
    ReplayError,
    dump_bundle,
    load_bundle,
    replay_bundle,
)
from ai_scan.injection import ExchangeOutcome, InjectionCase
from ai_scan.orchestration import compile_plan
from ai_scan.orchestration.checkpoint import PERSISTED_CANARY, CheckpointError, load_checkpoint
from ai_scan.orchestration.evidence import (
    CaseEvidence,
    EvidenceError,
    resolve_plan_packs,
    verify_records,
)
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.fixtures.apps import vulnerable_app
from tests.security.test_m4_evidence_contract import _CANARY, _bundle_doc, _exact_token, _reseal
from tests.trusted_engines import run_attack, run_plan

_URL = "http://127.0.0.1:8765/v1/chat"


def _plan():  # type: ignore[no-untyped-def]
    return compile_plan(normalize_target(_URL), "reliable")


# --- (1) plan-bound physical counts -------------------------------------------------


def test_normal_physical_count_is_preserved() -> None:
    plan = _plan()
    assert plan.limits.max_physical_requests == 256
    doc = _bundle_doc()
    assert doc["request_count"] == 32
    text = _reseal(doc)
    assert replay_bundle(text).verified
    assert run_plan(plan, _exact_token, canary=_CANARY).request_count == 32


def _first_attack(doc: dict) -> dict:
    return next(r for r in doc["records"] if r["kind"] == "attack")


def _set_attempts(doc: dict, value: int) -> None:
    trial = _first_attack(doc)["trials"][0]
    doc["request_count"] += value - trial["attempts"]
    trial["attempts"] = value


def _spread_attempts(doc: dict) -> None:
    # Every trial individually under budget, aggregate far over it.
    total = 0
    for record in doc["records"]:
        for trial in record["trials"]:
            trial["attempts"] = 100
            total += 100
    doc["request_count"] = total


def _record_sum_over_budget(doc: dict) -> None:
    rec = _first_attack(doc)
    for trial in rec["trials"]:
        trial["attempts"] = 90
    doc["request_count"] = sum(t["attempts"] for r in doc["records"] for t in r["trials"])


def _successes_exceed_trials(doc: dict) -> None:
    _first_attack(doc)["finding"]["successes"] = 4


def _trials_exceed_persisted(doc: dict) -> None:
    finding = _first_attack(doc)["finding"]
    finding["attack_trials"] = 4
    finding["successes"] = 4


def _huge_successes(doc: dict) -> None:
    finding = _first_attack(doc)["finding"]
    finding["attack_trials"] = 10**40
    finding["successes"] = 10**40


_FORGERIES = [
    pytest.param(lambda d: _set_attempts(d, 257), id="attempts-257"),
    pytest.param(lambda d: _set_attempts(d, 2**63), id="attempts-2^63"),
    pytest.param(lambda d: _set_attempts(d, 2**64 + 1), id="attempts-2^64+1"),
    pytest.param(lambda d: _set_attempts(d, 10**400), id="attempts-10^400"),
    pytest.param(_spread_attempts, id="aggregate-over-budget"),
    pytest.param(_record_sum_over_budget, id="record-sum-over-budget"),
    pytest.param(_successes_exceed_trials, id="successes>trials"),
    pytest.param(_trials_exceed_persisted, id="trials>persisted"),
    pytest.param(_huge_successes, id="huge-successes"),
]


@pytest.mark.parametrize("mutate", _FORGERIES)
def test_bundle_count_forgeries_rejected_in_every_input_form(mutate) -> None:
    doc = _bundle_doc()
    mutate(doc)
    text = _reseal(doc)
    with pytest.raises(BundleError):
        load_bundle(text)
    with pytest.raises(ReplayError):
        replay_bundle(text)
    with pytest.raises(ReplayError):
        replay_bundle(text.encode("utf-8"))
    with pytest.raises(ReplayError):
        replay_bundle(Bundle(content=json.loads(text)))


def test_reported_repro_attempts_257_count_288_is_rejected() -> None:
    doc = _bundle_doc()
    _set_attempts(doc, 257)
    assert doc["request_count"] == 288
    with pytest.raises(ReplayError, match="budget|commitment"):
        replay_bundle(_reseal(doc))


def _evidence(doc: dict) -> list[CaseEvidence]:
    return [
        CaseEvidence(
            case_id=r["case_id"], kind=r["kind"], status=r["finding"]["status"],
            proof=r["finding"]["proof"], attack_trials=r["finding"]["attack_trials"],
            successes=r["finding"]["successes"], trials=r["trials"], pack_id=r["pack_id"],
            family=r["family"], prompt=r["prompt"],
        )
        for r in doc["records"]
    ]


@pytest.mark.parametrize("mutate", _FORGERIES)
def test_public_contract_objects_reject_count_forgeries(mutate) -> None:
    plan = _plan()
    doc = _bundle_doc()
    identity = RunIdentity.verify_persisted(
        plan.digest,
        doc["canary_commitment"],
        doc["disclosure_marker_commitment"],
        doc["canary"],
        doc["disclosure_marker"],
    )
    verify_records(
        plan,
        resolve_plan_packs(plan),
        doc["canary"],
        _evidence(doc),
        doc["disclosure_marker"],
        identity,
    )  # genuine passes
    mutate(doc)
    with pytest.raises(EvidenceError):
        verify_records(
            plan,
            resolve_plan_packs(plan),
            doc["canary"],
            _evidence(doc),
            doc["disclosure_marker"],
            identity,
        )


def _checkpoint(tmp_path) -> tuple[object, str, dict]:
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


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda d: _ck_attack(d)["trials"][0].__setitem__("attempts", 257), id="257"),
        pytest.param(
            lambda d: _ck_attack(d)["trials"][0].__setitem__("attempts", 10**400), id="10^400"
        ),
        pytest.param(lambda d: d.__setitem__("request_count", 257), id="request-count-257"),
        pytest.param(lambda d: d.__setitem__("request_count", 2**64 + 1), id="request-count-2^64"),
        pytest.param(
            lambda d: [
                t.__setitem__("attempts", 100)
                for r in d["completed"].values() for t in r["trials"]
            ],
            id="aggregate-over-budget",
        ),
        pytest.param(lambda d: _ck_attack(d).__setitem__("successes", 4), id="successes>trials"),
    ],
)
def test_checkpoint_count_forgeries_rejected(tmp_path, mutate) -> None:
    plan, path, data = _checkpoint(tmp_path)
    assert data["request_count"] == 32
    mutate(data)
    _write(path, data)
    with pytest.raises(CheckpointError):
        load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)  # type: ignore[attr-defined]


# --- (2) boundary-spanning secret in proof -----------------------------------------

_SECRET = "Zq9xVv7Kp3Lm8Nw2Rt6Yb1Hc5"  # pragma: allowlist secret (opaque synthetic)


def _fragments(secret: str, minimum: int = 4) -> set[str]:
    return {
        secret[i:j]
        for i in range(len(secret))
        for j in range(i + minimum, len(secret) + 1)
    }


@pytest.mark.parametrize("side", ["right", "left"])
def test_boundary_spanning_secret_never_persists_in_checkpoint(tmp_path, side) -> None:
    plan = _plan()
    path = str(tmp_path / "run.ckpt")

    def responder(case: InjectionCase) -> ExchangeOutcome:
        if "{canary}" not in case.template:
            return ExchangeOutcome(body="benign synthetic answer")
        token = re.search(r"AISCAN-[A-Z0-9]+", case.rendered_prompt).group(0)  # type: ignore[union-attr]
        if side == "right":
            # Secret starts 30 chars after the canary: straddles the +40 window edge.
            body = f"Result {token} " + "x" * 29 + _SECRET + " trailing text"
        else:
            # Secret ends 30 chars before the canary: straddles the -40 window edge.
            body = "lead " + _SECRET + "y" * 29 + f" {token} done"
        return ExchangeOutcome(body=body, known_secrets=frozenset({_SECRET}))

    collector = BundleCollector()
    live = run_plan(
        plan, responder, canary=_CANARY, checkpoint_path=path, observer=collector.observe
    )
    assert any(f.status.value == "confirmed" for f in live.findings)

    on_disk = open(path, encoding="utf-8").read()  # noqa: SIM115
    leaked = sorted(f for f in _fragments(_SECRET) if f in on_disk)
    assert leaked == [], f"secret fragments persisted: {leaked[:3]}"
    for finding in live.findings:
        assert finding.proof is None or not any(f in finding.proof for f in _fragments(_SECRET))

    restored = load_checkpoint(path, expected_plan_digest=plan.digest, plan=plan)
    proofs = [r["proof"] for r in restored.completed.values() if r["status"] == "confirmed"]
    assert proofs and all("AISCAN-EVIDENCE-" in p for p in proofs)
    assert all(PERSISTED_CANARY not in p for p in proofs)
    assert all(_CANARY not in p for p in proofs)

    calls: list[str] = []

    def no_more(case: InjectionCase) -> ExchangeOutcome:
        calls.append(case.template)
        return responder(case)

    resumed = run_plan(plan, no_more, canary=_CANARY, checkpoint_path=path)
    assert calls == []
    assert {f.status.value for f in resumed.findings} == {f.status.value for f in live.findings}

    text = dump_bundle(collector.build(plan=plan, canary=_CANARY, run_id="boundary"))
    assert not [f for f in _fragments(_SECRET) if f in text]
    assert replay_bundle(text).verified
    assert copy.deepcopy(json.loads(text))["request_count"] == 32


# --- (3) M6: plugins run at least the resolved mode policy ---------------------------

_AC = "AISCAN-M6MODE0001"
_HC = "AISCAN-M6MODEHID01"


@pytest.mark.parametrize("mode", ["reliable", "kitchen-sink"])
def test_builtin_plugin_runs_resolved_mode_trial_policy(mode) -> None:
    plugin = DirectInjectionPlugin()
    assert (plugin.trial_policy.min_attack_trials, plugin.trial_policy.min_successes) == (1, 1)
    policy = resolve_policy(mode)
    ctx = AttackContext(attack_canary=_AC, hidden_canary=_HC, mode=mode)
    app = vulnerable_app(attack_canary=_AC, hidden_canary=_HC)
    calls: Counter[str] = Counter()

    def responder(case: AttackCase) -> ExchangeOutcome:
        calls[case.kind] += 1
        return app(case)

    cases = plugin.build_cases(ctx)
    result = run_attack(plugin, responder, ctx)
    attacks = sum(c.kind == "attack" for c in cases)
    controls = sum(c.kind == "control" for c in cases)
    assert calls["attack"] == policy.minimum_attack_trials * attacks
    assert calls["control"] == policy.minimum_control_trials * controls
    assert result.confirmed
    assert all(
        f.attack_trials == policy.minimum_attack_trials
        for f in result.findings if f.status.value == "confirmed"
    )


def test_builtin_plugin_single_execution_cannot_confirm_in_reliable() -> None:
    plugin = DirectInjectionPlugin()
    ctx = AttackContext(attack_canary=_AC, hidden_canary=_HC, mode="reliable")
    app = vulnerable_app(attack_canary=_AC, hidden_canary=_HC)
    seen: Counter[str] = Counter()

    def once(case: AttackCase) -> ExchangeOutcome:
        seen[case.prompt] += 1
        if case.kind == "attack" and seen[case.prompt] > 1:
            return ExchangeOutcome(body="I can't help with that.")
        return app(case)

    result = run_attack(plugin, once, ctx)
    assert not result.confirmed
