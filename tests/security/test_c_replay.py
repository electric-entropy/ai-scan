"""Phase C / M9 — offline replay CLI + bundle evidence integrity."""

from __future__ import annotations

import json

import pytest

from ai_scan import cli
from ai_scan.evidence_graph import (
    BundleCollector,
    BundleError,
    ReplayError,
    dump_bundle,
    load_bundle,
    replay_bundle,
)
from ai_scan.injection import ExchangeOutcome
from ai_scan.orchestration import compile_plan
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target
from tests.trusted_engines import run_plan

_CANARY = "AISCAN-CREPLAY01"


def _responder(case):  # type: ignore[no-untyped-def]
    body = f"model output: {_CANARY} (executed)" if "{canary}" in case.template else "benign"
    return ExchangeOutcome(body=body)


def _bundle_file(tmp_path) -> str:
    plan = compile_plan(normalize_target("http://127.0.0.1:9/chat"), "reliable")
    collector = BundleCollector()
    run_plan(plan, _responder, canary=_CANARY, goal="", observer=collector.observe)
    path = tmp_path / "bundle.json"
    path.write_text(
        dump_bundle(collector.build(plan=plan, canary=_CANARY, run_id="run-c")),
        encoding="utf-8",
    )
    return str(path)


def _redigest(path: str, mutate) -> None:
    data = json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115
    mutate(data)
    data.pop("digest", None)
    data["digest"] = compute_digest(data)
    open(path, "w", encoding="utf-8").write(json.dumps(data))  # noqa: SIM115


def test_bundle_export_scrubs_transport_known_secrets(tmp_path) -> None:
    """A transport-known secret (not globally pattern-shaped) must never be
    written into an exported bundle, even when it appears in response bodies."""
    secret = "CUSTOM_SHARED_BODY_SECRET_42"
    plan = compile_plan(normalize_target("http://127.0.0.1:9/chat"), "reliable")
    collector = BundleCollector()

    def responder(case):  # type: ignore[no-untyped-def]
        body = (
            f"model output {_CANARY} {secret}"
            if "{canary}" in case.template
            else f"benign {secret}"
        )
        return ExchangeOutcome(body=body, known_secrets=frozenset({secret}))

    run_plan(plan, responder, canary=_CANARY, goal="", observer=collector.observe)
    text = dump_bundle(collector.build(plan=plan, canary=_CANARY, run_id="secret-repro"))
    assert secret not in text
    # The scrubbed bundle must still load (fail-open on a scrubbed value is wrong,
    # fail-closed acceptance of a raw secret is the bug we are closing).
    load_bundle(text)


def test_bundle_export_scrubs_multiple_secrets_and_provenance(tmp_path) -> None:
    """Multiple secrets across records, plus a secret in provenance, are all
    scrubbed at export, and the scrubbed bundle still replays as confirmed."""
    s1, s2, s3 = "SECRET_ALPHA_11", "SECRET_BETA_22", "SECRET_PROV_33"
    plan = compile_plan(normalize_target("http://127.0.0.1:9/chat"), "reliable")
    collector = BundleCollector()

    seen: list[str] = []

    def responder(case):  # type: ignore[no-untyped-def]
        # Alternate the secret per case so multiple distinct secrets accumulate.
        secret = s1 if len(seen) % 2 == 0 else s2
        seen.append(secret)
        body = (
            f"model output {_CANARY} {secret}"
            if "{canary}" in case.template
            else f"benign {secret}"
        )
        return ExchangeOutcome(body=body, known_secrets=frozenset({secret}))

    result = run_plan(plan, responder, canary=_CANARY, goal="g", observer=collector.observe)
    bundle = collector.build(
        plan=plan,
        canary=_CANARY,
        run_id="multi",
        provenance={"operator": f"key={s3}"},
        known_secrets=frozenset({s3}),
    )
    text = dump_bundle(bundle)
    for secret in (s1, s2, s3):
        assert secret not in text
    # Scrubbed bundle still verifies, and confirmed findings stay confirmed.
    replayed = replay_bundle(text)
    assert replayed.verified
    assert any(s == "confirmed" for s in replayed.findings.values())
    assert any(f.status.value == "confirmed" for f in result.findings)


def test_replay_cli_error_never_leaks_secret(tmp_path, capsys) -> None:
    """An invalid/tampered bundle's CLI error must not echo any raw secret."""
    secret = "CLI_LEAK_SECRET_99"
    plan = compile_plan(normalize_target("http://127.0.0.1:9/chat"), "reliable")
    collector = BundleCollector()

    def responder(case):  # type: ignore[no-untyped-def]
        body = f"model output {_CANARY} {secret}" if "{canary}" in case.template else "benign"
        return ExchangeOutcome(body=body, known_secrets=frozenset({secret}))

    run_plan(plan, responder, canary=_CANARY, goal="", observer=collector.observe)
    path = tmp_path / "b.json"
    # Tamper AFTER export (breaks the digest) — the error path must stay scrubbed.
    text = dump_bundle(collector.build(plan=plan, canary=_CANARY, run_id="leak"))
    path.write_text(text.replace("model output", "MUTATED output"), encoding="utf-8")
    rc = cli.main(["replay", "--bundle", str(path), "--validate-only"])
    assert rc == cli.EXIT_RUNTIME_ERROR
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err


def test_replay_cli_validate_only_valid_bundle(tmp_path, capsys) -> None:
    rc = cli.main(["replay", "--bundle", _bundle_file(tmp_path), "--validate-only"])
    assert rc == cli.EXIT_OK
    assert "replayed:" in capsys.readouterr().out


def test_replay_cli_constructs_no_transport(tmp_path, monkeypatch) -> None:
    def boom(_controller):  # type: ignore[no-untyped-def]
        raise AssertionError("replay must not construct transport")

    monkeypatch.setattr(cli, "_make_transport", boom)
    rc = cli.main(["replay", "--bundle", _bundle_file(tmp_path), "--validate-only"])
    assert rc == cli.EXIT_OK


def test_replay_cli_tampered_bundle_exits_nonzero_scrubbed(tmp_path, capsys) -> None:
    path = _bundle_file(tmp_path)
    # Alter a record's proof without re-digesting → digest mismatch.
    data = json.loads(open(path, encoding="utf-8").read())  # noqa: SIM115
    data["records"][0]["finding"]["proof"] = "tampered"
    open(path, "w", encoding="utf-8").write(json.dumps(data))  # noqa: SIM115
    rc = cli.main(["replay", "--bundle", path, "--validate-only"])
    assert rc == cli.EXIT_RUNTIME_ERROR
    out = capsys.readouterr()
    assert "invalid" in out.out


def test_replay_rejects_bare_canary_confirmed_evidence(tmp_path) -> None:
    # Re-digest a bundle whose confirmed record keeps its claimed 3/3 counts but
    # whose persisted evidence is a single bare public canary: an exact-token
    # confirmation needs every persisted trial, so replay must fail closed.
    path = _bundle_file(tmp_path)

    def mutate(data: dict) -> None:
        for record in data["records"]:
            if record["kind"] == "attack" and record["finding"]["status"] == "confirmed":
                trial = dict(record["trials"][0], body=_CANARY)  # bare public canary only
                data["request_count"] -= sum(t["attempts"] for t in record["trials"][1:])
                record["trials"] = [trial]
                break

    _redigest(path, mutate)
    rc = cli.main(["replay", "--bundle", path, "--validate-only"])
    assert rc == cli.EXIT_RUNTIME_ERROR


def test_replay_cli_missing_bundle_file_scrubbed(tmp_path) -> None:
    rc = cli.main(["replay", "--bundle", str(tmp_path / "nope.json"), "--validate-only"])
    assert rc == cli.EXIT_RUNTIME_ERROR


def test_replay_rejects_unknown_metadata_field(tmp_path) -> None:
    path = _bundle_file(tmp_path)

    def mutate(data: dict) -> None:
        data["metadata"]["injected"] = "surprise"

    _redigest(path, mutate)
    with pytest.raises(BundleError):
        load_bundle(open(path, encoding="utf-8").read())  # noqa: SIM115
    rc = cli.main(["replay", "--bundle", path, "--validate-only"])
    assert rc == cli.EXIT_RUNTIME_ERROR


def _first_attack(data: dict) -> dict:
    for record in data["records"]:
        if record["kind"] == "attack" and record["finding"]["status"] == "confirmed":
            return record
    raise AssertionError("no confirmed attack record in sample bundle")


def _tampered_bundle_text(tmp_path, mutate) -> str:
    """Build a valid bundle, apply ``mutate`` to its dict, and RE-DIGEST it.

    Re-digesting is the whole point: a naive digest check would accept the
    forgery, so the plan-binding must reject it on content, not on the digest.
    """
    from ai_scan.packs.signatures import compute_digest

    data = json.loads(open(_bundle_file(tmp_path), encoding="utf-8").read())  # noqa: SIM115
    mutate(data)
    data.pop("digest", None)
    data["digest"] = compute_digest(data)
    return json.dumps(data)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(
            lambda d: _first_attack(d).__setitem__("prompt", "unrelated prompt, no canary"),
            id="prompt",
        ),
        pytest.param(
            lambda d: _first_attack(d).__setitem__("pack_id", "totally-bogus-pack"),
            id="pack_id",
        ),
        pytest.param(
            lambda d: _first_attack(d).__setitem__("family", "bogus-family"),
            id="family",
        ),
        pytest.param(
            lambda d: _first_attack(d).__setitem__("kind", "control"),
            id="kind",
        ),
        pytest.param(
            lambda d: _first_attack(d).__setitem__("case_id", "case-does-not-exist"),
            id="unknown-case",
        ),
    ],
)
def test_replay_binds_records_to_plan_case(tmp_path, mutate) -> None:
    """A re-digested record whose plan-bound fields are altered must fail closed."""
    text = _tampered_bundle_text(tmp_path, mutate)
    with pytest.raises(ReplayError):
        replay_bundle(text)


@pytest.mark.parametrize(
    "inflated",
    [
        pytest.param(8, id="above-policy-ceiling"),
        pytest.param(10**500, id="overflow-absurd"),
    ],
)
def test_replay_rejects_inflated_attack_trials(tmp_path, inflated) -> None:
    """attack_trials beyond the plan's per-case physical ceiling must fail closed.

    The runner runs at most ``trial_policy[0]`` attempts per attack case, so a
    re-digested bundle that inflates attack_trials (keeping successes consistent
    so status still re-derives to confirmed) cannot be substantiated by the plan.
    """

    def mutate(data: dict) -> None:
        _first_attack(data)["finding"]["attack_trials"] = inflated

    with pytest.raises(ReplayError):
        replay_bundle(_tampered_bundle_text(tmp_path, mutate))


def test_replay_binds_control_prompt_to_plan_case(tmp_path) -> None:
    def mutate(data: dict) -> None:
        for record in data["records"]:
            if record["kind"] == "control":
                record["prompt"] = "forged control prompt"
                return
        raise AssertionError("no control record in sample bundle")

    with pytest.raises(ReplayError):
        replay_bundle(_tampered_bundle_text(tmp_path, mutate))


def test_replay_rejects_forged_tool_name(tmp_path) -> None:
    path = _bundle_file(tmp_path)

    def mutate(data: dict) -> None:
        data["metadata"]["tool"] = "not-ai-scan"

    _redigest(path, mutate)
    with pytest.raises(BundleError):
        load_bundle(open(path, encoding="utf-8").read())  # noqa: SIM115
