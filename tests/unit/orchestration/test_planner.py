from __future__ import annotations

import json
from dataclasses import replace

import pytest

from ai_scan.orchestration import (
    PlanError,
    PlanLimits,
    PlannedCase,
    compile_plan,
    load_plan,
    plan_to_dict,
)
from ai_scan.orchestration.scheduler import schedule
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target


def test_compile_plan_is_offline_and_deterministic() -> None:
    target = normalize_target("https://Example.com:443/path")

    first = compile_plan(target, "reliable", seed=7)
    second = compile_plan(target, "reliable", seed=7)

    assert first.origin == "https://example.com"
    assert first.digest == second.digest
    assert first.cases
    assert first.control_cases()
    assert first.attack_cases()
    assert load_plan(plan_to_dict(first)) == first


def test_reliable_schedule_is_serial_sorted() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable", seed=99)

    scheduled = schedule(plan)

    assert scheduled.max_concurrency == 1
    assert [c.case_id for c in scheduled.order] == sorted(c.case_id for c in plan.attack_cases())


def test_kitchen_sink_schedule_is_seeded_and_bounded() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "kitchen-sink", seed=42)

    first = schedule(plan)
    second = schedule(plan)

    assert first == second
    assert first.max_concurrency == plan.limits.max_concurrency
    assert sorted(c.case_id for c in first.order) == sorted(c.case_id for c in plan.attack_cases())


def test_load_plan_rejects_tampering() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    data = plan_to_dict(plan)
    data["origin"] = "http://evil.local"

    with pytest.raises(PlanError, match="digest"):
        load_plan(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("seed", True),
        ("limits", [True, 1, 1.0, 1]),
        ("trial_policy", [1, False, 1]),
    ],
)
def test_load_plan_rejects_malformed_but_redigested_fields(field, value) -> None:  # type: ignore[no-untyped-def]
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    data = plan_to_dict(plan)
    data[field] = value
    data["digest"] = compute_digest(data)

    with pytest.raises(PlanError, match="malformed"):
        load_plan(data)


def test_load_plan_rejects_extra_fields_even_when_redigested() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    data = plan_to_dict(plan)
    data["unexpected"] = "value"
    data["digest"] = compute_digest(data)

    with pytest.raises(PlanError, match="unknown"):
        load_plan(data)


def test_load_plan_rejects_noncanonical_origin_and_inconsistent_case_id() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    data = plan_to_dict(plan)
    data["origin"] = "http://127.0.0.1:8000/path"
    data["digest"] = compute_digest(data)
    with pytest.raises(PlanError, match="malformed"):
        load_plan(data)

    data = plan_to_dict(plan)
    data["cases"][0][0] = "direct-injection-reliable:wrong:attack:0"
    data["digest"] = compute_digest(data)
    with pytest.raises(PlanError, match="malformed"):
        load_plan(data)


def test_plan_domain_constructors_fail_closed_through_replace() -> None:
    plan = compile_plan(normalize_target("http://127.0.0.1:8000"), "reliable")
    with pytest.raises(PlanError):
        PlanLimits(
            max_physical_requests=True,  # type: ignore[arg-type]
            max_concurrency=1,
            requests_per_second=1.0,
            max_duration_seconds=1,
        )
    with pytest.raises(PlanError):
        PlannedCase("id", "pack", "family", 0, "unknown", "template")
    with pytest.raises(PlanError):
        replace(plan, seed=True)  # type: ignore[arg-type]


def test_plan_command_writes_secret_free_json(tmp_path, capsys) -> None:
    from ai_scan.cli import main

    out = tmp_path / "plan.json"
    code = main(["plan", "--target", "http://127.0.0.1:8000", "--out", str(out)])

    assert code == 0
    assert capsys.readouterr().out == ""
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["origin"] == "http://127.0.0.1:8000"
    assert "digest" in data
    assert "auth" not in data
    assert "secret" not in out.read_text(encoding="utf-8").lower()


def test_plan_command_constructs_no_transport(monkeypatch, capsys) -> None:
    # `ai-scan plan` must be fully offline: it never builds a transport.
    from ai_scan import cli

    def boom(_controller):  # type: ignore[no-untyped-def]
        raise AssertionError("plan must not construct transport")

    monkeypatch.setattr(cli, "_make_transport", boom)
    rc = cli.main(["plan", "--target", "http://127.0.0.1:8080/chat", "--mode", "reliable"])
    assert rc == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "direct-injection-reliable" in out


def _redigest(doc: dict) -> dict:
    import copy as _copy

    from ai_scan.packs.signatures import compute_digest

    out = _copy.deepcopy(doc)
    out.pop("digest", None)
    out["digest"] = compute_digest(out)
    return out


def _base_doc() -> dict:
    return plan_to_dict(compile_plan(normalize_target("http://127.0.0.1:8080/chat"), "reliable"))


def test_load_plan_accepts_valid_redigested_document() -> None:
    assert load_plan(_redigest(_base_doc())).mode == "reliable"


def _first_index(doc: dict, kind: str) -> int:
    return next(i for i, c in enumerate(doc["cases"]) if c[4] == kind)


def test_load_plan_rejects_redigested_malformed_documents() -> None:
    import copy

    def attempt(mutate) -> None:  # type: ignore[no-untyped-def]
        doc = copy.deepcopy(_base_doc())
        mutate(doc)
        with pytest.raises(PlanError):
            load_plan(_redigest(doc))

    attempt(lambda d: d.update(unexpected="x"))          # unknown top-level field
    attempt(lambda d: d.pop("adapter"))                  # missing top-level field
    attempt(lambda d: d.update(origin="not a url"))      # non-canonical origin
    attempt(lambda d: d.update(origin="http://127.0.0.1:8080/chat"))  # origin with path
    attempt(lambda d: d.__setitem__("packs", d["packs"] + d["packs"]))  # duplicate pack rows
    attempt(lambda d: d["cases"][_first_index(d, "attack")].__setitem__(0, "bad:id:attack:0"))
    attempt(
        lambda d: d["cases"].__setitem__(
            _first_index(d, "attack"),
            [*d["cases"][_first_index(d, "attack")][:5], "no marker here"],
        )
    )
    attempt(
        lambda d: d["cases"].__setitem__(
            _first_index(d, "control"),
            [*d["cases"][_first_index(d, "control")][:5], "leak {canary}"],
        )
    )
