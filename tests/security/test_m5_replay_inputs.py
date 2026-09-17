"""Step 1B / Astra M5 — replay fully validates every input form.

``replay_bundle`` accepts a bundle as JSON text/bytes or as an in-memory
:class:`Bundle`. Every form passes the same full validation (digests, canonical
plan, graph, closed record schema, per-trial evidence contract), and an
in-memory ``Bundle`` is an immutable snapshot: mutating the source mapping, the
returned ``content``, or overriding accessors in a subclass can never change what
replay verifies.
"""

from __future__ import annotations

import copy
import json

import pytest

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
from ai_scan.orchestration import compile_plan, run_plan
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target

_CANARY = "AISCAN-M5REPLAY0001"


def _responder(case: InjectionCase) -> ExchangeOutcome:
    if "{canary}" in case.template:
        return ExchangeOutcome(body=f"Executed: {_CANARY}")
    return ExchangeOutcome(body="benign synthetic answer")


def _refusing(case: InjectionCase) -> ExchangeOutcome:
    return ExchangeOutcome(body="I can't help with that.")


def _bundle(responder=_responder) -> Bundle:  # type: ignore[no-untyped-def]
    plan = compile_plan(normalize_target("http://127.0.0.1:8766/chat"), "reliable")
    collector = BundleCollector()
    run_plan(plan, responder, canary=_CANARY, observer=collector.observe)
    return collector.build(plan=plan, canary=_CANARY, run_id="m5")


def _confirmed_attack(content: dict) -> dict:
    return next(
        r for r in content["records"]
        if r["kind"] == "attack" and r["finding"]["status"] == "confirmed"
    )


def test_text_bytes_and_bundle_forms_replay_identically() -> None:
    bundle = _bundle()
    text = dump_bundle(bundle)
    from_text = replay_bundle(text)
    from_bytes = replay_bundle(text.encode("utf-8"))
    from_bundle = replay_bundle(bundle)
    assert from_text == from_bytes == from_bundle
    assert "confirmed" in set(from_bundle.findings.values())
    assert set(from_bundle.findings.values()) <= {"confirmed", "not_observed"}


def test_in_memory_bundle_with_unsealed_forgery_is_rejected() -> None:
    content = copy.deepcopy(_bundle().content)
    _confirmed_attack(content)["finding"]["status"] = "not_observed"
    with pytest.raises(ReplayError):
        replay_bundle(Bundle(content=content))


def test_in_memory_bundle_with_resealed_evidence_forgery_is_rejected() -> None:
    content = copy.deepcopy(_bundle(_refusing).content)
    attack = next(r for r in content["records"] if r["kind"] == "attack")
    attack["finding"]["status"] = "confirmed"
    attack["finding"]["proof"] = _CANARY
    content.pop("digest")
    content["digest"] = compute_digest(content)
    with pytest.raises(ReplayError):
        replay_bundle(Bundle(content=content))


def test_in_memory_bundle_missing_fields_is_rejected() -> None:
    content = copy.deepcopy(_bundle().content)
    del content["graph"]
    with pytest.raises(ReplayError):
        replay_bundle(Bundle(content=content))


def test_mutating_source_mapping_after_construction_has_no_effect() -> None:
    source = copy.deepcopy(_bundle().content)
    bundle = Bundle(content=source)
    before = dump_bundle(bundle)
    source["records"].clear()
    source["canary"] = "AISCAN-FORGED"
    assert dump_bundle(bundle) == before
    assert replay_bundle(bundle) == replay_bundle(before)


def test_mutating_returned_content_has_no_effect() -> None:
    bundle = _bundle()
    expected = replay_bundle(dump_bundle(bundle))
    view = bundle.content
    _confirmed_attack(view)["finding"]["status"] = "not_observed"
    view["records"].clear()
    assert bundle.content is not view
    assert bundle.content["records"]
    assert replay_bundle(bundle) == expected


def test_mutating_loaded_bundle_records_has_no_effect() -> None:
    bundle = load_bundle(dump_bundle(_bundle()))
    expected = replay_bundle(bundle)
    records = bundle.records
    records.clear()
    bundle.content["records"].clear()
    assert replay_bundle(bundle) == expected


def test_bundle_attributes_are_immutable() -> None:
    bundle = _bundle()
    with pytest.raises((AttributeError, TypeError)):
        bundle.content = {}  # type: ignore[misc]
    with pytest.raises((AttributeError, TypeError)):
        bundle._text = "{}"  # type: ignore[attr-defined]  # noqa: SLF001


def test_subclass_accessor_overrides_cannot_steer_replay() -> None:
    genuine = _bundle(_refusing)
    forged_content = copy.deepcopy(_bundle().content)

    class Sneaky(Bundle):
        @property
        def content(self):  # type: ignore[no-untyped-def,override]
            return forged_content

        @property
        def records(self):  # type: ignore[no-untyped-def,override]
            return forged_content["records"]

        @property
        def canary(self):  # type: ignore[no-untyped-def,override]
            return _CANARY

    sneaky = Sneaky(content=genuine.content)
    result = replay_bundle(sneaky)
    assert result == replay_bundle(dump_bundle(genuine))
    assert "confirmed" not in set(result.findings.values())


@pytest.mark.parametrize(
    "value",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(object(), id="object"),
        pytest.param({1, 2}, id="set"),
    ],
)
def test_bundle_rejects_non_json_content(value) -> None:
    content = copy.deepcopy(_bundle().content)
    content["metadata"]["provenance"]["x"] = value
    with pytest.raises(BundleError):
        Bundle(content=content)


@pytest.mark.parametrize(
    "source",
    [
        pytest.param(None, id="none"),
        pytest.param(42, id="int"),
        pytest.param({"bundle_version": 2}, id="dict"),
        pytest.param(["x"], id="list"),
        pytest.param(b"\xff\xfe not utf-8", id="bad-bytes"),
        pytest.param("", id="empty"),
    ],
)
def test_unsupported_or_invalid_sources_fail_closed(source) -> None:
    with pytest.raises(ReplayError):
        replay_bundle(source)  # type: ignore[arg-type]


def test_valid_dict_is_not_accepted_without_a_bundle_boundary() -> None:
    content = json.loads(dump_bundle(_bundle()))
    with pytest.raises(ReplayError):
        replay_bundle(content)  # type: ignore[arg-type]
