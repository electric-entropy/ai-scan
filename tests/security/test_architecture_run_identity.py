"""Architecture regressions for one checkpoint/bundle run identity."""

from __future__ import annotations

import json

import pytest

from ai_scan.evidence_graph import build_bundle, dump_bundle, load_bundle
from ai_scan.injection import generate_canary
from ai_scan.orchestration import compile_plan
from ai_scan.targets import normalize_target


def _empty(*, canary: str, marker: str | None):  # type: ignore[no-untyped-def]
    plan = compile_plan(normalize_target("http://127.0.0.1:8000/chat"), "reliable")
    return build_bundle(
        plan=plan,
        records=[],
        canary=canary,
        disclosure_marker=marker,
        run_id="architecture-run",
    )


def test_empty_bundle_commits_canary_and_present_or_absent_marker_identity() -> None:
    canary = generate_canary()
    other_canary = generate_canary()
    first_marker = generate_canary()
    second_marker = generate_canary()

    first = _empty(canary=canary, marker=first_marker).content
    second = _empty(canary=canary, marker=second_marker).content
    absent = _empty(canary=canary, marker=None).content
    other = _empty(canary=other_canary, marker=first_marker).content

    assert first["bundle_version"] == 3
    assert first["canary_commitment"] == second["canary_commitment"]
    assert first["canary_commitment"] != other["canary_commitment"]
    assert first["disclosure_marker_commitment"] != second["disclosure_marker_commitment"]
    assert first["disclosure_marker_commitment"] != absent["disclosure_marker_commitment"]
    assert first["canary"] != other["canary"]
    assert first["disclosure_marker"] != second["disclosure_marker"]
    assert absent["disclosure_marker"] is None
    assert first["digest"] != second["digest"]
    assert first["digest"] != absent["digest"]


@pytest.mark.parametrize("field", ["canary_commitment", "disclosure_marker_commitment"])
def test_bundle_load_rejects_identity_commitment_or_pseudonym_relabel(field: str) -> None:
    bundle = _empty(canary=generate_canary(), marker=generate_canary())
    document = bundle.content
    document[field] = "0" * 64
    document.pop("digest")
    from ai_scan.packs.signatures import compute_digest

    document["digest"] = compute_digest(document)
    with pytest.raises(Exception, match="identity|commitment"):
        load_bundle(json.dumps(document))


def test_valid_empty_bundle_round_trips_with_verified_identity() -> None:
    bundle = _empty(canary=generate_canary(), marker=generate_canary())
    loaded = load_bundle(dump_bundle(bundle))
    assert loaded.content == bundle.content
