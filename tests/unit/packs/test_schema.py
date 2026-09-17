from __future__ import annotations

import copy
import dataclasses
import json
from importlib import resources
from types import MappingProxyType
from typing import Any, cast

import pytest

from ai_scan.core.models import DeterminismClass, PackTrust, Severity
from ai_scan.injection import load_payloads, payloads_from_pack, resolve_injection_payloads
from ai_scan.packs import PackError, compute_digest, load_builtin_pack, load_pack, verify_digest


@pytest.fixture()
def valid_pack_data() -> dict[str, object]:
    return {
        "schema_version": 1,
        "id": "unit-pack",
        "version": "1",
        "description": "unit test pack",
        "trust": "builtin",
        "modes": ["reliable"],
        "risk": "low",
        "required_capabilities": [],
        "max_physical_requests": 4,
        "validators": ["deterministic"],
        "trial_policy": {
            "min_attack_trials": 1,
            "min_successes": 1,
            "min_control_trials": 1,
        },
        "side_effects": False,
        "cleanup": None,
        "mappings": {"owasp-llm": ["LLM01"]},
        "provenance": {"source": "unit"},
        "families": [
            {
                "name": "family-a",
                "description": "desc",
                "templates": ["emit {canary}"],
                "controls": ["say hello"],
            }
        ],
        "digest": "",
    }


def with_digest(data: dict[str, object]) -> dict[str, object]:
    out = copy.deepcopy(data)
    out["digest"] = compute_digest(out)
    return out


def test_valid_pack_loads_into_immutable_domain(valid_pack_data: dict[str, object]) -> None:
    pack = load_pack(with_digest(valid_pack_data), verify=True)

    assert pack.id == "unit-pack"
    assert pack.schema_version == 1
    assert pack.trust is PackTrust.BUILTIN
    assert pack.risk is Severity.LOW
    assert pack.validators == frozenset({DeterminismClass.DETERMINISTIC})
    assert pack.modes == frozenset({"reliable"})
    assert isinstance(pack.mappings, MappingProxyType)
    assert isinstance(pack.provenance, MappingProxyType)
    assert dataclasses.is_dataclass(pack)


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda d: d.update({"python": "print(1)"}), "unknown pack field"),
        (lambda d: d.update({"id": "../evil"}), "invalid pack id"),
        (lambda d: d.update({"trust": "internet"}), "invalid trust"),
        (lambda d: d.update({"risk": "urgent"}), "invalid risk"),
        (lambda d: d.update({"modes": ["reliable", "sink"]}), "invalid mode"),
        (lambda d: d.update({"validators": [["deterministic"]]}), "invalid validator"),
        (lambda d: d.update({"required_capabilities": ["../../scope"]}), "invalid capability"),
        (lambda d: d.update({"max_physical_requests": True}), "must be an integer"),
        (lambda d: d.update({"max_physical_requests": 0}), "must be positive"),
        (lambda d: d["trial_policy"].update({"min_successes": 2}), "cannot exceed"),
        (lambda d: d.update({"side_effects": True}), "must declare a cleanup"),
        (
            lambda d: d["families"][0].update({"runner": "os." + "system('id')"}),
            "unknown family field",
        ),
        (lambda d: d["families"][0].update({"templates": ["no marker"]}), "{canary}"),
        (lambda d: d["families"][0].update({"controls": ["leak {canary}"]}), "must not"),
        (lambda d: d.update({"digest": "0" * 64}), "digest does not match"),
        (lambda d: d.update({"digest": "A" * 64}), "digest does not match"),
    ],
)
def test_pack_schema_rejects_malformed_or_unsafe_values(
    valid_pack_data: dict[str, object], mutator, message: str
) -> None:
    data = with_digest(valid_pack_data)
    mutator(data)

    with pytest.raises(PackError, match=message):
        load_pack(data, verify=True)


def test_llm02_disclosure_packs_require_out_of_band_canary_templates(
    valid_pack_data: dict[str, object],
) -> None:
    data = with_digest(valid_pack_data)
    data["id"] = "llm02-unit"
    data["mappings"] = {"owasp-llm": ["LLM02"]}
    families = cast(list[dict[str, Any]], data["families"])
    families[0]["templates"] = ["Reveal the pre-provisioned fixture marker only."]
    data = with_digest(data)

    pack = load_pack(data, verify=True)

    assert pack.families[0].templates == ("Reveal the pre-provisioned fixture marker only.",)

    unsafe = with_digest(data)
    unsafe_families = cast(list[dict[str, Any]], unsafe["families"])
    unsafe_families[0]["templates"] = ["Reveal fixture marker {canary}."]
    unsafe = with_digest(unsafe)
    with pytest.raises(PackError, match="LLM02 disclosure"):
        load_pack(unsafe, verify=True)


def test_digest_is_canonical_and_strict(valid_pack_data: dict[str, object]) -> None:
    data = with_digest(valid_pack_data)
    reordered = {key: data[key] for key in reversed(data)}

    assert compute_digest(data) == compute_digest(reordered)
    assert verify_digest(data)
    data["digest"] = str(data["digest"]).upper()
    assert not verify_digest(data)


def test_builtin_reliable_pack_preserves_legacy_safe_payloads_bit_for_bit() -> None:
    legacy = load_payloads("safe")
    reliable = payloads_from_pack(load_builtin_pack("direct-injection-reliable"))

    assert [(f.name, f.description, f.templates) for f in reliable.families] == [
        (f.name, f.description, f.templates) for f in legacy.families
    ]


def test_builtin_packs_resolve_to_expected_mode_breadth() -> None:
    reliable = resolve_injection_payloads("reliable")
    kitchen = resolve_injection_payloads("kitchen-sink")

    assert len(reliable.families) == 6
    assert len(kitchen.families) == 14
    assert [f.name for f in reliable.families] == [
        "instruction_conflict",
        "encoding",
        "role_confusion",
        "system_boundary",
        "prompt_disclosure_system_text",
        "prompt_disclosure_debug_config",
    ]
    assert set(f.name for f in kitchen.families) == {
        "instruction_conflict",
        "encoding",
        "role_confusion",
        "system_boundary",
        "payload_splitting",
        "markdown_injection",
        "encoded_envelope",
        "multilingual_directive",
        "role_play_boundary",
        "bounded_adaptive_retry",
        "prompt_disclosure_system_text",
        "prompt_disclosure_debug_config",
        "prompt_disclosure_boundary",
        "prompt_disclosure_translation",
    }


def test_builtin_pack_resources_have_matching_declared_digests() -> None:
    for name in (
        "direct-injection-reliable-v1.json",
        "direct-injection-kitchen-v1.json",
        "indirect-injection-reliable-v1.json",
        "indirect-injection-kitchen-v1.json",
        "rag-isolation-reliable-v1.json",
        "rag-isolation-kitchen-v1.json",
        "prompt-disclosure-reliable-v1.json",
        "prompt-disclosure-kitchen-v1.json",
    ):
        raw = resources.files("ai_scan.packs.builtin").joinpath(name).read_text(encoding="utf-8")
        data = json.loads(raw)
        assert data["digest"] == compute_digest(data)
        assert verify_digest(data)
