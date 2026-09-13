"""Milestone 16: output handling, encoding, and multimodal groundwork."""

from __future__ import annotations

import json

import pytest

from ai_scan.adapters import AdapterConfigError, MultimodalAdapter, available_adapters
from ai_scan.attacks import (
    AttackContext,
    AttackError,
    EncodingPlugin,
    OutputHandlingPlugin,
    run_attack,
)
from ai_scan.attacks.base import AttackCase
from ai_scan.injection import ExchangeOutcome, InjectionStatus
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse
from tests.fixtures.apps import reflective_output_app, resistant_output_app, vulnerable_output_app

AC = "AISCAN-ENCODED-CANARY"
HC = "AISCAN-DOM-EVIDENCE"
TARGET = normalize_target("http://127.0.0.1:8080/multimodal")


def _ctx(
    mode: str = "reliable",
    *,
    capabilities: frozenset[str] = frozenset({"browser_render", "file_upload"}),
    identities: tuple[str, ...] = ("viewer",),
) -> AttackContext:
    return AttackContext(AC, HC, mode, capabilities, identities)


@pytest.mark.parametrize("plugin_cls", [OutputHandlingPlugin, EncodingPlugin])
def test_vulnerable_fixture_confirms_from_non_reflection_evidence(plugin_cls) -> None:
    result = run_attack(
        plugin_cls(), vulnerable_output_app(attack_canary=AC, hidden_canary=HC), _ctx()
    )
    assert result.confirmed


@pytest.mark.parametrize("plugin_cls", [OutputHandlingPlugin, EncodingPlugin])
def test_text_reflection_does_not_confirm(plugin_cls) -> None:
    result = run_attack(
        plugin_cls(), reflective_output_app(attack_canary=AC, hidden_canary=HC), _ctx()
    )
    assert not result.confirmed
    assert result.status is InjectionStatus.NOT_OBSERVED


@pytest.mark.parametrize("plugin_cls", [OutputHandlingPlugin, EncodingPlugin])
def test_resistant_fixture_has_zero_confirmed_findings(plugin_cls) -> None:
    result = run_attack(
        plugin_cls(), resistant_output_app(attack_canary=AC, hidden_canary=HC), _ctx()
    )
    assert not result.confirmed
    assert result.status is InjectionStatus.NOT_OBSERVED


def test_output_handling_requires_dom_evidence_capability_before_request() -> None:
    def must_not_call(_case: AttackCase) -> ExchangeOutcome:
        raise AssertionError("output handling must fail before responder calls")

    with pytest.raises(AttackError):
        run_attack(OutputHandlingPlugin(), must_not_call, _ctx(capabilities=frozenset()))


def test_encoding_prompts_do_not_contain_literal_success_canary() -> None:
    cases = EncodingPlugin().build_cases(_ctx("kitchen-sink"))
    assert all(AC not in c.prompt for c in cases if c.kind == "attack")
    assert len([c for c in cases if c.kind == "attack"]) > len(
        [c for c in EncodingPlugin().build_cases(_ctx("reliable")) if c.kind == "attack"]
    )


def test_output_kitchen_sink_broadens_cases_without_changing_gate() -> None:
    plugin = OutputHandlingPlugin()
    reliable = plugin.build_cases(_ctx("reliable"))
    kitchen = plugin.build_cases(_ctx("kitchen-sink"))
    assert len([c for c in kitchen if c.kind == "attack"]) > len(
        [c for c in reliable if c.kind == "attack"]
    )
    with pytest.raises(AttackError):
        plugin.build_cases(_ctx("kitchen-sink", capabilities=frozenset()))


def test_control_dom_or_decoded_canary_blocks_confirmation() -> None:
    def always_evidence(_case: AttackCase) -> ExchangeOutcome:
        return ExchangeOutcome(body=f"sandbox_dom_evidence={HC} decoded_authorized_canary={AC}")

    assert (
        run_attack(OutputHandlingPlugin(), always_evidence, _ctx()).status
        is InjectionStatus.POTENTIAL
    )
    assert run_attack(EncodingPlugin(), always_evidence, _ctx()).status is InjectionStatus.POTENTIAL


def test_multimodal_adapter_is_registered_and_shapes_only_synthetic_media() -> None:
    assert "multimodal" in available_adapters()
    adapter = MultimodalAdapter(
        target=TARGET,
        media_type="text/markdown",
        media_text="![synthetic](cid:local) hidden instruction fixture",
    )
    prepared = adapter.build_request("inspect this synthetic file")
    assert prepared.method == "POST"
    payload = json.loads(prepared.body.decode("utf-8"))
    assert payload["prompt"] == "inspect this synthetic file"
    assert payload["media"]["type"] == "text/markdown"


def test_multimodal_adapter_rejects_remote_or_binary_media_before_request() -> None:
    with pytest.raises(AdapterConfigError):
        MultimodalAdapter(target=TARGET, media_type="application/octet-stream", media_text="abc")
    with pytest.raises(AdapterConfigError):
        MultimodalAdapter(
            target=TARGET, media_type="text/plain", media_text="https://example.invalid/x"
        )
    with pytest.raises(AdapterConfigError):
        MultimodalAdapter(
            target=TARGET, media_type="text/plain", media_text="ok", extra_headers={"X": object()}
        )


def test_multimodal_adapter_extracts_bounded_text() -> None:
    adapter = MultimodalAdapter(
        target=TARGET,
        media_type="image/svg+xml",
        media_text="<svg><!-- synthetic --></svg>",
        max_chars=4,
    )
    response = HttpResponse(
        status=200,
        body=json.dumps({"output": "abcdef"}),
        headers={},
        redirected=False,
        redirect_location=None,
        truncated=False,
        request_line={"method": "POST", "url": TARGET.url},
    )
    assert adapter.extract(response) == "abcd"
