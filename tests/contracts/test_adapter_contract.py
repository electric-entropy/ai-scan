"""Adapter registry contract tests."""

from __future__ import annotations

from typing import cast

import pytest

from ai_scan.adapters import Adapter, AdapterConfigError, AdapterRegistry, default_registry
from ai_scan.adapters.base import AdapterCapabilities
from ai_scan.targets import normalize_target


def test_default_registry_lists_builtin_adapters_without_config() -> None:
    registry = default_registry()
    assert registry.names() == ["captured_http", "generic_http"]
    assert registry.capabilities("generic_http").name == "generic_http"
    assert registry.capabilities("captured_http").name == "captured_http"


def test_registry_create_surfaces_malformed_config_before_request_creation() -> None:
    registry = default_registry()
    with pytest.raises(AdapterConfigError):
        registry.create(
            "generic_http",
            target=normalize_target("http://mock.local/chat"),
            method="POST",
            body_template="no marker",
        )


def test_unknown_adapter_fails_closed() -> None:
    registry = default_registry()
    with pytest.raises(AdapterConfigError):
        registry.capabilities("missing")
    with pytest.raises(AdapterConfigError):
        registry.create("missing")


def test_duplicate_registration_rejected() -> None:
    registry = AdapterRegistry()
    caps = AdapterCapabilities(
        name="x",
        methods=frozenset({"GET"}),
        prompt_encodings=frozenset({"raw"}),
        extraction_modes=frozenset({"text"}),
    )
    registry.register("x", lambda: cast(Adapter, object()), caps)
    with pytest.raises(AdapterConfigError):
        registry.register("x", lambda: cast(Adapter, object()), caps)
