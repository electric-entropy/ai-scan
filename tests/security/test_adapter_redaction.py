"""Adapter config errors must be secret-free (central scrubbing at the boundary).

Every adapter configuration/extraction error that embeds an untrusted string
value must scrub it through the central redactor first, so a secret-like value
never survives in a public library exception message.
"""

from __future__ import annotations

import pytest

from ai_scan.adapters import (
    AdapterConfigError,
    CapturedHttpAdapter,
    ExtractionSpec,
    GenericHttpAdapter,
    default_registry,
)
from ai_scan.targets import normalize_target

# Credential-format literal that the central scrubber redacts on sight.
_SECRET = "ghp_abcdefghijklmnopqrstuvwxyz0123"  # pragma: allowlist secret
_TARGET = normalize_target("http://127.0.0.1:8080/chat")


def _assert_scrubbed(exc: Exception) -> None:
    message = str(exc)
    assert _SECRET not in message, f"secret leaked: {message}"
    assert "REDACTED" in message, f"no redaction marker: {message}"


def test_generic_prompt_encoding_value_is_scrubbed() -> None:
    with pytest.raises(AdapterConfigError) as exc:
        GenericHttpAdapter(target=_TARGET, method="POST", prompt_encoding=_SECRET)
    _assert_scrubbed(exc.value)


def test_generic_method_value_is_scrubbed() -> None:
    with pytest.raises(AdapterConfigError) as exc:
        GenericHttpAdapter(target=_TARGET, method=_SECRET)
    _assert_scrubbed(exc.value)


def test_extraction_spec_mode_value_is_scrubbed() -> None:
    with pytest.raises(AdapterConfigError) as exc:
        ExtractionSpec(mode=_SECRET)
    _assert_scrubbed(exc.value)


def test_captured_prompt_encoding_value_is_scrubbed() -> None:
    raw = "POST /chat HTTP/1.1\nHost: 127.0.0.1:8080\n\n{\"in\":\"*\"}"
    with pytest.raises(AdapterConfigError) as exc:
        CapturedHttpAdapter(target=_TARGET, raw_request=raw, prompt_encoding=_SECRET)
    _assert_scrubbed(exc.value)


def test_captured_method_value_is_scrubbed() -> None:
    raw = f"{_SECRET} /chat HTTP/1.1\nHost: 127.0.0.1:8080\n\n*"
    with pytest.raises(AdapterConfigError) as exc:
        CapturedHttpAdapter(target=_TARGET, raw_request=raw)
    _assert_scrubbed(exc.value)


def test_captured_duplicate_header_name_is_scrubbed() -> None:
    # A duplicate header whose NAME is secret-like must not leak in the message.
    raw = (
        "POST /chat HTTP/1.1\nHost: 127.0.0.1:8080\n"
        f"{_SECRET}: 1\n{_SECRET}: 2\n\n*"
    )
    with pytest.raises(AdapterConfigError) as exc:
        CapturedHttpAdapter(target=_TARGET, raw_request=raw)
    _assert_scrubbed(exc.value)


def test_registry_unknown_adapter_name_is_scrubbed() -> None:
    registry = default_registry()
    with pytest.raises(AdapterConfigError) as exc:
        registry.create(_SECRET)
    _assert_scrubbed(exc.value)
