"""Tests for the fail-closed authorization gate and target-bound receipts."""

from __future__ import annotations

import json
import os
import stat

import pytest

from ai_scan.authorization import (
    AuthorizationError,
    Receipt,
    confirmation_phrase,
    interactive_authorize,
    load_receipt,
    validate_receipt,
    write_receipt,
)
from ai_scan.targets import normalize_target

TARGET = "https://api.example.com:8443/chat"
FUTURE = "2999-01-01"
PAST = "2000-01-01"


def _make_receipt(**overrides) -> Receipt:
    kwargs = dict(
        target=normalize_target(TARGET),
        client="Acme",
        engagement="ENG-1",
        expires=FUTURE,
    )
    kwargs.update(overrides)
    return Receipt.create(**kwargs)


# --- interactive gate -------------------------------------------------------


def test_confirmation_phrase_includes_origin() -> None:
    target = normalize_target(TARGET)
    phrase = confirmation_phrase(target)
    assert target.origin in phrase


def test_exact_phrase_authorizes() -> None:
    target = normalize_target(TARGET)
    phrase = confirmation_phrase(target)
    assert interactive_authorize(target, prompt=lambda _msg: phrase) is True


@pytest.mark.parametrize("answer", ["", "yes", "  ", "I AUTHORIZE", "nope"])
def test_wrong_phrase_denies(answer: str) -> None:
    target = normalize_target(TARGET)
    assert interactive_authorize(target, prompt=lambda _msg: answer) is False


def test_phrase_with_surrounding_whitespace_still_authorizes() -> None:
    target = normalize_target(TARGET)
    phrase = confirmation_phrase(target)
    assert interactive_authorize(target, prompt=lambda _msg: f"  {phrase}  ") is True


# --- receipt binding & integrity --------------------------------------------


def test_receipt_binds_origin_client_engagement_expiry() -> None:
    r = _make_receipt()
    assert r.origin == normalize_target(TARGET).origin
    assert r.client == "Acme"
    assert r.engagement == "ENG-1"
    assert r.expires == FUTURE
    assert r.created_at  # ISO timestamp present
    assert r.digest  # integrity digest present


def test_valid_receipt_validates_against_matching_target() -> None:
    r = _make_receipt()
    validate_receipt(r, normalize_target(TARGET))  # must not raise


def test_expired_receipt_fails() -> None:
    r = _make_receipt(expires=PAST)
    with pytest.raises(AuthorizationError):
        validate_receipt(r, normalize_target(TARGET))


def test_wrong_target_receipt_fails() -> None:
    r = _make_receipt()
    with pytest.raises(AuthorizationError):
        validate_receipt(r, normalize_target("https://api.example.com/chat"))


def test_subdomain_target_receipt_fails() -> None:
    r = _make_receipt()
    with pytest.raises(AuthorizationError):
        validate_receipt(r, normalize_target("https://evil.example.com:8443/chat"))


def test_altered_receipt_fails_integrity() -> None:
    r = _make_receipt()
    tampered = r.to_dict()
    tampered["engagement"] = "ENG-HACKED"
    with pytest.raises(AuthorizationError):
        rec = Receipt.from_dict(tampered)
        validate_receipt(rec, normalize_target(TARGET))


def test_digest_is_canonical_and_stable() -> None:
    r = _make_receipt()
    # Recomputing over the same canonical content yields the same digest.
    assert Receipt.from_dict(r.to_dict()).digest == r.digest


# --- persistence ------------------------------------------------------------


def test_write_and_load_roundtrip(tmp_path) -> None:
    r = _make_receipt()
    path = tmp_path / "auth.json"
    write_receipt(r, str(path))
    loaded = load_receipt(str(path))
    validate_receipt(loaded, normalize_target(TARGET))
    assert loaded.digest == r.digest


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits only")
def test_receipt_file_is_mode_0600(tmp_path) -> None:
    r = _make_receipt()
    path = tmp_path / "auth.json"
    write_receipt(r, str(path))
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_load_missing_file_fails(tmp_path) -> None:
    with pytest.raises(AuthorizationError):
        load_receipt(str(tmp_path / "does-not-exist.json"))


def test_load_malformed_file_fails(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text("{ not valid json", encoding="utf-8")
    with pytest.raises(AuthorizationError):
        load_receipt(str(path))


def test_load_non_object_fails(tmp_path) -> None:
    path = tmp_path / "arr.json"
    path.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
    with pytest.raises(AuthorizationError):
        load_receipt(str(path))


def test_expires_must_be_valid_date() -> None:
    with pytest.raises(AuthorizationError):
        _make_receipt(expires="not-a-date")


# --- Finding 8: receipt version + created_at validation ----------------------


def test_receipt_has_supported_version() -> None:
    from ai_scan.authorization import SUPPORTED_RECEIPT_VERSION

    assert _make_receipt().version == SUPPORTED_RECEIPT_VERSION


def test_receipt_missing_version_rejected() -> None:
    d = _make_receipt().to_dict()
    del d["version"]
    with pytest.raises(AuthorizationError):
        Receipt.from_dict(d)


def test_unsupported_version_rejected_even_with_valid_digest() -> None:
    # Forge a receipt at version 2 with a *matching* digest; it must still be
    # rejected because the version is unsupported.
    from ai_scan.authorization import _compute_digest

    origin = normalize_target(TARGET).origin
    forged = {
        "version": 2,
        "origin": origin,
        "client": "Acme",
        "engagement": "ENG-1",
        "created_at": "2026-01-01T00:00:00+00:00",
        "expires": FUTURE,
        "digest": _compute_digest(2, origin, "Acme", "ENG-1", FUTURE, "2026-01-01T00:00:00+00:00"),
    }
    with pytest.raises(AuthorizationError):
        Receipt.from_dict(forged)


def test_bad_created_at_rejected_even_with_valid_digest() -> None:
    from ai_scan.authorization import SUPPORTED_RECEIPT_VERSION, _compute_digest

    origin = normalize_target(TARGET).origin
    bad_ts = "not-a-timestamp"
    forged = {
        "version": SUPPORTED_RECEIPT_VERSION,
        "origin": origin,
        "client": "Acme",
        "engagement": "ENG-1",
        "created_at": bad_ts,
        "expires": FUTURE,
        "digest": _compute_digest(
            SUPPORTED_RECEIPT_VERSION, origin, "Acme", "ENG-1", FUTURE, bad_ts
        ),
    }
    with pytest.raises(AuthorizationError):
        Receipt.from_dict(forged)
