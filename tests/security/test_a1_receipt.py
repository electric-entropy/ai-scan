"""Phase A1.5 — strict authorization-receipt validation.

Receipts must carry a strict, timezone-aware RFC 3339 ``created_at`` (no naive /
space-separated forms), reject a future issuance, reject unknown fields (closed
schema), and reject duplicate JSON keys on load.
"""

from __future__ import annotations

from datetime import date

import pytest

from ai_scan.authorization import (
    AuthorizationError,
    Receipt,
    load_receipt,
    validate_receipt,
    write_receipt,
)
from ai_scan.targets import normalize_target

_URL = "http://127.0.0.1:9/chat"


def _valid_dict() -> dict:
    receipt = Receipt.create(
        target=normalize_target(_URL), client="C", engagement="E",
        expires="2999-01-01", created_at="2026-01-01T00:00:00+00:00",
    )
    return receipt.to_dict()


def _reseal(data: dict) -> dict:
    # Recompute the digest so structural tamper is isolated from digest tamper.
    from ai_scan.authorization import _compute_digest

    data = dict(data)
    data["digest"] = _compute_digest(
        data["version"], data["origin"], data["client"], data["engagement"],
        data["expires"], data["created_at"],
    )
    return data


def test_naive_created_at_is_rejected() -> None:
    data = _reseal({**_valid_dict(), "created_at": "2026-01-01T00:00:00"})  # no tz
    with pytest.raises(AuthorizationError):
        Receipt.from_dict(data)


def test_space_separated_created_at_is_rejected() -> None:
    data = _reseal({**_valid_dict(), "created_at": "2026-01-01 00:00:00+00:00"})
    with pytest.raises(AuthorizationError):
        Receipt.from_dict(data)


def test_unknown_field_is_rejected() -> None:
    data = _reseal(_valid_dict())
    data["surprise"] = "x"
    with pytest.raises(AuthorizationError):
        Receipt.from_dict(data)


def test_future_issuance_is_rejected() -> None:
    receipt = Receipt.create(
        target=normalize_target(_URL), client="C", engagement="E",
        expires="2999-01-01", created_at="2999-06-01T00:00:00+00:00",
    )
    with pytest.raises(AuthorizationError):
        validate_receipt(receipt, normalize_target(_URL), now=date(2026, 9, 13))


def test_duplicate_json_key_in_receipt_file_is_rejected(tmp_path) -> None:
    receipt = Receipt.create(
        target=normalize_target(_URL), client="C", engagement="E", expires="2999-01-01"
    )
    path = tmp_path / "r.json"
    write_receipt(receipt, str(path))
    text = path.read_text(encoding="utf-8")
    # Duplicate with the SAME value so the digest still matches: only strict
    # duplicate-key rejection (not the digest check) can catch this.
    dup = text[:-1] + ', "client": "C"}'
    path.write_text(dup, encoding="utf-8")
    with pytest.raises(AuthorizationError):
        load_receipt(str(path))


def test_plan_bound_receipt_round_trips(tmp_path) -> None:
    tgt = normalize_target(_URL)
    receipt = Receipt.create(
        target=tgt, client="C", engagement="E", expires="2999-01-01", plan_digest="a" * 64
    )
    assert receipt.plan_digest == "a" * 64
    assert receipt.target == tgt.url  # exact target bound automatically
    path = tmp_path / "pb.json"
    write_receipt(receipt, str(path))
    loaded = load_receipt(str(path))
    assert loaded.plan_digest == "a" * 64
    assert loaded.target == tgt.url


def test_plan_bound_receipt_digest_tamper_rejected(tmp_path) -> None:
    import json as _json

    tgt = normalize_target(_URL)
    receipt = Receipt.create(
        target=tgt, client="C", engagement="E", expires="2999-01-01", plan_digest="a" * 64
    )
    path = tmp_path / "pb.json"
    write_receipt(receipt, str(path))
    data = _json.loads(path.read_text(encoding="utf-8"))
    data["plan_digest"] = "b" * 64  # tamper the bound digest WITHOUT resealing
    path.write_text(_json.dumps(data), encoding="utf-8")
    with pytest.raises(AuthorizationError):
        load_receipt(str(path))


def test_origin_only_receipt_has_no_plan_binding(tmp_path) -> None:
    receipt = Receipt.create(
        target=normalize_target(_URL), client="C", engagement="E", expires="2999-01-01"
    )
    assert receipt.plan_digest is None
    assert receipt.target is None
    # Serialization stays byte-stable for origin-only receipts (no null padding).
    assert "plan_digest" not in receipt.to_dict()


def test_valid_receipt_still_loads(tmp_path) -> None:
    receipt = Receipt.create(
        target=normalize_target(_URL), client="C", engagement="E",
        expires="2999-01-01", created_at="2026-01-01T00:00:00+00:00",
    )
    path = tmp_path / "ok.json"
    write_receipt(receipt, str(path))
    loaded = load_receipt(str(path))
    validate_receipt(loaded, normalize_target(_URL), now=date(2026, 9, 13))
    assert loaded.origin == normalize_target(_URL).origin
