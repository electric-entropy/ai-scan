"""Milestone 1: stable content IDs over a strict JSON domain, safe prefixes."""

from __future__ import annotations

import decimal
import math

import pytest

from ai_scan.core.errors import ValidationError
from ai_scan.core.ids import attempt_id, content_id

# --- stability & determinism --------------------------------------------------


def test_content_id_is_stable_for_equal_content() -> None:
    assert content_id({"b": 2, "a": 1}) == content_id({"a": 1, "b": 2})


def test_content_id_differs_for_different_content() -> None:
    assert content_id({"a": 1}) != content_id({"a": 2})


def test_content_id_is_deterministic_across_calls() -> None:
    payload = {"nested": [1, 2, {"x": "y"}], "k": "v", "b": True, "n": None}
    assert content_id(payload) == content_id(payload)


def test_content_id_shape() -> None:
    cid = content_id({"a": 1})
    assert cid.startswith("cid-")
    assert len(cid) == len("cid-") + 32
    assert content_id({"a": 1}, prefix="resp").startswith("resp-")


# --- collision safety ---------------------------------------------------------


def test_int_and_string_do_not_collide() -> None:
    assert content_id(1) != content_id("1")


def test_bool_and_int_do_not_collide() -> None:
    assert content_id(True) != content_id(1)


def test_int_and_float_do_not_collide() -> None:
    assert content_id(1) != content_id(1.0)


# --- strict JSON domain: unsupported content is rejected ---------------------


def test_non_string_map_keys_are_rejected() -> None:
    with pytest.raises(ValidationError):
        content_id({1: "a"})


def test_tuples_are_rejected() -> None:
    # A tuple would otherwise alias a list; reject rather than collide.
    with pytest.raises(ValidationError):
        content_id({"x": (1, 2)})


def test_sets_are_rejected() -> None:
    with pytest.raises(ValidationError):
        content_id({"x": {1, 2}})


def test_decimal_is_rejected() -> None:
    # Decimal would otherwise be coerced to a string and alias one.
    with pytest.raises(ValidationError):
        content_id({"x": decimal.Decimal("1")})


def test_bytes_and_objects_are_rejected() -> None:
    with pytest.raises(ValidationError):
        content_id({"x": b"bytes"})
    with pytest.raises(ValidationError):
        content_id(object())


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_non_finite_floats_are_rejected(bad: float) -> None:
    with pytest.raises(ValidationError):
        content_id({"x": bad})


# --- prefix grammar -----------------------------------------------------------


@pytest.mark.parametrize(
    "bad_prefix",
    ["", "Cid", "cid-", "c id", "c/d", "../x", "c\n", "c.d", "1cid", "x" * 17, "réf"],
)
def test_invalid_prefixes_are_rejected(bad_prefix: str) -> None:
    with pytest.raises(ValidationError):
        content_id({"a": 1}, prefix=bad_prefix)
    with pytest.raises(ValidationError):
        attempt_id(prefix=bad_prefix)


@pytest.mark.parametrize("ok_prefix", ["cid", "att", "resp_1", "a", "node_v2"])
def test_valid_prefixes_are_accepted(ok_prefix: str) -> None:
    assert content_id({"a": 1}, prefix=ok_prefix).startswith(f"{ok_prefix}-")


# --- attempt IDs: deterministic format + small uniqueness smoke --------------


def test_attempt_id_format() -> None:
    aid = attempt_id()
    assert aid.startswith("att-")
    hexpart = aid[len("att-"):]
    assert len(hexpart) == 16
    int(hexpart, 16)  # is hex


def test_attempt_id_uniqueness_smoke() -> None:
    ids = {attempt_id() for _ in range(8)}
    assert len(ids) == 8


def test_attempt_id_namespace_distinct_from_content_id() -> None:
    assert not attempt_id().startswith("cid-")
