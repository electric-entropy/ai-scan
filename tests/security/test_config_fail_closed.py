"""Milestone 2: strict config loading fails closed on malformed/unsafe input."""

from __future__ import annotations

import json

import pytest

from ai_scan.core.config import load_document, load_json_strict
from ai_scan.core.errors import ConfigError
from ai_scan.orchestration import compile_plan, plan_to_dict
from ai_scan.packs.signatures import compute_digest
from ai_scan.targets import normalize_target

_TS = "2026-09-12T00:00:00Z"


def _reseal_plan(doc: dict) -> dict:
    doc = dict(doc)
    doc.pop("digest", None)
    doc["digest"] = compute_digest(doc)
    return doc


def _target(**overrides) -> dict:
    doc = {
        "schema_version": 1,
        "kind": "target",
        "name": "app",
        "adapter": "generic_http",
        "endpoints": ["https://api.example.com/chat"],
        "request": {"method": "POST", "prompt_marker": "*"},
        "response": {"extract": "raw_body"},
    }
    doc.update(overrides)
    return doc


# --- strict JSON parsing ------------------------------------------------------


def test_duplicate_keys_rejected() -> None:
    with pytest.raises(ConfigError):
        load_json_strict('{"a": 1, "a": 2}')


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_nan_infinity_rejected(literal: str) -> None:
    with pytest.raises(ConfigError):
        load_json_strict('{"x": ' + literal + "}")


@pytest.mark.parametrize(
    "raw",
    [
        '{"x": 1e999}',          # exponent overflow → inf
        '{"x": -1e999}',         # → -inf
        '{"x": [1e999]}',        # nested in a list
        '{"x": {"y": 1e999}}',   # nested in an object
        "1e999",                 # bare overflow
    ],
)
def test_numeric_overflow_to_infinity_rejected(raw: str) -> None:
    with pytest.raises(ConfigError):
        load_json_strict(raw)


def test_finite_floats_still_parse() -> None:
    assert load_json_strict('{"x": 1.5, "y": 1e300}') == {"x": 1.5, "y": 1e300}


def test_malformed_json_rejected() -> None:
    with pytest.raises(ConfigError):
        load_json_strict("{not json")


def test_duplicate_keys_rejected_in_document() -> None:
    raw = '{"schema_version": 1, "kind": "target", "name": "a", "name": "b",' \
          ' "adapter": "g", "endpoints": ["https://x.example"]}'
    with pytest.raises(ConfigError):
        load_document(raw, "target")


# --- schema version handling --------------------------------------------------


def test_unsupported_schema_version_rejected() -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(schema_version=99)), "target")


def test_missing_schema_version_rejected() -> None:
    doc = _target()
    del doc["schema_version"]
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_non_integer_schema_version_rejected() -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(schema_version="1")), "target")


# --- unknown fields -----------------------------------------------------------


def test_unknown_top_level_field_rejected() -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(surprise="x")), "target")


def test_unknown_nested_field_rejected() -> None:
    doc = _target(auth_refs=[{"header": "Authorization", "env": "T", "extra": 1}])
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


# --- invalid / unbounded limits ----------------------------------------------


def _engagement(**limit_overrides) -> dict:
    limits = {
        "max_physical_requests": 256,
        "max_duration_seconds": 1800,
        "requests_per_second": 2.0,
        "max_concurrency": 1,
    }
    limits.update(limit_overrides)
    return {
        "schema_version": 1, "kind": "engagement", "engagement_id": "E", "client": "C",
        "approver": "A", "issued_at": _TS, "expires_at": _TS,
        "target_scopes": ["https://api.example.com"], "capabilities": ["read"],
        "limits": limits, "signer_key_id": "k",
    }


@pytest.mark.parametrize(
    "limits",
    [
        {"max_physical_requests": 0},
        {"max_physical_requests": -1},
        {"max_physical_requests": 10_000_000},  # exceeds schema maximum (unbounded)
        {"requests_per_second": 0},
        {"max_concurrency": 0},
        {"max_duration_seconds": 10**9},
        {"max_physical_requests": 2.5},  # fractional where integer required
    ],
)
def test_invalid_or_unbounded_limits_rejected(limits: dict) -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_engagement(**limits)), "engagement")


def test_bool_where_integer_expected_rejected() -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_engagement(max_physical_requests=True)), "engagement")


# --- path traversal -----------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["../etc/passwd", "a/../../b", "..\\win", "..", "%2e%2e/secrets", "%252e%252e/x"],
)
def test_path_traversal_rejected(value: str) -> None:
    # Includes recursively percent-decoded traversal (%2e%2e, double-encoded).
    doc = _target(response={"extract": "json_path", "json_path": value})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


# --- prohibited secret literals ----------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "AKIA1234567890ABCDEF",
        "sk-abcdefghijklmnop0123",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "-----BEGIN RSA PRIVATE KEY-----",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
        "Bearer abcdef0123456789ABCDEF",
        "ASIA1234567890ABCDEF",
    ],
)
def test_secret_literals_rejected(secret: str) -> None:
    # Field-aware: a literal secret in a secret-bearing reference field (env)
    # is rejected.
    doc = _target(auth_refs=[{"header": "Authorization", "env": secret}])
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_tokenlike_payload_text_is_allowed() -> None:
    # Field-aware: payload/body text that merely *resembles* a token is benign.
    tokenlike = '{"q": "try Bearer sk-abcdef0123456789 / AKIA1234567890ABCDEF : *"}'
    doc = _target(request={"method": "POST", "prompt_marker": "*", "body_template": tokenlike})
    assert load_document(json.dumps(doc), "target")["name"] == "app"


def test_benign_name_resembling_token_is_allowed() -> None:
    doc = _target(name="sk-test-fixture-app")
    assert load_document(json.dumps(doc), "target")["name"] == "sk-test-fixture-app"


def test_sha256_digest_is_not_a_false_positive_secret() -> None:
    # A 64-hex digest is legitimate config and must not trip secret detection.
    doc = {
        "schema_version": 1, "kind": "pack", "id": "safe", "version": "v1",
        "trust": "builtin", "digest": "a" * 64, "families": ["x"],
    }
    assert load_document(json.dumps(doc), "pack")["digest"] == "a" * 64


def test_env_reference_for_secret_is_accepted() -> None:
    # Secrets supplied by reference (env var name) are fine.
    doc = _target(auth_refs=[{"header": "Authorization", "env": "API_TOKEN"}])
    assert load_document(json.dumps(doc), "target")["auth_refs"][0]["env"] == "API_TOKEN"


# --- type-aware const/enum (integer 1 is not boolean true) -------------------

_DIGEST = "a" * 64
_TS_Z = "2026-09-12T00:00:00Z"


def _plan() -> dict:
    # The canonical *runtime* plan artifact — the exact document the runner runs.
    return plan_to_dict(compile_plan(normalize_target("https://api.example.com/chat"), "reliable"))


def test_canonical_runtime_plan_validates() -> None:
    assert load_document(json.dumps(_plan()), "plan")["mode"] == "reliable"


def test_plan_with_duplicate_key_rejected() -> None:
    text = json.dumps(_plan())
    dup = text[:-1] + ', "seed": 3}'
    with pytest.raises(ConfigError):
        load_document(dup, "plan")


def test_plan_missing_required_field_rejected() -> None:
    doc = _plan()
    del doc["digest"]
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "plan")


# --- semantic URL / scope validation -----------------------------------------


@pytest.mark.parametrize(
    "scope",
    [
        "https://user:pass@api.example.com/chat",  # credentials
        "https://api.example.com/#frag",           # fragment
        "https://API.example.com/chat",            # not normalized (uppercase host)
        "ftp://api.example.com/chat",              # wrong scheme
        "not-a-url",
    ],
)
def test_invalid_plan_target_rejected(scope: str) -> None:
    # A re-digested plan whose target is not a canonical HTTP(S) URL is rejected.
    doc = _reseal_plan({**_plan(), "target": scope})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "plan")


def test_endpoint_with_credentials_rejected() -> None:
    doc = _target(endpoints=["https://user:pass@api.example.com/chat"])
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://api.example.com:443/chat",   # default HTTPS port → non-canonical
        "http://api.example.com:80/chat",      # default HTTP port → non-canonical
        "https://API.example.com/chat",        # uppercase host → non-canonical
    ],
)
def test_non_canonical_endpoint_origin_rejected(endpoint: str) -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(endpoints=[endpoint])), "target")


def test_canonical_endpoint_with_nondefault_port_accepted() -> None:
    doc = _target(endpoints=["https://api.example.com:8443/chat"])
    assert load_document(json.dumps(doc), "target")["endpoints"][0].endswith(":8443/chat")


# --- timezone-aware RFC 3339 timestamps and ordering -------------------------


def _engagement_ts(issued: str, expires: str) -> dict:
    return {
        "schema_version": 1, "kind": "engagement", "engagement_id": "E", "client": "C",
        "approver": "A", "issued_at": issued, "expires_at": expires,
        "target_scopes": ["https://api.example.com"], "capabilities": ["read"],
        "limits": {
            "max_physical_requests": 256, "max_duration_seconds": 1800,
            "requests_per_second": 2.0, "max_concurrency": 1,
        },
        "signer_key_id": "k",
    }


def test_naive_timestamp_rejected() -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_engagement_ts("2026-09-12T00:00:00", _TS_Z)), "engagement")


@pytest.mark.parametrize(
    "bad",
    [
        "2026-09-12 00:00:00+00:00",  # space separator instead of 'T'
        "2026-09-12T00:00:00",         # no timezone
        "2026-09-12",                  # date only
        "not-a-timestamp",
    ],
)
def test_non_rfc3339_timestamp_rejected(bad: str) -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_engagement_ts(bad, _TS_Z)), "engagement")


def test_timestamp_ordering_enforced() -> None:
    # issued_at after expires_at must be rejected.
    later = "2026-09-13T00:00:00Z"
    with pytest.raises(ConfigError):
        load_document(json.dumps(_engagement_ts(later, _TS_Z)), "engagement")


def test_valid_timestamps_and_ordering_accepted() -> None:
    doc = _engagement_ts("2026-09-12T00:00:00+00:00", "2026-09-13T00:00:00+00:00")
    assert load_document(json.dumps(doc), "engagement")["engagement_id"] == "E"


# --- exact-match executable plan semantics (tightening path removed) ---------


def test_plan_widened_limit_rejected() -> None:
    # A re-digested plan that widens a mode ceiling is not policy-derived → reject.
    doc = _reseal_plan({**_plan(), "limits": _widened_limits()})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "plan")


def _widened_limits() -> list:
    limits = list(_plan()["limits"])
    limits[0] = limits[0] + 10_000  # widen max_physical_requests beyond policy
    return limits


def test_plan_lowered_trial_policy_rejected() -> None:
    doc = _plan()
    trial = list(doc["trial_policy"])
    trial[0] = 1  # below the mode's minimum_attack_trials
    doc = _reseal_plan({**doc, "trial_policy": trial})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "plan")


def test_plan_altered_case_rejected() -> None:
    doc = _plan()
    cases = [list(row) for row in doc["cases"]]
    cases[0][5] = cases[0][5] + " tamper"
    doc = _reseal_plan({**doc, "cases": cases})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "plan")


# --- blocker 2: discriminated target request/response/session ----------------


def test_json_path_extract_requires_json_path() -> None:
    doc = _target(response={"extract": "json_path"})  # missing json_path
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_regex_extract_requires_regex() -> None:
    doc = _target(response={"extract": "regex"})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_stateful_session_requires_session_header() -> None:
    doc = _target(session={"mode": "stateful"})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_body_template_must_contain_declared_marker() -> None:
    request = {"method": "POST", "prompt_marker": "@@", "body_template": '{"q": "no marker"}'}
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(request=request)), "target")


def test_secret_reference_must_be_exactly_one_of_env_or_fd() -> None:
    both = _target(auth_refs=[{"header": "Authorization", "env": "T", "fd": 3}])
    with pytest.raises(ConfigError):
        load_document(json.dumps(both), "target")
    neither = _target(auth_refs=[{"header": "Authorization"}])
    with pytest.raises(ConfigError):
        load_document(json.dumps(neither), "target")


def test_fd_secret_reference_is_accepted() -> None:
    doc = _target(auth_refs=[{"header": "Authorization", "fd": 3}])
    assert load_document(json.dumps(doc), "target")["auth_refs"][0]["fd"] == 3


# --- blocker 2b: mutually exclusive target branches --------------------------


def test_get_rejects_body_template() -> None:
    doc = _target(request={"method": "GET", "prompt_marker": "*", "body_template": "{\"q\":\"*\"}"})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


@pytest.mark.parametrize("extra", [{"json_path": "x"}, {"regex": "x"}])
def test_raw_body_rejects_extractors(extra: dict) -> None:
    doc = _target(response={"extract": "raw_body", **extra})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_json_path_rejects_regex() -> None:
    doc = _target(response={"extract": "json_path", "json_path": "reply", "regex": "x"})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_regex_rejects_json_path() -> None:
    doc = _target(response={"extract": "regex", "regex": "x", "json_path": "reply"})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_stateless_rejects_session_header() -> None:
    doc = _target(session={"mode": "stateless", "session_header": "X-Session"})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_compatible_branches_accepted() -> None:
    doc = _target(
        request={"method": "GET", "prompt_marker": "*"},
        response={"extract": "json_path", "json_path": "reply"},
        session={"mode": "stateful", "session_header": "X-Session"},
    )
    assert load_document(json.dumps(doc), "target")["session"]["mode"] == "stateful"


# --- blocker 3: Unicode control/format/surrogate/private/unassigned in URLs ---


@pytest.mark.parametrize(
    "codepoint",
    [
        0x0080,  # C1 control (Cc) - beyond ASCII C0/DEL
        0x200B,  # zero-width space (Cf)
        0xFEFF,  # BOM / zero-width no-break space (Cf)
        0xE000,  # private use (Co)
        0x000B,  # vertical tab (Cc)
    ],
)
def test_unicode_control_format_in_url_rejected(codepoint: int) -> None:
    endpoint = f"https://api.example.com/ch{chr(codepoint)}at"
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(endpoints=[endpoint])), "target")


# --- blocker 3: percent-decode to a fixed point before traversal -------------


@pytest.mark.parametrize(
    "encoded",
    [
        "%2e%2e/secrets",          # single layer
        "%252e%252e/x",            # double
        "%25252e%25252e/x",        # triple
        "%2525252e%2525252e/x",    # quadruple (beyond the old 6-pass window idea)
    ],
)
def test_deeply_encoded_traversal_rejected(encoded: str) -> None:
    doc = _target(response={"extract": "json_path", "json_path": encoded})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def _layered_quote(value: str, layers: int) -> str:
    from urllib.parse import quote

    for _ in range(layers):
        value = quote(value, safe="")
    return value


@pytest.mark.parametrize("layers", [65, 80])
def test_encoding_beyond_cap_rejected_as_suspicious(layers: int) -> None:
    # Decoding that still changes at the cap is rejected, not accepted — for
    # traversal payloads...
    doc = _target(response={"extract": "json_path", "json_path": _layered_quote("../x", layers)})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_non_traversal_encoding_beyond_cap_rejected_as_suspicious() -> None:
    # ...and for a benign-looking value that is simply encoded beyond the cap.
    doc = _target(response={"extract": "json_path", "json_path": _layered_quote("safe/path", 80)})
    with pytest.raises(ConfigError):
        load_document(json.dumps(doc), "target")


def test_shallow_encoding_within_cap_still_accepted() -> None:
    # A normally-encoded, non-traversal value must still be accepted.
    doc = _target(response={"extract": "json_path", "json_path": _layered_quote("reply", 3)})
    assert load_document(json.dumps(doc), "target")["response"]["extract"] == "json_path"


# --- blocker 4: URL hardening (whitespace / control / encoded host) ----------


@pytest.mark.parametrize(
    "endpoint",
    [
        " https://api.example.com/chat",       # leading whitespace
        "https://api.example.com/chat ",        # trailing whitespace
        "https://api.example.com/ch\tat",        # internal tab
        "https://api.example.com/ch\nat",        # control char
        "https://%61pi.example.com/chat",        # percent-encoded host
    ],
)
def test_malformed_url_rejected(endpoint: str) -> None:
    with pytest.raises(ConfigError):
        load_document(json.dumps(_target(endpoints=[endpoint])), "target")
