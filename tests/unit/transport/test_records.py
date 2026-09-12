"""Milestone 3: canonical, immutable exchange records + store boundary."""

from __future__ import annotations

import dataclasses
import json
from types import MappingProxyType

import pytest

from ai_scan.transport.records import (
    ExchangeRecord,
    RecordStore,
    RecordValidationError,
    RequestRecord,
    ResponseRecord,
    UnredactedRecordError,
    build_exchange_record,
)


def _valid_request() -> RequestRecord:
    return RequestRecord(method="POST", url="https://api.example.com/x", headers={})


def _valid_response() -> ResponseRecord:
    return ResponseRecord(
        status=200, headers={}, body="{}", redirected=False, redirect_location=None, truncated=False
    )


def _record(**overrides) -> ExchangeRecord:
    kwargs = dict(
        method="POST",
        url="https://api.example.com/chat",
        request_headers={
            "Authorization": "Bearer sk-abcdef0123456789", "Accept": "application/json"
        },
        status=200,
        response_headers={"Content-Type": "application/json", "Set-Cookie": "session=abc"},
        body='{"reply": "AISCAN-DEADBEEFCAFEBABE"}',
        redirected=False,
        redirect_location=None,
        truncated=False,
        attempts=1,
        known_secrets=frozenset(),
    )
    kwargs.update(overrides)
    return build_exchange_record(**kwargs)


# --- redaction at the record boundary ----------------------------------------


def test_build_record_redacts_headers_body_url() -> None:
    rec = _record(
        url="https://user:pass@api.example.com/chat?token=LEAK",
        body="reflected AKIA1234567890ABCDEF here",
    )
    dumped = json.dumps(rec.to_dict())
    assert "Bearer sk-" not in dumped
    assert "sk-abcdef0123456789" not in dumped
    assert "user:pass" not in dumped
    assert "LEAK" not in dumped
    assert "AKIA1234567890ABCDEF" not in dumped
    # sensitive headers redacted
    assert rec.request.headers["Authorization"] == "REDACTED"
    assert rec.response.headers["Set-Cookie"] == "REDACTED"


def test_build_record_preserves_canary() -> None:
    rec = _record()
    assert "AISCAN-DEADBEEFCAFEBABE" in rec.response.body


def test_build_record_is_marked_complete() -> None:
    assert _record().redaction_complete is True


# --- immutability -------------------------------------------------------------


def test_exchange_record_is_frozen() -> None:
    rec = _record()
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.attempts = 5  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        rec.request.method = "GET"  # type: ignore[misc]


def test_request_headers_are_deeply_immutable() -> None:
    rec = _record()
    with pytest.raises(TypeError):
        rec.request.headers["Authorization"] = "Bearer [INJECTED]"  # type: ignore[index]


def test_response_headers_are_deeply_immutable() -> None:
    rec = _record()
    with pytest.raises(TypeError):
        rec.response.headers["Set-Cookie"] = "session=INJECTED"  # type: ignore[index]


def test_digest_stable_after_external_mutation_attempts() -> None:
    rec = _record()
    before = rec.digest()
    # Header maps cannot be mutated...
    with pytest.raises(TypeError):
        rec.response.headers["Set-Cookie"] = "session=LEAK"  # type: ignore[index]
    # ...and to_dict() hands out fresh copies that cannot affect the record.
    snapshot = rec.to_dict()
    snapshot["response"]["headers"]["Set-Cookie"] = "session=LEAK"
    snapshot["request"]["headers"]["Authorization"] = "Bearer LEAK"
    assert rec.digest() == before
    assert "LEAK" not in json.dumps(rec.to_dict())


def test_source_headers_copied_at_construction() -> None:
    # Mutating the caller's original dict after build must not affect the record.
    src = {"Authorization": "Bearer sk-abcdef0123456789", "Accept": "application/json"}
    rec = _record(request_headers=src)
    src["Accept"] = "text/evil"
    src["X-New"] = "added"
    assert rec.request.headers["Accept"] == "application/json"
    assert "X-New" not in rec.request.headers


# --- stable / canonical serialization ----------------------------------------


def test_serialization_is_stable_and_canonical() -> None:
    a = _record()
    b = _record()
    assert a.to_dict() == b.to_dict()
    assert json.dumps(a.to_dict(), sort_keys=True) == json.dumps(b.to_dict(), sort_keys=True)
    assert a.digest() == b.digest()


def test_digest_changes_with_content() -> None:
    assert _record().digest() != _record(status=500).digest()
    assert _record().digest() != _record(body='{"reply": "AISCAN-OTHER0000000000"}').digest()


def test_record_dict_has_expected_shape() -> None:
    data = _record().to_dict()
    assert set(data) == {"schema_version", "redaction_complete", "attempts", "request", "response"}
    assert set(data["request"]) == {"method", "url", "headers"}
    assert set(data["response"]) == {
        "status", "headers", "body", "redirected", "redirect_location", "truncated"
    }


# --- store boundary rejects unmarked records ---------------------------------


def test_store_accepts_redaction_complete_record() -> None:
    store = RecordStore()
    store.add(_record())
    assert len(store) == 1


def test_store_rejects_unmarked_record() -> None:
    rec = dataclasses.replace(_record(), redaction_complete=False)
    store = RecordStore()
    with pytest.raises(UnredactedRecordError):
        store.add(rec)
    assert len(store) == 0


def test_store_rejects_object_without_marking() -> None:
    class _Fake:
        pass

    store = RecordStore()
    with pytest.raises(UnredactedRecordError):
        store.add(_Fake())  # type: ignore[arg-type]


# --- provenance: forged/direct records are not persistable -------------------


def test_directly_constructed_record_is_rejected_even_if_marked_complete() -> None:
    forged = ExchangeRecord(
        request=_valid_request(),
        response=_valid_response(),
        attempts=1,
        redaction_complete=True,  # claims safe, but has no trusted provenance
    )
    store = RecordStore()
    with pytest.raises(UnredactedRecordError):
        store.add(forged)
    assert len(store) == 0


def test_built_record_carries_trusted_provenance() -> None:
    store = RecordStore()
    store.add(_record())  # built via build_exchange_record → accepted
    assert len(store) == 1


def test_replace_changing_child_invalidates_seal() -> None:
    # A mutation with no secret still breaks the content-bound seal.
    rec = _record()
    benign = ResponseRecord(
        status=204, headers={}, body="{}", redirected=False, redirect_location=None, truncated=False
    )
    forged = dataclasses.replace(rec, response=benign)
    store = RecordStore()
    with pytest.raises(UnredactedRecordError):
        store.add(forged)


def test_replace_changing_attempts_invalidates_seal() -> None:
    forged = dataclasses.replace(_record(), attempts=9)
    with pytest.raises(UnredactedRecordError):
        RecordStore().add(forged)


def test_copied_seal_onto_different_content_rejected() -> None:
    a = _record(status=200)
    b = _record(status=500)
    # Paste A's seal onto B's (different) content → must not validate.
    forged = dataclasses.replace(b, provenance=a.provenance)
    with pytest.raises(UnredactedRecordError):
        RecordStore().add(forged)


def test_empty_or_arbitrary_seal_rejected() -> None:
    rec = _record()
    with pytest.raises(UnredactedRecordError):
        RecordStore().add(dataclasses.replace(rec, provenance=""))
    with pytest.raises(UnredactedRecordError):
        RecordStore().add(dataclasses.replace(rec, provenance="deadbeef"))


def test_record_is_rejected_if_nested_child_hides_a_secret() -> None:
    # A record whose content is not actually secret-free fails canonical
    # re-validation even if it somehow carried provenance.
    rec = _record()
    bad_response = ResponseRecord(
        status=200,
        headers={"X-Leak": "AKIA1234567890ABCDEF"},  # credential literal survives
        body="{}",
        redirected=False,
        redirect_location=None,
        truncated=False,
    )
    forged = dataclasses.replace(rec, response=bad_response)  # keeps provenance
    store = RecordStore()
    with pytest.raises(UnredactedRecordError):
        store.add(forged)


# --- constructor runtime validation ------------------------------------------


def test_request_record_rejects_non_string_headers() -> None:
    with pytest.raises(RecordValidationError):
        RequestRecord(method="POST", url="https://x", headers={"k": 1})  # type: ignore[dict-item]
    with pytest.raises(RecordValidationError):
        RequestRecord(method="POST", url="https://x", headers={1: "v"})  # type: ignore[dict-item]


def test_request_record_copies_and_freezes_headers() -> None:
    src = {"Accept": "application/json"}
    rec = RequestRecord(method="POST", url="https://x", headers=src)
    assert isinstance(rec.headers, MappingProxyType)
    src["Accept"] = "changed"
    assert rec.headers["Accept"] == "application/json"  # copied


@pytest.mark.parametrize("status", [True, 2.5, "200", float("inf"), float("nan"), -1, 600])
def test_response_record_rejects_bad_status(status: object) -> None:
    with pytest.raises(RecordValidationError):
        ResponseRecord(
            status=status,  # type: ignore[arg-type]
            headers={}, body="{}", redirected=False, redirect_location=None, truncated=False,
        )


@pytest.mark.parametrize("attempts", [0, -1, True, 2.5])
def test_exchange_record_rejects_bad_attempts(attempts: object) -> None:
    with pytest.raises(RecordValidationError):
        ExchangeRecord(
            request=_valid_request(), response=_valid_response(),
            attempts=attempts,  # type: ignore[arg-type]
            redaction_complete=True,
        )


def test_exchange_record_rejects_wrong_child_types() -> None:
    with pytest.raises(RecordValidationError):
        ExchangeRecord(
            request={"method": "POST"},  # type: ignore[arg-type]
            response=_valid_response(), attempts=1, redaction_complete=True,
        )
    with pytest.raises(RecordValidationError):
        ExchangeRecord(
            request=_valid_request(), response="nope",  # type: ignore[arg-type]
            attempts=1, redaction_complete=True,
        )


def test_exchange_record_rejects_bad_schema_version() -> None:
    with pytest.raises(RecordValidationError):
        ExchangeRecord(
            request=_valid_request(), response=_valid_response(), attempts=1,
            redaction_complete=True, schema_version="exchange-v99",
        )


# --- full-field redaction coverage -------------------------------------------


def test_secret_in_url_path_redacted() -> None:
    rec = build_exchange_record(
        method="POST", url="https://api.example.com/AKIA1234567890ABCDEF/x",
        request_headers={}, status=200, response_headers={}, body="{}",
        redirected=False, redirect_location=None, truncated=False, attempts=1,
    )
    assert "AKIA1234567890ABCDEF" not in json.dumps(rec.to_dict())


def test_secret_in_response_header_value_redacted() -> None:
    rec = build_exchange_record(
        method="POST", url="https://api.example.com/x", request_headers={},
        status=200, response_headers={"X-Thing": "AKIA1234567890ABCDEF"},
        body="{}", redirected=False, redirect_location=None, truncated=False, attempts=1,
    )
    assert "AKIA1234567890ABCDEF" not in json.dumps(rec.to_dict())


def test_known_secret_in_body_redacted() -> None:
    secret = "runtime-opaque-0123456789abcdef"
    rec = build_exchange_record(
        method="POST", url="https://api.example.com/x", request_headers={},
        status=200, response_headers={}, body=f"reply: {secret}",
        redirected=False, redirect_location=None, truncated=False, attempts=1,
        known_secrets=frozenset({secret}),
    )
    assert secret not in json.dumps(rec.to_dict())


def test_store_rejects_fake_even_with_redaction_complete_true() -> None:
    # A non-ExchangeRecord that merely declares redaction_complete=True must be
    # rejected by the type check before the marking check.
    class _Fake:
        redaction_complete = True

        def to_dict(self) -> dict:
            return {"response": {"headers": {"Set-Cookie": "session=SECRET"}}}

    store = RecordStore()
    with pytest.raises(UnredactedRecordError):
        store.add(_Fake())  # type: ignore[arg-type]
    assert len(store) == 0


# --- HttpResponse.to_record integration --------------------------------------


def test_httpresponse_to_record_is_complete_and_redacted() -> None:
    from ai_scan.transport import HttpResponse

    resp = HttpResponse(
        status=200,
        body='{"reply": "ok"}',
        headers={"Set-Cookie": "REDACTED"},
        redirected=False,
        redirect_location=None,
        truncated=False,
        request_line={"method": "POST", "url": "https://api.example.com/chat"},
        request_headers={"Authorization": "REDACTED"},
        attempts=1,
    )
    rec = resp.to_record()
    assert rec.redaction_complete is True
    RecordStore().add(rec)  # accepted
    assert rec.request.headers["Authorization"] == "REDACTED"
