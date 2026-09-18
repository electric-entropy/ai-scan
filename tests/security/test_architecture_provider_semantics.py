"""Architecture regressions for one provider semantic-eligibility decision."""

from __future__ import annotations

import hashlib
import json

import pytest

from ai_scan.adapters import ExtractionError, OpenAICompatibleAdapter
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse


def _response(*, status: int, redirected: bool = False, body: bytes | None = None) -> HttpResponse:
    raw = body or (
        b'{"choices":[{"message":{"role":"assistant","content":"benign"},'
        b'"finish_reason":"stop"}],"usage":{"total_tokens":2}}'
    )
    return HttpResponse(
        status=status,
        body=raw.decode("utf-8", errors="replace"),
        headers={},
        redirected=redirected,
        redirect_location="http://127.0.0.1/elsewhere" if redirected else None,
        truncated=False,
        request_line={"method": "POST", "url": "http://127.0.0.1/provider"},
        raw_body_digest=hashlib.sha256(raw).hexdigest(),
        raw_body_length=len(raw),
        decode_valid=True,
    )


@pytest.mark.parametrize("status,redirected", [(0, False), (302, True), (400, False), (500, False)])
def test_non_success_provider_responses_share_identity_only_decision(
    status: int, redirected: bool
) -> None:
    response = _response(status=status, redirected=redirected)
    decision = response.provider_semantics()
    audit = json.loads(response.evidence(redact_provider_text=True)["response"]["body"])

    assert decision.final_content_eligible is False
    assert decision.audit_metadata_eligible is False
    assert set(audit) == {"audit_version", "raw_body"}


def test_success_provider_decision_drives_extraction_and_allowlisted_audit() -> None:
    response = _response(status=200)
    decision = response.provider_semantics()
    audit = json.loads(response.evidence(redact_provider_text=True)["response"]["body"])
    adapter = OpenAICompatibleAdapter(
        target=normalize_target("http://127.0.0.1:8000/v1/chat/completions"),
        model="local",
    )

    assert decision.final_content_eligible is True
    assert decision.audit_metadata_eligible is True
    assert adapter.extract(response) == "benign"
    assert set(audit) <= {"audit_version", "raw_body", "role", "completion_state", "usage"}


def test_provider_adapter_rejects_content_when_shared_decision_is_ineligible() -> None:
    response = _response(status=500)
    adapter = OpenAICompatibleAdapter(
        target=normalize_target("http://127.0.0.1:8000/v1/chat/completions"),
        model="local",
    )
    with pytest.raises(ExtractionError):
        adapter.extract(response)


@pytest.mark.parametrize("finish_reason", ["length", "max_tokens", "tool_calls"])
def test_incomplete_provider_finish_state_is_identity_only(finish_reason: str) -> None:
    raw = json.dumps(
        {
            "choices": [
                {
                    "message": {"role": "assistant", "content": "partial"},
                    "finish_reason": finish_reason,
                }
            ]
        }
    ).encode()
    response = _response(status=200, body=raw)
    decision = response.provider_semantics()
    audit = json.loads(response.evidence(redact_provider_text=True)["response"]["body"])

    assert decision.final_content_eligible is False
    assert decision.audit_metadata_eligible is False
    assert set(audit) == {"audit_version", "raw_body"}
