"""SSE + WebSocket adapters: bounded aggregation, truncation/error → inconclusive."""

from __future__ import annotations

import json

import pytest

from ai_scan.adapters import AdapterConfigError, ExtractionError, SseAdapter, WebSocketAdapter
from ai_scan.core.models import DeterminismClass
from ai_scan.injection import (
    ExchangeOutcome,
    InjectionStatus,
    _evaluate_pack_case,
    _select_validators,
)
from ai_scan.packs.schema import TrialPolicy
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse

TARGET = normalize_target("http://127.0.0.1:8080/v1/chat")


def _response(body: str, *, truncated: bool = False, status: int = 200) -> HttpResponse:
    return HttpResponse(
        status=status, body=body, headers={}, redirected=False,
        redirect_location=None, truncated=truncated,
        request_line={"method": "POST", "url": TARGET.url},
    )


def _sse(*deltas: str, done: bool = True) -> str:
    events = ["data: " + json.dumps({"choices": [{"delta": {"content": d}}]}) for d in deltas]
    if done:
        events.append("data: [DONE]")
    return "\n\n".join(events) + "\n\n"


def _ws(*deltas: str, done: bool = True) -> str:
    frames = [json.dumps({"delta": d}) for d in deltas]
    if done:
        frames.append(json.dumps({"type": "done"}))
    return "\n".join(frames)


def test_sse_aggregates_deltas_in_order() -> None:
    adapter = SseAdapter(target=TARGET, model="gpt")
    assert adapter.extract(_response(_sse("Hel", "lo", " world"))) == "Hello world"


def test_sse_request_sets_stream_and_accept() -> None:
    prepared = SseAdapter(target=TARGET, model="gpt").build_request("hi")
    assert json.loads(prepared.body.decode("utf-8"))["stream"] is True
    assert prepared.headers["Accept"] == "text/event-stream"


def test_sse_reaching_max_chars_before_done_raises() -> None:
    # Hitting the bound before [DONE] is truncation, not completion — it must
    # never yield a (confirmable) body.
    adapter = SseAdapter(target=TARGET, model="gpt", max_chars=4)
    with pytest.raises(ExtractionError):
        adapter.extract(_response(_sse("aa", "bb", "cc")))


def test_sse_canary_at_bound_without_terminator_cannot_confirm() -> None:
    canary = "AISCAN-STREAMCAP"
    adapter = SseAdapter(target=TARGET, model="gpt", max_chars=len(canary))
    # A single canary-bearing delta that reaches the bound, with no [DONE].
    body = "data: " + json.dumps({"choices": [{"delta": {"content": canary}}]}) + "\n\n"
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body))


def test_ws_reaching_max_chars_before_done_raises() -> None:
    adapter = WebSocketAdapter(target=TARGET, model="gpt", max_chars=4)
    with pytest.raises(ExtractionError):
        adapter.extract(_response(_ws("aa", "bb", "cc")))


def test_ws_canary_at_bound_without_terminator_cannot_confirm() -> None:
    canary = "AISCAN-STREAMCAP"
    adapter = WebSocketAdapter(target=TARGET, model="gpt", max_chars=len(canary))
    body = json.dumps({"delta": canary})  # one frame, no done frame
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body))


def test_sse_complete_within_bound_still_aggregates() -> None:
    # A terminated stream whose content fits the bound returns normally.
    adapter = SseAdapter(target=TARGET, model="gpt", max_chars=100)
    assert adapter.extract(_response(_sse("Hel", "lo"))) == "Hello"


@pytest.mark.parametrize(
    "body,truncated",
    [
        (_sse("x", done=False), False),   # never terminated
        (_sse("x"), True),                # byte-truncated
    ],
)
def test_sse_incomplete_or_truncated_raises(body, truncated) -> None:
    adapter = SseAdapter(target=TARGET, model="gpt")
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body, truncated=truncated))


def test_sse_error_event_raises() -> None:
    adapter = SseAdapter(target=TARGET, model="gpt")
    body = "data: " + json.dumps({"error": {"message": "boom"}}) + "\n\n"
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body))


def test_ws_aggregates_frames_in_order() -> None:
    adapter = WebSocketAdapter(target=TARGET, model="gpt")
    assert adapter.extract(_response(_ws("Wor", "ld"))) == "World"


def test_ws_upgrade_headers_present() -> None:
    prepared = WebSocketAdapter(target=TARGET, model="gpt").build_request("hi")
    assert prepared.headers["Upgrade"] == "websocket"


@pytest.mark.parametrize(
    "body,truncated",
    [(_ws("x", done=False), False), (_ws("x"), True)],
)
def test_ws_incomplete_or_truncated_raises(body, truncated) -> None:
    adapter = WebSocketAdapter(target=TARGET, model="gpt")
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body, truncated=truncated))


def test_ws_error_frame_raises() -> None:
    adapter = WebSocketAdapter(target=TARGET, model="gpt")
    with pytest.raises(ExtractionError):
        adapter.extract(_response(json.dumps({"error": "nope"})))


@pytest.mark.parametrize("cls", [SseAdapter, WebSocketAdapter])
def test_streaming_empty_model_fails_closed(cls) -> None:
    with pytest.raises(AdapterConfigError):
        cls(target=TARGET, model="")


@pytest.mark.parametrize("cls", [SseAdapter, WebSocketAdapter])
def test_streaming_extra_headers_are_validated_and_frozen(cls) -> None:
    headers = {"X-Test": "one"}
    adapter = cls(target=TARGET, model="gpt", extra_headers=headers)
    headers["X-Test"] = "mutated"

    assert adapter.build_request("hi").headers["X-Test"] == "one"
    with pytest.raises(AdapterConfigError):
        cls(target=TARGET, model="gpt", extra_headers={"X-Test": object()})


def test_streaming_json_pointer_rejects_negative_list_indices() -> None:
    adapter = SseAdapter(target=TARGET, model="gpt", delta_path="/choices/-1/delta/content")
    body = _sse("ignored")
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body))


def test_websocket_wrong_delta_path_fails_closed() -> None:
    adapter = WebSocketAdapter(target=TARGET, model="gpt", delta_path="/missing")
    with pytest.raises(ExtractionError):
        adapter.extract(_response(_ws("ignored")))


def test_truncated_streaming_response_classifies_inconclusive() -> None:
    # Through the shared M7 predicate, a byte-truncated streaming response is
    # inconclusive — never confirmed — even if the canary appears in the partial
    # body.
    canary = "AISCAN-STREAM01"
    outcome = ExchangeOutcome(body=f"partial {canary}", truncated=True)
    status, _ = _evaluate_pack_case(
        outcome,
        canary,
        "prompt",
        _select_validators(frozenset({DeterminismClass.DETERMINISTIC})),
        control_succeeded=False,
        matched_clean_control=False,
        trial=TrialPolicy(1, 1, 1),
        requires_state_change=False,
    )
    assert status is InjectionStatus.INCONCLUSIVE


def test_sse_event_error_type_cannot_confirm() -> None:
    # An `event: error` block must be rejected before its data is aggregated,
    # even when the data looks like a normal canary-bearing delta and a later
    # [DONE] arrives.
    canary = "AISCAN-EVTERR0001"
    adapter = SseAdapter(target=TARGET, model="gpt")
    body = (
        "event: error\n"
        "data: " + json.dumps({"choices": [{"delta": {"content": canary}}]}) + "\n\n"
        "data: [DONE]\n\n"
    )
    with pytest.raises(ExtractionError):
        adapter.extract(_response(body))
