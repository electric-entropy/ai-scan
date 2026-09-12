"""Tests for the bounded HTTP transport."""

from __future__ import annotations

import json

import pytest

from ai_scan.injection import generate_canary, load_payloads
from ai_scan.targets import normalize_target
from ai_scan.transport import (
    ACTIVE_METHODS,
    MARKER,
    BudgetExceededError,
    HttpResponse,
    RequestController,
    Transport,
    TransportConfig,
    TransportError,
    json_escape_prompt,
)
from tests.conftest import MockRequest, MockResponse


def _target(server, path="/chat"):
    return normalize_target(f"{server.base_url}{path}")


def test_get_inserts_prompt_at_marker_in_query(echo_server) -> None:
    t = Transport(TransportConfig())
    target = _target(echo_server, f"/chat?q={MARKER}")
    resp = t.send(target, method="GET", prompt="hello world")
    echoed = json.loads(resp.body)
    assert echoed["method"] == "GET"
    assert "hello%20world" in echoed["path"] or "hello world" in echoed["path"]


def test_post_inserts_prompt_at_marker_in_json_body(echo_server) -> None:
    t = Transport(TransportConfig())
    target = _target(echo_server)
    template = json.dumps({"messages": [{"role": "user", "content": MARKER}]})
    resp = t.send(target, method="POST", prompt="PING", body_template=template)
    echoed = json.loads(resp.body)
    assert "PING" in echoed["body"]
    assert MARKER not in echoed["body"]


def test_sends_user_agent(echo_server) -> None:
    t = Transport(TransportConfig(user_agent="ai-scan-test/9"))
    resp = t.send(_target(echo_server), method="POST", prompt="x", body_template=MARKER)
    echoed = json.loads(resp.body)
    assert echoed["headers"].get("User-Agent") == "ai-scan-test/9"


def test_redirect_is_not_followed_and_captured_as_evidence(mock_server) -> None:
    def behavior(req: MockRequest) -> MockResponse:
        return MockResponse(
            status=302,
            headers={"Location": "http://evil.example.com/steal"},
            body=b"",
        )

    server = mock_server(behavior)
    t = Transport(TransportConfig())
    resp = t.send(_target(server), method="POST", prompt="x", body_template=MARKER)
    assert resp.status == 302
    assert resp.redirected is True
    assert resp.redirect_location == "http://evil.example.com/steal"


def test_oversized_response_is_truncated_and_flagged(mock_server) -> None:
    big = b"A" * 5000

    def behavior(req: MockRequest) -> MockResponse:
        return MockResponse(status=200, body=big)

    server = mock_server(behavior)
    t = Transport(TransportConfig(max_response_bytes=1024))
    resp = t.send(_target(server), method="POST", prompt="x", body_template=MARKER)
    assert len(resp.body.encode("utf-8")) <= 1024
    assert resp.truncated is True


def test_redacts_sensitive_request_headers_in_evidence(echo_server) -> None:
    t = Transport(TransportConfig())
    resp = t.send(
        _target(echo_server),
        method="POST",
        prompt="x",
        body_template=MARKER,
        headers={
            "Authorization": "Bearer super-secret-token",
            "Cookie": "session=abc123",
            "X-Api-Key": "key-9999",
            "X-Auth-Token": "tok-8888",
            "Accept": "application/json",
        },
    )
    evidence = resp.evidence()
    dumped = json.dumps(evidence)
    assert "super-secret-token" not in dumped
    assert "abc123" not in dumped
    assert "key-9999" not in dumped
    assert "tok-8888" not in dumped
    assert "REDACTED" in dumped
    # Non-sensitive headers are preserved.
    assert evidence["request"]["headers"].get("Accept") == "application/json"


def test_secret_not_in_exception_string_on_bad_host() -> None:
    t = Transport(TransportConfig(timeout=0.5))
    # Unroutable target; the secret header must never surface in the error text.
    target = normalize_target("http://127.0.0.1:9/chat")
    with pytest.raises(TransportError) as exc:
        t.send(
            target,
            method="POST",
            prompt="x",
            body_template=MARKER,
            headers={"Authorization": "Bearer super-secret-token"},
        )
    assert "super-secret-token" not in str(exc.value)


def test_timeout_is_required_positive() -> None:
    with pytest.raises(ValueError):
        TransportConfig(timeout=0)


def test_response_type() -> None:
    t = Transport(TransportConfig())
    assert isinstance(t.config.max_response_bytes, int)
    assert HttpResponse  # imported symbol is usable


def test_json_escape_prompt_handles_control_chars_and_quotes() -> None:
    prompt = 'line1\nline2\t"q" \\ end'
    escaped = json_escape_prompt(prompt)
    # Inserted into a JSON string position, the result must parse and round-trip.
    body = '{"input": "' + escaped + '"}'
    assert json.loads(body)["input"] == prompt


def test_post_body_stays_valid_json_with_newline_and_quote_prompt(echo_server) -> None:
    t = Transport(TransportConfig())
    prompt = 'first\nsecond "quoted" \\ done'
    resp = t.send(
        _target(echo_server),
        method="POST",
        prompt=prompt,
        body_template='{"input": "*"}',
    )
    echoed = json.loads(resp.body)
    # The raw request body the server received must itself be valid JSON.
    sent_body = json.loads(echoed["body"])
    assert sent_body["input"] == prompt


def test_all_default_payloads_render_valid_json_in_default_body(echo_server) -> None:
    # Reproduces the review blocker: newline-containing payloads must not
    # produce invalid JSON under the default {"input": "*"} template.
    t = Transport(TransportConfig())
    canary = generate_canary()
    pack = load_payloads("safe")
    for family in pack.families:
        for template in family.templates:
            prompt = template.replace("{canary}", canary)
            resp = t.send(
                _target(echo_server),
                method="POST",
                prompt=prompt,
                body_template='{"input": "*"}',
            )
            echoed = json.loads(resp.body)
            sent_body = json.loads(echoed["body"])  # must not raise
            assert canary in sent_body["input"]


# --- Finding 1: evidence must not leak secrets from URL/Location/headers ------


def test_secret_query_params_are_redacted_in_evidence(echo_server) -> None:
    t = Transport(TransportConfig())
    target = normalize_target(
        f"{echo_server.base_url}/chat?api_key=SEEKRIT123&token=TT-999&q=hello"
    )
    resp = t.send(target, method="POST", prompt="x", body_template='{"input": "*"}')
    dumped = json.dumps(resp.evidence())
    assert "SEEKRIT123" not in dumped
    assert "TT-999" not in dumped
    assert "REDACTED" in dumped
    # Non-secret query values are preserved.
    assert "hello" in resp.evidence()["request"]["url"]


def test_redirect_location_secrets_are_redacted(mock_server) -> None:
    def behavior(req: MockRequest) -> MockResponse:
        return MockResponse(
            status=302,
            headers={"Location": "http://evil.example.com/c?session=ABCSECRET&x=1"},
            body=b"",
        )

    server = mock_server(behavior)
    t = Transport(TransportConfig())
    resp = t.send(
        normalize_target(f"{server.base_url}/x"),
        method="POST",
        prompt="x",
        body_template=MARKER,
    )
    assert resp.redirected is True
    dumped = json.dumps(resp.evidence())
    assert "ABCSECRET" not in dumped


def test_unrecognized_token_header_is_redacted(echo_server) -> None:
    # An unrecognized but clearly token-bearing header name (ends in a credential
    # token) is redacted by the precise classifier, while a benign header is kept.
    t = Transport(TransportConfig())
    resp = t.send(
        normalize_target(f"{echo_server.base_url}/chat"),
        method="POST",
        prompt="x",
        body_template='{"input": "*"}',
        headers={"X-Acme-Access-Token": "blob-SECRET-42", "Accept": "text/plain"},
    )
    dumped = json.dumps(resp.evidence())
    assert "blob-SECRET-42" not in dumped
    assert resp.evidence()["request"]["headers"].get("Accept") == "text/plain"


# --- Finding 2: HTTP method allowlist ----------------------------------------


def test_active_methods_allowlist_is_get_post() -> None:
    assert ACTIVE_METHODS == frozenset({"GET", "POST"})


@pytest.mark.parametrize("method", ["DELETE", "PUT", "PATCH", "TRACE", "FROBNICATE"])
def test_unsafe_methods_are_rejected(echo_server, method: str) -> None:
    t = Transport(TransportConfig())
    with pytest.raises(TransportError):
        t.send(
            normalize_target(f"{echo_server.base_url}/x"),
            method=method,
            prompt="x",
            body_template=MARKER,
        )


# --- Finding 4: enforced rate limiting (injected clock/sleeper) --------------


def test_rate_limit_sleeps_between_requests(echo_server) -> None:
    clock_t = {"now": 0.0}
    slept: list[float] = []

    def clock() -> float:
        return clock_t["now"]

    def sleeper(seconds: float) -> None:
        slept.append(seconds)
        clock_t["now"] += seconds  # advance virtual time

    controller = RequestController(
        max_requests=10, min_interval=0.5, clock=clock, sleeper=sleeper
    )
    t = Transport(TransportConfig(), controller=controller)
    target = normalize_target(f"{echo_server.base_url}/chat")
    for _ in range(3):
        t.send(target, method="POST", prompt="x", body_template='{"input": "*"}')
    # First request no wait; subsequent ones each wait ~min_interval.
    assert len([s for s in slept if s > 0]) >= 2


# --- Finding 7: single physical-request counter incl. retries ----------------


def test_budget_counts_every_physical_attempt_including_retries() -> None:
    controller = RequestController(max_requests=2, min_interval=0.0)
    t = Transport(TransportConfig(max_retries=5), controller=controller)
    # Unroutable host forces retries; the budget must stop it at 2 attempts.
    target = normalize_target("http://127.0.0.1:9/chat")
    with pytest.raises(TransportError):
        t.send(target, method="POST", prompt="x", body_template=MARKER)
    assert controller.count == 2


def test_response_reports_attempts(echo_server) -> None:
    controller = RequestController(max_requests=10, min_interval=0.0)
    t = Transport(TransportConfig(), controller=controller)
    resp = t.send(
        normalize_target(f"{echo_server.base_url}/chat"),
        method="POST",
        prompt="x",
        body_template='{"input": "*"}',
    )
    assert resp.attempts == 1
    assert controller.count == 1


def test_budget_exhaustion_raises_budget_error(echo_server) -> None:
    controller = RequestController(max_requests=1, min_interval=0.0)
    t = Transport(TransportConfig(), controller=controller)
    target = normalize_target(f"{echo_server.base_url}/chat")
    t.send(target, method="POST", prompt="x", body_template='{"input": "*"}')
    with pytest.raises(BudgetExceededError):
        t.send(target, method="POST", prompt="x", body_template='{"input": "*"}')


# --- Finding 10: responses are explicitly closed -----------------------------


def test_response_objects_are_closed(echo_server) -> None:
    closed: list[bool] = []
    t = Transport(TransportConfig())

    # Wrap the broker's opener (shared from the transport) to observe close()
    # calls. Physical I/O now flows through the broker, which always closes the
    # response via contextlib.closing.
    import urllib.request as _u

    orig_open = t._opener.open

    def wrapped_open(*a, **k):
        raw = orig_open(*a, **k)
        orig_close = raw.close

        def tracking_close() -> None:
            closed.append(True)
            orig_close()

        raw.close = tracking_close  # type: ignore[method-assign]
        return raw

    t._opener.open = wrapped_open  # type: ignore[method-assign]
    assert _u  # keep reference used
    t.send(
        normalize_target(f"{echo_server.base_url}/chat"),
        method="POST",
        prompt="x",
        body_template='{"input": "*"}',
    )
    assert closed == [True]
