"""LLM04 external retrieval-poisoning protocol CLI coverage."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.resources
import json
import random
import re
import string
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ai_scan import cli
from ai_scan import data_poisoning as dp
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse, RequestController, Transport, TransportError
from ai_scan.transport.broker import RawExchange
from ai_scan.transport.budgets import AttemptKind

PROTOCOL = "ai-scan-llm04-retrieval-v1"
OPERATIONS = (
    "pre_attack_query",
    "pre_clean_query",
    "poison_ingest",
    "post_attack_query",
    "post_clean_query",
    "isolation_query",
    "cleanup",
    "cleanup_verify",
)


def _http_response(raw: bytes, *, truncated: bool = False) -> HttpResponse:
    return HttpResponse(
        status=200,
        body=raw.decode("utf-8", errors="replace"),
        headers={},
        redirected=False,
        redirect_location=None,
        truncated=truncated,
        request_line={"method": "POST", "url": "<target>"},
        raw_body_digest=hashlib.sha256(raw).hexdigest(),
        raw_body_length=len(raw),
    )


class _FixtureState:
    def __init__(self, behavior: str = "secure", **flags: object) -> None:
        self.behavior = behavior
        self.flags = flags
        self.requests: list[dict[str, object]] = []
        self.poison_marker: str | None = None
        self.poison_item_id: str | None = None
        self.deleted = False

    def handle(self, body: dict[str, object]) -> tuple[int, dict[str, object]]:
        self.requests.append(body)
        index = len(self.requests) - 1
        expected = OPERATIONS[index] if index < len(OPERATIONS) else "unexpected"
        assert body["protocol_version"] == PROTOCOL
        assert body["operation"] == expected
        assert re.fullmatch(r"llm04-trial-[0-9a-f]{32}", str(body["trial_id"]))
        assert re.fullmatch(r"op-[0-9a-f]{32}", str(body["operation_id"]))
        assert body["namespace"] in {"tenant-alpha", "tenant-beta"}
        body_text = json.dumps(body, sort_keys=True)
        if expected != "poison_ingest":
            assert "AISCAN-POISON-" not in body_text
        if expected == "poison_ingest":
            content = str(body["content"])
            marker = str(body["marker"])
            assert marker in content
            assert marker.startswith("AISCAN-POISON-")
            assert body["poison_item_id"]
            self.poison_marker = marker
            self.poison_item_id = str(body["poison_item_id"])
        payload: dict[str, object] = {
            "protocol_version": PROTOCOL,
            "trial_id": body["trial_id"],
            "operation_id": body["operation_id"],
            "status": "ok",
        }
        if self.flags.get("wrong_identity") and expected == "post_attack_query":
            payload["operation_id"] = "op-" + "0" * 32
        if self.flags.get("replay") and expected == "post_attack_query" and len(self.requests) >= 1:
            prior = self.requests[0]
            payload["operation_id"] = prior["operation_id"]
        if self.flags.get("unknown_response_key") and expected == "post_attack_query":
            payload["unexpected"] = "x"
        if self.flags.get("marker_in_metadata") and expected == "post_attack_query":
            payload["metadata"] = {"content": self.poison_marker}
        if expected.endswith("query") or expected == "cleanup_verify":
            payload["retrieval"] = {"content": self._content_for(expected)}
        if expected == "cleanup":
            if self.flags.get("cleanup_failure"):
                payload["status"] = "error"
            else:
                self.deleted = True
        return (200, payload)

    def _content_for(self, operation: str) -> str:
        marker = self.poison_marker or ""
        if self.flags.get("dirty_pre") and operation == "pre_attack_query":
            return marker or "AISCAN-POISON-DIRTY"
        if self.flags.get("dirty_clean") and operation == "post_clean_query":
            return marker
        if self.flags.get("namespace_crossover") and operation == "isolation_query":
            return marker
        if self.flags.get("lying_cleanup") and operation == "cleanup_verify":
            return marker
        if operation == "post_attack_query" and self.behavior == "vulnerable":
            mode = self.flags.get("attack_marker_mode", "exact")
            if mode == "exact":
                return marker
            if mode == "prefixed":
                return f"prefix-{marker}"
            if mode == "suffixed":
                return f"{marker}-suffix"
            if mode == "explanation":
                return f"I saw marker {marker} in an explanation, not retrieval."
        return "clean retrieval result"


@contextlib.contextmanager
def _server(state: _FixtureState):  # type: ignore[no-untyped-def]
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/llm04":
                self.send_response(404)
                self.end_headers()
                return
            if state.flags.get("redirect"):
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/escape")
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            if state.flags.get("duplicate_json"):
                response = (
                    b'{"protocol_version":"ai-scan-llm04-retrieval-v1",'
                    b'"status":"ok","status":"ok"}'
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                return
            body = json.loads(raw.decode("utf-8"))
            status, payload = state.handle(body)
            data = json.dumps(payload, sort_keys=True).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args: object) -> None:
            return

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}/llm04"
    finally:
        httpd.shutdown()
        thread.join(timeout=5)
        httpd.server_close()


def _run(target: str, capsys: pytest.CaptureFixture[str], fmt: str = "json") -> tuple[int, str]:
    code = cli.main(["data-poisoning-audit", "--target", target, "--format", fmt])
    return code, capsys.readouterr().out


def _assert_public_output_is_opaque(output: str, state: _FixtureState) -> None:
    parsed = json.loads(output)
    assert parsed["schema_version"] == "ai-scan-data-poisoning-result-v3"
    rendered = json.dumps(parsed, sort_keys=True)
    forbidden = [
        "AISCAN-POISON-",
        "tenant-alpha",
        "tenant-beta",
        "benefits policy",
        "travel policy",
        "clean retrieval result",
        "http://127.0.0.1",
    ]
    for request in state.requests:
        secretish_keys = (
            "trial_id",
            "operation_id",
            "poison_item_id",
            "marker",
            "content",
            "query",
            "namespace",
        )
        for key in secretish_keys:
            value = str(request.get(key, ""))
            if value:
                forbidden.append(value)
    for value in forbidden:
        if value:
            assert value not in rendered
    for check in parsed["checks"]:
        assert re.fullmatch(r"llm04-[a-z]+-[0-9a-f]{32}", str(check["ref"]))
        assert re.fullmatch(r"[0-9a-f]{64}", str(check["request_commitment"]))
        for field in ("response_commitment", "eligible_content_commitment"):
            value = check[field]
            assert value is None or re.fullmatch(r"[0-9a-f]{64}", str(value))
        assert "commitment" not in check
    assert parsed["physical_requests"]["total"] >= len(state.requests)


def test_vulnerable_external_service_confirms_only_after_full_protocol_and_cleanup(
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _FixtureState("vulnerable")
    with _server(state) as target:
        code, out = _run(target, capsys)

    assert code == cli.EXIT_CONFIRMED_FINDING
    assert [request["operation"] for request in state.requests] == list(OPERATIONS)
    assert state.deleted is True
    parsed = json.loads(out)
    assert parsed["status"] == "finding"
    assert {check["reason_code"] for check in parsed["checks"]} == {
        "pre_poison_absent",
        "pre_clean_absent",
        "post_clean_unaffected",
        "namespace_isolated",
        "cleanup_verified",
        "eligible_retrieval_after_poison",
    }
    _assert_public_output_is_opaque(out, state)


def test_secure_external_service_runs_same_protocol_without_finding(
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _FixtureState("secure")
    with _server(state) as target:
        code, out = _run(target, capsys)

    assert code == cli.EXIT_OK
    assert [request["operation"] for request in state.requests] == list(OPERATIONS)
    parsed = json.loads(out)
    assert parsed["status"] == "passed"
    assert "eligible_retrieval_after_poison" not in {
        check["reason_code"] for check in parsed["checks"]
    }
    _assert_public_output_is_opaque(out, state)


@pytest.mark.parametrize(
    ("flag", "reason"),
    [
        ("dirty_clean", "dirty_control_content"),
        ("namespace_crossover", "dirty_control_content"),
        ("cleanup_failure", "cleanup_failed"),
        ("lying_cleanup", "cleanup_unresolved"),
        ("wrong_identity", "protocol_identity_mismatch"),
        ("replay", "protocol_identity_mismatch"),
        ("unknown_response_key", "malformed_response"),
        ("duplicate_json", "malformed_response"),
        ("redirect", "transport_not_usable"),
    ],
)
def test_adversarial_service_behaviors_fail_closed_without_findings(
    flag: str, reason: str, capsys: pytest.CaptureFixture[str]
) -> None:
    state = _FixtureState("vulnerable", **{flag: True})
    with _server(state) as target:
        code, out = _run(target, capsys)

    assert code in {cli.EXIT_INCONCLUSIVE, cli.EXIT_DENIED}
    if out.lstrip().startswith("{"):
        parsed = json.loads(out)
        assert parsed["status"] in {"inconclusive", "blocked"}
        assert not any(check["status"] == "finding" for check in parsed["checks"])
        assert reason in {check["reason_code"] for check in parsed["checks"]}
        _assert_public_output_is_opaque(out, state)
    else:
        assert "AISCAN-POISON-" not in out


@pytest.mark.parametrize("mode", ["prefixed", "suffixed", "explanation"])
def test_marker_context_that_is_not_exact_retrieval_content_does_not_confirm(
    mode: str, capsys: pytest.CaptureFixture[str]
) -> None:
    state = _FixtureState("vulnerable", attack_marker_mode=mode)
    with _server(state) as target:
        code, out = _run(target, capsys)

    assert code == cli.EXIT_INCONCLUSIVE
    parsed = json.loads(out)
    assert parsed["status"] == "inconclusive"
    assert "ineligible_retrieval_content" in {check["reason_code"] for check in parsed["checks"]}
    _assert_public_output_is_opaque(out, state)


@pytest.mark.parametrize(
    "control",
    [
        "pre_attack_query",
        "pre_clean_query",
        "post_clean_query",
        "isolation_query",
        "cleanup_verify",
    ],
)
@pytest.mark.parametrize(
    "representation",
    [
        "prefix",
        "suffix",
        "explanation",
        "percent",
        "base64",
        "base64_unpadded",
        "hex",
        "unicode_escape",
        "mixed_unicode_escape",
        "mixed_percent",
        "mixed_hex",
        "mixed_base64_suffix",
        "mixed_base64_prefix",
        "nested_percent_at_decode_cap",
    ],
)
def test_marker_in_any_control_representation_prevents_finding(
    control: str, representation: str
) -> None:
    marker = "AISCAN-POISON-" + "A" * 48

    def encoded() -> str:
        if representation == "prefix":
            return "prefix-" + marker
        if representation == "suffix":
            return marker + "-suffix"
        if representation == "explanation":
            return "request echo contained " + marker + " in prior input"
        if representation == "percent":
            return "".join(f"%{byte:02X}" for byte in marker.encode())
        if representation == "base64":
            return base64.b64encode(marker.encode()).decode()
        if representation == "base64_unpadded":
            return base64.b64encode(marker.encode()).decode().rstrip("=")
        if representation == "hex":
            return marker.encode().hex()
        if representation == "unicode_escape":
            return "".join(f"\\u{ord(char):04x}" for char in marker)
        split = len(marker) // 2
        if representation == "mixed_unicode_escape":
            return marker[:split] + "".join(
                f"\\u{ord(char):04x}" for char in marker[split:]
            )
        if representation == "mixed_percent":
            return marker[:split] + "".join(
                f"%{byte:02X}" for byte in marker[split:].encode()
            )
        if representation == "mixed_hex":
            return marker[:split] + marker[split:].encode().hex()
        if representation == "mixed_base64_suffix":
            return marker[:split] + base64.b64encode(marker[split:].encode()).decode().rstrip("=")
        if representation == "mixed_base64_prefix":
            return base64.b64encode(marker[:split].encode()).decode() + marker[split:]
        nested = "".join(f"%{byte:02X}" for byte in marker.encode())
        for _ in range(5):
            nested = "".join(f"%{byte:02X}" for byte in nested.encode())
        return nested

    results = {
        operation: dp._OperationResult(
            operation=operation,
            operation_id=f"op-{index:032x}",
            status="ok",
            content=(
                marker
                if operation == "post_attack_query"
                else encoded()
                if operation == control
                else "clean"
            ),
            request_commitment=f"{index:064x}",
            response_commitment=f"{index + 100:064x}",
            eligible_content_commitment=f"{index + 200:064x}",
        )
        for index, operation in enumerate(OPERATIONS, start=1)
    }
    checks: list[dict[str, object]] = []

    dp._classify_results(results, checks, "target-ref", "trial-ref", marker)

    assert not any(check["status"] == "finding" for check in checks)
    assert any(check["reason_code"] == "dirty_control_content" for check in checks)


def test_deeply_percent_encoded_benign_content_is_not_a_dirty_control() -> None:
    marker = "AISCAN-POISON-" + "C" * 48
    benign = "harmless"
    for _ in range(6):
        benign = "".join(f"%{byte:02X}" for byte in benign.encode())

    assert dp._contains_marker_representation(benign, marker) is False


def test_full_base64_matches_padded_and_unpadded_forms() -> None:
    marker = "AISCAN-POISON-" + "E" * 48
    padded = base64.b64encode(marker.encode()).decode()

    assert padded.endswith("=")
    assert dp._contains_marker_representation(padded, marker) is True
    assert dp._contains_marker_representation(padded.rstrip("="), marker) is True


def test_randomized_benign_encoded_content_stays_clean_and_bounded() -> None:
    marker = "AISCAN-POISON-" + "D" * 48
    rng = random.Random(20260917)
    alphabet = string.ascii_letters + string.digits + " _-."
    for _ in range(250):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 256)))
        for _depth in range(rng.randint(0, 8)):
            codec = rng.choice(("percent", "base64", "hex"))
            if codec == "percent":
                value = "".join(f"%{byte:02X}" for byte in value.encode())
            elif codec == "base64":
                value = base64.b64encode(value.encode()).decode()
            else:
                value = value.encode().hex()
            if len(value) > 32_768:
                break
        assert dp._contains_marker_representation(value, marker) is False


def test_marker_in_response_metadata_envelope_does_not_confirm(
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _FixtureState("secure", marker_in_metadata=True)
    with _server(state) as target:
        code, out = _run(target, capsys)

    assert code == cli.EXIT_INCONCLUSIVE
    parsed = json.loads(out)
    assert parsed["status"] == "inconclusive"
    _assert_public_output_is_opaque(out, state)


def test_error_status_retrieval_content_never_confirms() -> None:
    marker = "AISCAN-POISON-" + "B" * 48
    results = {
        operation: dp._OperationResult(
            operation=operation,
            operation_id=f"op-{index:032x}",
            status="error" if operation == "post_attack_query" else "ok",
            content=marker if operation == "post_attack_query" else "clean",
            request_commitment=f"{index:064x}",
            response_commitment=f"{index + 100:064x}",
            eligible_content_commitment=(
                None if operation == "post_attack_query" else f"{index + 200:064x}"
            ),
        )
        for index, operation in enumerate(OPERATIONS, start=1)
    }
    checks: list[dict[str, object]] = []

    dp._classify_results(results, checks, "target-ref", "trial-ref", marker)

    assert not any(check["status"] == "finding" for check in checks)
    assert "operation_error" in {check["reason_code"] for check in checks}


def test_target_validation_happens_before_transport_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode_transport(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("transport must not be constructed for invalid offline config")

    monkeypatch.setattr(cli, "_make_transport", explode_transport)
    assert (
        cli.main(["data-poisoning-audit", "--target", "https://example.com/a#frag"])
        == cli.EXIT_RUNTIME_ERROR
    )


def test_named_localhost_is_blocked_but_ip_literal_loopback_is_explicitly_allowed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _FixtureState("secure")
    with _server(state) as target:
        localhost = target.replace("127.0.0.1", "localhost")
        code, out = _run(localhost, capsys)
        assert code == cli.EXIT_DENIED
        assert "private" in out or "blocked" in out

        code, out = _run(target, capsys)
        assert code == cli.EXIT_OK
        assert json.loads(out)["status"] == "passed"


def test_unsafe_request_budget_is_rejected_before_any_io(
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = _FixtureState("vulnerable")
    with _server(state) as target:
        code = cli.main(
            [
                "data-poisoning-audit",
                "--target",
                target,
                "--format",
                "json",
                "--max-requests",
                "4",
            ]
        )
        out = capsys.readouterr().out

    assert code == cli.EXIT_RUNTIME_ERROR
    assert state.requests == []
    assert out.strip() == "invalid: llm04_request_budget_too_small"


@pytest.mark.parametrize(
    "target",
    [
        "gopher://token-SECRET.example/path",
        "http://token-SECRET.example/path#fragment",
        "http://token-SECRET.example:999999/path?api_key=SECRET",
        "http://" + "user" + ":" + "SECRET" + "@host.example/path",
    ],
)
def test_target_errors_never_echo_submitted_target_or_parser_details(
    target: str, capsys: pytest.CaptureFixture[str]
) -> None:
    code = cli.main(["data-poisoning-audit", "--target", target])
    captured = capsys.readouterr()

    assert code == cli.EXIT_RUNTIME_ERROR
    assert captured.out.strip() == "invalid: llm04_target_invalid"
    assert captured.err == ""
    assert "SECRET" not in captured.out
    assert "token" not in captured.out


class _UncertainIngestTransport:
    def __init__(
        self,
        controller: RequestController,
        ingest_failure: str,
        *,
        cleanup_fails: bool = False,
        expire_after_ingest: list[float] | None = None,
    ) -> None:
        self.controller = controller
        self.ingest_failure = ingest_failure
        self.cleanup_fails = cleanup_fails
        self.expire_after_ingest = expire_after_ingest
        self.operations: list[str] = []
        self.stored = False

    def send_prepared(self, target: object, prepared: object) -> HttpResponse:
        with self.controller.ledger.attempt(AttemptKind.INITIAL):
            request = json.loads(prepared.body)  # type: ignore[union-attr]
            operation = request["operation"]
            self.operations.append(operation)
            if operation == "poison_ingest":
                self.stored = True
                if self.expire_after_ingest is not None:
                    self.expire_after_ingest[0] = 2.0
                if self.ingest_failure == "lost":
                    raise TransportError("connection failed")
                if self.ingest_failure == "malformed":
                    return _http_response(b"not-json")
            if operation == "cleanup":
                if self.cleanup_fails:
                    raise TransportError("connection failed")
                self.stored = False
            payload: dict[str, object] = {
                "protocol_version": PROTOCOL,
                "trial_id": request["trial_id"],
                "operation_id": request["operation_id"],
                "status": "ok",
            }
            if operation.endswith("query") or operation == "cleanup_verify":
                payload["retrieval"] = {"content": "clean"}
            return _http_response(json.dumps(payload).encode())


@pytest.mark.parametrize("failure", ["lost", "malformed"])
def test_uncertain_ingest_always_attempts_cleanup_and_reader_verification(failure: str) -> None:
    controller = RequestController(max_requests=16, max_duration_seconds=10)
    transport = _UncertainIngestTransport(controller, failure)

    result = dp.assess_target(
        normalize_target("http://127.0.0.1:9999/llm04"), transport, controller  # type: ignore[arg-type]
    )

    assert transport.operations == [
        "pre_attack_query",
        "pre_clean_query",
        "poison_ingest",
        "cleanup",
        "cleanup_verify",
    ]
    assert transport.stored is False
    assert result.status == "inconclusive"
    assert not any(check["status"] == "finding" for check in result.checks)


def test_cleanup_retry_exhaustion_is_bounded_and_reported_unresolved() -> None:
    controller = RequestController(max_requests=16, max_duration_seconds=10)
    transport = _UncertainIngestTransport(controller, "lost", cleanup_fails=True)

    result = dp.assess_target(
        normalize_target("http://127.0.0.1:9999/llm04"), transport, controller  # type: ignore[arg-type]
    )

    assert transport.operations.count("cleanup") == dp.RETRY_ATTEMPTS
    assert "cleanup_verify" not in transport.operations
    assert transport.stored is True
    assert result.status == "inconclusive"
    assert "cleanup_unresolved" in {check["reason_code"] for check in result.checks}
    assert result.physical_requests["total"] <= controller.max_requests


def test_expired_deadline_does_not_extend_for_cleanup_and_reports_unresolved() -> None:
    now = [0.0]
    controller = RequestController(
        max_requests=16, max_duration_seconds=1.0, clock=lambda: now[0]
    )
    transport = _UncertainIngestTransport(controller, "lost", expire_after_ingest=now)

    result = dp.assess_target(
        normalize_target("http://127.0.0.1:9999/llm04"), transport, controller  # type: ignore[arg-type]
    )

    assert transport.operations == ["pre_attack_query", "pre_clean_query", "poison_ingest"]
    assert transport.stored is True
    assert result.status == "inconclusive"
    assert "cleanup_unresolved" in {check["reason_code"] for check in result.checks}
    document = result.to_dict()
    assert document["external_state"] == {
        "unresolved": True,
        "notice": dp.UNRESOLVED_EXTERNAL_STATE_NOTICE,
    }
    assert "127.0.0.1" not in dp.render_human(result)
    assert dp.UNRESOLVED_EXTERNAL_STATE_NOTICE in dp.render_human(result)


def _redigest_protocol(document: dict[str, object]) -> str:
    unsigned = dict(document)
    unsigned.pop("content_digest", None)
    canonical = json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return hashlib.sha256(b"ai-scan-llm04-protocol-resource-v1\0" + canonical).hexdigest()


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown",
        "missing",
        "operation",
        "count",
        "contract",
        "version",
        "nested_unknown",
        "nested_missing",
        "nested_type",
        "response_contract",
        "request_shape_contract",
        "cleanup_contract",
        "error_contract",
    ],
)
def test_protocol_resource_rejects_redigested_semantic_tampering(mutation: str) -> None:
    text = (
        importlib.resources.files("ai_scan")
        .joinpath("owasp/llm04-retrieval-protocol-v1.json")
        .read_text(encoding="utf-8")
    )
    document = json.loads(text)
    if mutation == "unknown":
        document["unknown"] = True
    elif mutation == "missing":
        document.pop("transport")
    elif mutation == "operation":
        document["operation_order"][0] = "post_attack_query"
    elif mutation == "count":
        document["operation_order"].pop()
    elif mutation == "contract":
        document["confirmation_contract"] = "exact marker is enough"
    elif mutation == "version":
        document["protocol_version"] = "ai-scan-llm04-retrieval-v2"
    elif mutation == "nested_unknown":
        document["request_fields"]["unknown"] = []
    elif mutation == "nested_missing":
        document["response_fields"].pop("status_values")
    elif mutation == "nested_type":
        document["request_fields"]["required"] = "protocol_version"
    elif mutation == "response_contract":
        document["response_fields"]["status_values"] = ["ok"]
    elif mutation == "request_shape_contract":
        document["request_fields"]["by_operation"]["cleanup"].append("marker")
    elif mutation == "cleanup_contract":
        document["cleanup_contract"] = "cleanup is optional"
    else:
        document["error_contract"] = "errors may confirm"
    document["content_digest"] = _redigest_protocol(document)

    with pytest.raises(dp.DataPoisoningProtocolError, match="protocol_resource_invalid"):
        dp.load_protocol_resource_text(json.dumps(document, allow_nan=False))


def test_protocol_semantics_reject_tamper_even_if_expected_digest_is_monkeypatched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = (
        importlib.resources.files("ai_scan")
        .joinpath("owasp/llm04-retrieval-protocol-v1.json")
        .read_text(encoding="utf-8")
    )
    document = json.loads(text)
    document["request_fields"]["optional_by_operation"]["cleanup"] = [
        "poison_item_id",
        "marker",
    ]
    document["content_digest"] = _redigest_protocol(document)
    monkeypatch.setattr(dp, "PROTOCOL_RESOURCE_DIGEST", document["content_digest"])

    with pytest.raises(dp.DataPoisoningProtocolError, match="protocol_resource_invalid"):
        dp.load_protocol_resource_text(json.dumps(document, allow_nan=False))


@pytest.mark.parametrize(
    "text",
    [
        '{"schema_version":"x","schema_version":"x"}',
        '{"content_digest":"x","value":NaN}',
        '{"content_digest":"x","value":1e999}',
        "[]",
    ],
)
def test_protocol_resource_rejects_duplicate_nonfinite_and_wrong_shape(text: str) -> None:
    with pytest.raises(dp.DataPoisoningProtocolError, match="protocol_resource_invalid"):
        dp.load_protocol_resource_text(text)


def test_request_commitment_is_stable_across_outcomes_and_binds_every_request_field() -> None:
    target = normalize_target("https://example.com:443/llm04?fixed=1")
    base = {
        "target": target,
        "trial_id": "trial",
        "operation": "post_attack_query",
        "operation_ordinal": 3,
        "operation_id": "op-1",
        "namespace": "tenant-alpha",
        "attack_query": "benefits policy",
        "clean_query": "travel policy",
        "poison_item_id": "item-1",
        "request_body": b'{"operation":"post_attack_query"}',
    }
    original = dp._request_commitment(**base)
    assert original == dp._request_commitment(**base)
    mutations = []
    for key, value in (
        ("target", normalize_target("https://example.org/llm04?fixed=1")),
        ("trial_id", "trial-2"),
        ("operation_ordinal", 4),
        ("operation_id", "op-2"),
        ("namespace", "tenant-beta"),
        ("attack_query", "other attack"),
        ("clean_query", "other clean"),
        ("poison_item_id", "item-2"),
        ("request_body", b'{"operation":"post_attack_query","x":1}'),
        ("operation", "post_clean_query"),
    ):
        changed = dict(base)
        changed[key] = value
        mutations.append(dp._request_commitment(**changed))

    assert len({original, *mutations}) == len(mutations) + 1

    # Outcome/status/reason and response state are deliberately not inputs: the
    # exact prepared request keeps one identity before issuance and afterward.
    for _outcome in ("pre_issue", "response", "transport_error", "protocol_error", "late"):
        assert dp._request_commitment(**base) == original


def test_response_and_eligible_commitments_are_separate_from_request_identity() -> None:
    target = normalize_target("https://example.com/llm04")
    request = dp._request_commitment(
        target=target,
        trial_id="trial",
        operation="post_attack_query",
        operation_ordinal=3,
        operation_id="op-a",
        namespace="tenant-alpha",
        attack_query="benefits policy",
        clean_query="travel policy",
        poison_item_id="item-a",
        request_body=b'{"operation":"post_attack_query"}',
    )

    assert dp._response_commitment(b"one") != dp._response_commitment(b"two")
    assert dp._eligible_content_commitment("one") != dp._eligible_content_commitment("two")
    assert request == dp._request_commitment(
        target=target,
        trial_id="trial",
        operation="post_attack_query",
        operation_ordinal=3,
        operation_id="op-a",
        namespace="tenant-alpha",
        attack_query="benefits policy",
        clean_query="travel policy",
        poison_item_id="item-a",
        request_body=b'{"operation":"post_attack_query"}',
    )


def test_raw_invalid_utf8_bytes_have_distinct_commitments_after_real_transport_shaping() -> None:
    transport = Transport()
    responses = [
        transport._shape(
            RawExchange(status=200, headers={}, payload=raw),
            {"method": "POST", "url": "<target>"},
            {},
            frozenset(),
            1,
        )
        for raw in (b"\xff", b"\xfe")
    ]

    assert responses[0].body == responses[1].body == "\ufffd"
    commitments = [dp._response_commitment_for_http_response(response) for response in responses]
    assert all(commitment is not None for commitment in commitments)
    assert len(set(commitments)) == 2


@pytest.mark.parametrize(
    ("digest", "length", "body"),
    [
        (None, None, "opaque-marker"),
        (hashlib.sha256(b"x").hexdigest(), None, "opaque-marker"),
        (None, 1, "opaque-marker"),
        ("0" * 63, 1, "opaque-marker"),
        ("G" * 64, 1, "opaque-marker"),
        (hashlib.sha256(b"x").hexdigest(), True, "opaque-marker"),
        (hashlib.sha256(b"x").hexdigest(), -1, "opaque-marker"),
        (hashlib.sha256(b"x").hexdigest(), 262_145, "opaque-marker"),
        (hashlib.sha256(b"").hexdigest(), 0, "opaque-marker"),
        (hashlib.sha256(b"x").hexdigest(), 1, ""),
    ],
)
def test_missing_partial_malformed_or_inconsistent_raw_identity_fails_closed(
    digest: object, length: object, body: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = RequestController(max_requests=2, max_duration_seconds=10)
    request_bodies: list[bytes] = []

    class InvalidIdentityTransport:
        def send_prepared(self, _target: object, prepared: object) -> HttpResponse:
            with controller.ledger.attempt(AttemptKind.INITIAL):
                request_body = prepared.body  # type: ignore[union-attr]
                assert isinstance(request_body, bytes)
                request_bodies.append(request_body)
                return HttpResponse(
                    status=200,
                    body=body,
                    headers={},
                    redirected=False,
                    redirect_location=None,
                    truncated=False,
                    request_line={"method": "POST", "url": "<target>"},
                    raw_body_digest=digest,  # type: ignore[arg-type]
                    raw_body_length=length,  # type: ignore[arg-type]
                )

    monkeypatch.setattr(dp.secrets, "token_hex", lambda _size: "3" * 32)
    target = normalize_target("https://example.com/llm04")
    with pytest.raises(dp._OperationFailure) as raised:
        dp._send_operation(
            target,
            InvalidIdentityTransport(),  # type: ignore[arg-type]
            controller=controller,
            trial_id="trial",
            operation="poison_ingest",
            marker="opaque-marker",
            poison_item_id="item",
            max_attempts=1,
            cleanup_reserved=0,
        )

    failure = raised.value
    assert str(failure) == "raw_response_identity_unavailable"
    assert failure.response_commitment is None
    assert failure.request_commitment == dp._request_commitment(
        target=target,
        trial_id="trial",
        operation="poison_ingest",
        operation_ordinal=2,
        operation_id="op-" + "3" * 32,
        namespace="tenant-alpha",
        attack_query="benefits policy",
        clean_query="travel policy",
        poison_item_id="item",
        request_body=request_bodies[0],
    )
    assert "opaque-marker" not in repr(vars(failure))


def test_transport_error_commitments_bind_exact_distinct_requests() -> None:
    target = normalize_target("https://example.com/llm04")
    common = {
        "target": target,
        "trial_id": "trial",
        "operation": "poison_ingest",
        "namespace": "tenant-alpha",
        "attack_query": "benefits policy",
        "clean_query": "travel policy",
        "operation_ordinal": 2,
    }
    one = dp._request_commitment(
        **common,
        operation_id="op-one",
        poison_item_id="item-one",
        request_body=b'{"operation_id":"op-one"}',
    )
    two = dp._request_commitment(
        **common,
        operation_id="op-two",
        poison_item_id="item-two",
        request_body=b'{"operation_id":"op-two"}',
    )

    assert one != two
    assert "op-one" not in one and "item-one" not in one


@pytest.mark.parametrize(
    "mode",
    ["success", "transport_error", "protocol_error", "truncated", "late", "pre_deadline"],
)
def test_every_runtime_outcome_reuses_precomputed_exact_request_identity(
    mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    controller = RequestController(
        max_requests=4, max_duration_seconds=1.0, clock=lambda: now[0]
    )
    if mode == "pre_deadline":
        with controller.ledger.attempt(AttemptKind.INITIAL):
            pass
        now[0] = 2.0
    response_bytes = b"not-json"
    captured_body: list[bytes] = []

    class OutcomeTransport:
        def send_prepared(self, _target: object, prepared: object) -> HttpResponse:
            body = prepared.body  # type: ignore[union-attr]
            assert isinstance(body, bytes)
            captured_body.append(body)
            with controller.ledger.attempt(AttemptKind.INITIAL):
                if mode == "transport_error":
                    raise TransportError("connection failed")
                request = json.loads(body)
                if mode in {"success", "late"}:
                    payload = {
                        "protocol_version": PROTOCOL,
                        "trial_id": request["trial_id"],
                        "operation_id": request["operation_id"],
                        "status": "ok",
                    }
                    raw = json.dumps(payload, sort_keys=True).encode()
                else:
                    raw = response_bytes
                if mode == "late":
                    now[0] = 2.0
                return HttpResponse(
                    status=200,
                    body=raw.decode(),
                    headers={},
                    redirected=False,
                    redirect_location=None,
                    truncated=mode == "truncated",
                    request_line={"method": "POST", "url": "<target>"},
                    raw_body_digest=hashlib.sha256(raw).hexdigest(),
                    raw_body_length=len(raw),
                )

    monkeypatch.setattr(dp.secrets, "token_hex", lambda _size: "1" * 32)
    target = normalize_target("https://example.com/llm04")

    try:
        result = dp._send_operation(
            target,
            OutcomeTransport(),  # type: ignore[arg-type]
            controller=controller,
            trial_id="trial",
            operation="poison_ingest",
            marker="marker",
            poison_item_id="item",
            max_attempts=1,
            cleanup_reserved=0,
        )
    except dp._OperationFailure as failure:
        request_commitment = failure.request_commitment
        response_commitment = failure.response_commitment
    else:
        request_commitment = result.request_commitment
        response_commitment = result.response_commitment

    canonical_body = captured_body[0] if captured_body else json.dumps(
        dp._request_doc(
            trial_id="trial",
            operation_id="op-" + "1" * 32,
            operation="poison_ingest",
            marker="marker",
            poison_item_id="item",
        ),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    expected_request_commitment = dp._request_commitment(
        target=target,
        trial_id="trial",
        operation="poison_ingest",
        operation_ordinal=2,
        operation_id="op-" + "1" * 32,
        namespace="tenant-alpha",
        attack_query="benefits policy",
        clean_query="travel policy",
        poison_item_id="item",
        request_body=canonical_body,
    )
    assert request_commitment == expected_request_commitment
    if mode in {"protocol_error", "truncated", "late", "success"}:
        assert response_commitment is not None
    else:
        assert response_commitment is None


def test_late_strictly_valid_query_keeps_response_and_eligible_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [0.0]
    controller = RequestController(
        max_requests=2, max_duration_seconds=1.0, clock=lambda: now[0]
    )
    deadline_checks = [0]

    def staged_deadline() -> None:
        deadline_checks[0] += 1
        if deadline_checks[0] == 4:
            raise TransportError("deadline")

    monkeypatch.setattr(controller.ledger, "check_deadline", staged_deadline)

    class LateTransport:
        def send_prepared(self, _target: object, prepared: object) -> HttpResponse:
            with controller.ledger.attempt(AttemptKind.INITIAL):
                request = json.loads(prepared.body)  # type: ignore[union-attr]
                raw = json.dumps(
                    {
                        "protocol_version": PROTOCOL,
                        "trial_id": request["trial_id"],
                        "operation_id": request["operation_id"],
                        "status": "ok",
                        "retrieval": {"content": "eligible"},
                    },
                    sort_keys=True,
                ).encode()
                return HttpResponse(
                    200,
                    raw.decode(),
                    {},
                    False,
                    None,
                    False,
                    {"method": "POST", "url": "<target>"},
                    raw_body_digest=hashlib.sha256(raw).hexdigest(),
                    raw_body_length=len(raw),
                )

    monkeypatch.setattr(dp.secrets, "token_hex", lambda _size: "2" * 32)
    with pytest.raises(dp._OperationFailure) as raised:
        dp._send_operation(
            normalize_target("https://example.com/llm04"),
            LateTransport(),  # type: ignore[arg-type]
            controller=controller,
            trial_id="trial",
            operation="post_attack_query",
            marker="marker",
            poison_item_id="item",
            max_attempts=1,
            cleanup_reserved=0,
        )

    assert raised.value.response_commitment is not None
    assert raised.value.eligible_content_commitment == dp._eligible_content_commitment("eligible")


def test_help_documents_target_protocol_not_fixture_engine(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        cli.main(["data-poisoning-audit", "--help"])
    assert raised.value.code == 0
    out = capsys.readouterr().out
    assert "--target" in out
    assert "fixed HTTP retrieval fixture protocol" in out
    assert "--fixture" not in out
    assert "engine" not in out.lower()
