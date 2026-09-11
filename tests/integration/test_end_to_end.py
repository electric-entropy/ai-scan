"""End-to-end tests against local in-process HTTP targets.

Each server models a distinct application behavior. These exercise the real
urllib transport, the authorization gate, the engines, and reporting together —
all on loopback only.
"""

from __future__ import annotations

import json
import re

from ai_scan import cli
from ai_scan.authorization import Receipt, write_receipt
from ai_scan.fingerprint import DEFAULT_PROBES, ProbeExchange, run_fingerprint
from ai_scan.injection import ExchangeOutcome, generate_canary, load_payloads, run_injection
from ai_scan.targets import normalize_target
from ai_scan.transport import MARKER, Transport, TransportConfig
from tests.conftest import MockRequest, MockResponse

# --- application behaviors ---------------------------------------------------


def _resistant_app(req: MockRequest) -> MockResponse:
    return MockResponse(
        status=200,
        body=json.dumps({"reply": "I can't help with that."}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _vulnerable_app(req: MockRequest) -> MockResponse:
    # Simulates a model that FOLLOWS the injected instruction: it emits only the
    # canary token it was told to output (not a copy of the whole prompt).
    payload = json.loads(req.body or b"{}")
    prompt = payload.get("input", "")
    match = re.search(r"AISCAN-[0-9A-F]+", prompt)
    token = match.group(0) if match else "ok"
    return MockResponse(
        status=200,
        body=json.dumps({"reply": token}).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Model-Name": "gpt-4o"},
    )


def _echo_app(req: MockRequest) -> MockResponse:
    # Resistant to injection but reflective: echoes the whole prompt verbatim.
    payload = json.loads(req.body or b"{}")
    prompt = payload.get("input", "")
    return MockResponse(
        status=200,
        body=json.dumps({"reply": f"You said: {prompt}"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _outcome_responder(transport, target):
    def respond(case):
        resp = transport.send(
            target, method="POST", prompt=case.rendered_prompt, body_template='{"input": "*"}'
        )
        return ExchangeOutcome(
            body=resp.body,
            status=resp.status,
            redirected=resp.redirected,
            truncated=resp.truncated,
            attempts=resp.attempts,
        )

    return respond


def _redirecting_app(req: MockRequest) -> MockResponse:
    return MockResponse(
        status=302,
        body=b"",
        headers={"Location": "http://evil.example.com/collect"},
    )


def _oversized_app(req: MockRequest) -> MockResponse:
    return MockResponse(status=200, body=b"Z" * 50_000)


def _strict_json_app_factory(bad_counter: dict[str, int]):
    """A target that requires a valid JSON body; records any parse failure."""

    def app(req: MockRequest) -> MockResponse:
        try:
            payload = json.loads(req.body or b"{}")
        except json.JSONDecodeError:
            bad_counter["bad"] += 1
            return MockResponse(
                status=400,
                body=json.dumps({"error": "invalid json"}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
        prompt = payload.get("input", "")
        return MockResponse(
            status=200,
            body=json.dumps({"reply": f"echo: {prompt}"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    return app


# --- tests -------------------------------------------------------------------


def test_resistant_app_yields_no_confirmed_finding(mock_server) -> None:
    server = mock_server(_resistant_app)
    target = normalize_target(f"{server.base_url}/chat")
    transport = Transport(TransportConfig())
    canary = generate_canary()
    result = run_injection(
        load_payloads("safe"), _outcome_responder(transport, target), canary=canary, goal="g"
    )
    assert result.status.value in ("not_observed", "potential")


def test_vulnerable_app_confirms_via_canary(mock_server) -> None:
    server = mock_server(_vulnerable_app)
    target = normalize_target(f"{server.base_url}/chat")
    transport = Transport(TransportConfig())
    canary = generate_canary()
    result = run_injection(
        load_payloads("safe"), _outcome_responder(transport, target), canary=canary, goal="g"
    )
    assert result.status.value == "confirmed"
    assert any(canary in (f.proof or "") for f in result.findings)


def test_echo_app_is_not_confirmed_regression(mock_server) -> None:
    # Finding 5 regression: a target that merely reflects the prompt (canary and
    # all) must NOT be reported as a confirmed prompt injection.
    server = mock_server(_echo_app)
    target = normalize_target(f"{server.base_url}/chat")
    transport = Transport(TransportConfig())
    canary = generate_canary()
    result = run_injection(
        load_payloads("safe"), _outcome_responder(transport, target), canary=canary, goal="g"
    )
    assert result.status.value != "confirmed"
    assert all(f.status.value != "confirmed" for f in result.findings)


def test_redirect_is_blocked_and_captured(mock_server) -> None:
    server = mock_server(_redirecting_app)
    target = normalize_target(f"{server.base_url}/chat")
    transport = Transport(TransportConfig())
    resp = transport.send(target, method="POST", prompt="x", body_template=MARKER)
    assert resp.redirected is True
    assert resp.redirect_location == "http://evil.example.com/collect"
    # Evidence never contains the followed content; scope escape blocked.
    assert resp.status == 302


def test_oversized_response_is_bounded(mock_server) -> None:
    server = mock_server(_oversized_app)
    target = normalize_target(f"{server.base_url}/chat")
    transport = Transport(TransportConfig(max_response_bytes=2048))
    resp = transport.send(target, method="POST", prompt="x", body_template=MARKER)
    assert resp.truncated is True
    assert len(resp.body.encode("utf-8")) <= 2048


def test_fingerprint_reads_model_header_from_live_target(mock_server) -> None:
    server = mock_server(_vulnerable_app)
    target = normalize_target(f"{server.base_url}/chat")
    transport = Transport(TransportConfig())

    def probe_responder(probe) -> ProbeExchange:
        resp = transport.send(
            target, method="POST", prompt=probe.prompt, body_template='{"input": "*"}'
        )
        return ProbeExchange(probe.id, resp.body, resp.headers)

    result = run_fingerprint(DEFAULT_PROBES, probe_responder)
    assert any(
        e.kind == "header" for c in result.candidates for e in c.evidence
    )


def test_cli_non_interactive_requires_receipt_before_network(mock_server) -> None:
    # No receipt + --non-interactive must exit 2 without touching the server.
    hits = {"n": 0}

    def counting_app(req: MockRequest) -> MockResponse:
        hits["n"] += 1
        return _resistant_app(req)

    server = mock_server(counting_app)
    rc = cli.main(
        ["inject", "--target", f"{server.base_url}/chat", "--goal", "g", "--non-interactive"],
        prompt=lambda _m: (_ for _ in ()).throw(AssertionError("must not prompt")),
    )
    assert rc == cli.EXIT_AUTH_DENIED
    assert hits["n"] == 0


def test_cli_assess_with_receipt_runs_headless_and_reports(mock_server, tmp_path) -> None:
    server = mock_server(_vulnerable_app)
    target_url = f"{server.base_url}/chat"
    target = normalize_target(target_url)

    receipt_path = tmp_path / "auth.json"
    receipt = Receipt.create(
        target=target, client="Acme", engagement="ENG-42", expires="2999-01-01"
    )
    write_receipt(receipt, str(receipt_path))

    out = tmp_path / "report.json"
    rc = cli.main(
        [
            "assess",
            "--target",
            target_url,
            "--auth-receipt",
            str(receipt_path),
            "--non-interactive",
            "--out",
            str(out),
        ],
    )
    # Vulnerable app reflects the canary → confirmed → exit 3.
    assert rc == cli.EXIT_CONFIRMED_FINDING
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["target_origin"] == target.origin
    assert report["authorization"]["mode"] == "receipt"
    assert report["injection"]["status"] == "confirmed"
    # No confirmation phrase or secrets leaked into the report.
    assert "I confirm I am authorized" not in json.dumps(report)
    # Finding 7: budget is reported from the enforced physical counter.
    budget = report["request_budget"]
    assert budget["used"] >= 1
    assert budget["used"] <= budget["max_requests"]


def _write_receipt(tmp_path, target):
    from ai_scan.authorization import Receipt, write_receipt

    receipt_path = tmp_path / "auth.json"
    write_receipt(
        Receipt.create(
            target=target, client="Acme", engagement="ENG-1", expires="2999-01-01"
        ),
        str(receipt_path),
    )
    return receipt_path


def test_cli_inject_sends_only_parseable_json_to_strict_target(mock_server, tmp_path) -> None:
    bad = {"bad": 0}
    server = mock_server(_strict_json_app_factory(bad))
    target_url = f"{server.base_url}/chat"
    target = normalize_target(target_url)
    receipt_path = _write_receipt(tmp_path, target)

    rc = cli.main(
        [
            "inject",
            "--target",
            target_url,
            "--goal",
            "canary",
            "--auth-receipt",
            str(receipt_path),
            "--non-interactive",
        ],
    )
    # Every default payload must have been accepted as valid JSON.
    assert bad["bad"] == 0
    assert rc in (cli.EXIT_OK, cli.EXIT_CONFIRMED_FINDING, cli.EXIT_INCONCLUSIVE)


def test_cli_assess_sends_only_parseable_json_to_strict_target(mock_server, tmp_path) -> None:
    bad = {"bad": 0}
    server = mock_server(_strict_json_app_factory(bad))
    target_url = f"{server.base_url}/chat"
    target = normalize_target(target_url)
    receipt_path = _write_receipt(tmp_path, target)

    rc = cli.main(
        [
            "assess",
            "--target",
            target_url,
            "--auth-receipt",
            str(receipt_path),
            "--non-interactive",
        ],
    )
    assert bad["bad"] == 0
    assert rc in (cli.EXIT_OK, cli.EXIT_CONFIRMED_FINDING, cli.EXIT_INCONCLUSIVE)


def test_raw_template_preserves_literal_marker_substitution(mock_server) -> None:
    # With prompt_encoding="raw", the prompt is inserted verbatim (no escaping),
    # preserving Burp-style/raw template behavior when explicitly requested.
    captured: dict[str, str] = {}

    def app(req: MockRequest) -> MockResponse:
        captured["body"] = req.text
        return MockResponse(status=200, body=b"ok")

    server = mock_server(app)
    target = normalize_target(f"{server.base_url}/x")
    transport = Transport(TransportConfig())
    prompt = 'a"b\nc'
    resp = transport.send(
        target,
        method="POST",
        prompt=prompt,
        body_template="RAW-START|*|RAW-END",
        prompt_encoding="raw",
    )
    assert resp.status == 200
    # Verbatim: the exact prompt bytes appear, unescaped, at the marker.
    assert captured["body"] == f"RAW-START|{prompt}|RAW-END"
