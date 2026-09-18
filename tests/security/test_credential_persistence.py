"""Phase 1A credential-persistence regressions (Astra H4).

Real transport-to-persistence coverage converted from the reviewer's
``/tmp/ai_scan_redaction_review.py``. A credential supplied to the target must
never survive into a persisted report — in any representation:

* a ``Cookie`` component value reflected in the body,
* a JSON-``\\u``-escaped reflection,
* a response *header name* built from the secret,
* a duplicate-key structured request template (rejected before transport).

Negative controls prove ordinary Bearer redaction still works and that a valid
single-key JSON template is accepted.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ai_scan.adapters import GenericHttpAdapter
from ai_scan.reporting import Report, write_report_atomic
from ai_scan.targets import normalize_target
from ai_scan.transport import RequestController, Transport, TransportConfig
from ai_scan.transport.redaction import (
    REDACTED,
    scrub_structure,
    scrub_text,
    sensitive_header_values,
)

SECRET = "OpaqueReviewCredential7"  # pragma: allowlist secret  (dummy test value)
_SURR_SECRET = "opaque🔑token"  # pragma: allowlist secret  (non-BMP / surrogate pair)


class _Reflector(BaseHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        mode = self.path.strip("/")
        text = SECRET
        if mode == "escaped":
            text = json.dumps({"answer": SECRET}).replace("O", "\\u004f")
        elif mode == "surrogate":
            text = json.dumps({"answer": _SURR_SECRET})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if mode == "key":
            self.send_header("X-" + SECRET, "benign")
        self.end_headers()
        self.wfile.write(text.encode())


@pytest.fixture
def reflector() -> Iterator[ThreadingHTTPServer]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Reflector)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()


def _persist_and_read(
    srv: ThreadingHTTPServer, mode: str, headers: dict[str, str], body: str, tmp: Path
) -> str:
    target = normalize_target(f"http://127.0.0.1:{srv.server_port}/{mode}")
    adapter = GenericHttpAdapter(target=target, extra_headers=headers, body_template=body)
    transport = Transport(TransportConfig(), controller=RequestController(max_requests=2))
    resp = transport.send_prepared(target, adapter.build_request("hello"))
    report = Report.build(
        target=target,
        fingerprint=None,
        injection=None,
        request_budget={},
        evidence=[resp.evidence()],
    )
    out = tmp / f"{mode}.json"
    write_report_atomic(report, str(out), known_secrets=resp.known_secrets)
    return out.read_text(encoding="utf-8")


def test_plain_bearer_reflection_is_redacted(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    dumped = _persist_and_read(
        reflector, "plain", {"Authorization": "Bearer " + SECRET}, '{"input":"*"}', tmp_path
    )
    assert SECRET not in dumped


def test_cookie_component_reflection_does_not_persist(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    dumped = _persist_and_read(
        reflector, "cookie", {"Cookie": "session=" + SECRET}, '{"input":"*"}', tmp_path
    )
    assert SECRET not in dumped


def test_json_escaped_reflection_does_not_persist(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    dumped = _persist_and_read(
        reflector, "escaped", {"Authorization": "Bearer " + SECRET}, '{"input":"*"}', tmp_path
    )
    # Neither the raw spelling nor the JSON-decoded reconstruction may survive.
    doc = json.loads(dumped)
    body = doc["evidence"][0]["response"]["body"]
    assert SECRET not in dumped
    try:
        assert SECRET not in json.dumps(json.loads(body))
    except (ValueError, TypeError):
        pass  # a fully-redacted body is not valid JSON, which is fine


def test_secret_bearing_response_header_name_does_not_persist(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    dumped = _persist_and_read(
        reflector, "key", {"Authorization": "Bearer " + SECRET}, '{"input":"*"}', tmp_path
    )
    assert SECRET not in dumped


# --- duplicate-key structured template is rejected before transport -----------


def test_duplicate_key_template_rejected_before_transport(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    from ai_scan.cli import main

    template = tmp_path / "dup-template.json"
    template.write_text(
        '{"password":"' + SECRET + '","password":"harmlessLastValue","input":"*"}'
    )
    report = tmp_path / "dup-report.json"
    rc = main(
        [
            "fingerprint",
            "--target",
            f"http://127.0.0.1:{reflector.server_port}/duplicate",
            "--request-template",
            str(template),
            "--out",
            str(report),
        ]
    )
    assert rc != 0  # rejected before any transport is constructed
    if report.exists():
        assert SECRET not in report.read_text(encoding="utf-8")


def test_transport_send_rejects_duplicate_key_template_without_io() -> None:
    from ai_scan.transport import TransportError
    from ai_scan.transport.http import Transport, TransportConfig

    hits: list[int] = []

    class _Counter(BaseHTTPRequestHandler):
        def log_message(self, *_a: object) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            hits.append(1)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Counter)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        target = normalize_target(f"http://127.0.0.1:{srv.server_port}/")
        transport = Transport(TransportConfig(max_retries=0))
        with pytest.raises(TransportError):
            transport.send(
                target,
                method="POST",
                prompt="x",
                body_template=(
                    '{"password":"first-secret",'  # pragma: allowlist secret
                    '"password":"last","input":"*"}'
                ),
                prompt_encoding="raw",
            )
        # Rejected before any request/broker construction — zero socket I/O.
        assert hits == []
        # Raw mode stays explicit: a non-JSON template with repeated tokens is
        # sent verbatim (one hit).
        assert (
            transport.send(
                target,
                method="POST",
                prompt="x",
                body_template="user=*&dup=1&dup=2",
                prompt_encoding="raw",
            ).status
            == 200
        )
        assert hits == [1]
    finally:
        srv.shutdown()
        srv.server_close()


def test_valid_single_key_template_is_accepted(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    from ai_scan.cli import main

    template = tmp_path / "ok-template.json"
    template.write_text('{"input":"*"}')
    report = tmp_path / "ok-report.json"
    rc = main(
        [
            "fingerprint",
            "--target",
            f"http://127.0.0.1:{reflector.server_port}/plain",
            "--request-template",
            str(template),
            "--out",
            str(report),
        ]
    )
    assert rc == 0
    assert report.exists()


# --- focused redaction-helper units (precise failure localization) ------------


def test_cookie_component_value_is_collected() -> None:
    values = sensitive_header_values({"Cookie": "session=" + SECRET})
    assert SECRET in values


def test_secret_bearing_mapping_key_is_scrubbed() -> None:
    scrubbed = scrub_structure({SECRET: "benign"}, frozenset({SECRET}))
    assert SECRET not in json.dumps(scrubbed)


@pytest.mark.parametrize(
    "secret",
    [
        SECRET,
        'Opaque"ReviewCredential7',  # pragma: allowlist secret  (quote-embedded)
        "Opaque\\ReviewCredential7",  # pragma: allowlist secret  (backslash)
    ],
)
def test_json_escaped_secret_redacted_inside_valid_json(secret: str) -> None:
    # A secret spelled with ANY JSON string escape must be redacted, and the
    # result must remain valid JSON (never re-decode to the secret).
    body = json.dumps({"answer": secret})
    result = scrub_text(body, frozenset({secret}))
    assert secret not in json.dumps(json.loads(result))


def test_unicode_escaped_secret_redacted_inside_valid_json() -> None:
    body = json.dumps({"answer": SECRET}).replace("O", "\\u004f")
    result = scrub_text(body, frozenset({SECRET}))
    assert SECRET not in json.dumps(json.loads(result))


def test_mixed_raw_and_escaped_non_json_fails_closed() -> None:
    # When the surrounding text is not a JSON document, a mixed raw+escaped
    # occurrence falls back to whole-string redaction (fail closed, no leak).
    escaped = json.dumps({"a": SECRET}).replace("O", "\\u004f")
    mixed = f"raw={SECRET} and {escaped}"
    result = scrub_text(mixed, frozenset({SECRET}))
    assert result == REDACTED


# --- report / checkpoint / bundle runtime regressions (escaped secret) --------

_ESCAPED_CANARY = "AISCAN-ESCAPED01"


def _run_with_escaped_secret(tmp_path: Path, checkpoint: bool):  # type: ignore[no-untyped-def]
    from ai_scan.injection import ExchangeOutcome
    from ai_scan.orchestration import compile_plan
    from tests.trusted_engines import run_plan

    plan = compile_plan(normalize_target("http://127.0.0.1:8080/chat"), "reliable")
    escaped_body = json.dumps({"answer": SECRET, "canary": _ESCAPED_CANARY}).replace(
        "O", "\\u004f"
    )

    def responder(case):  # type: ignore[no-untyped-def]
        return ExchangeOutcome(body=escaped_body, known_secrets=frozenset({SECRET}))

    kwargs: dict[str, object] = {"canary": _ESCAPED_CANARY, "goal": "g"}
    if checkpoint:
        kwargs["checkpoint_path"] = str(tmp_path / "cp.json")
    from ai_scan.evidence_graph import BundleCollector

    collector = BundleCollector()
    result = run_plan(plan, responder, observer=collector.observe, **kwargs)  # type: ignore[arg-type]
    return plan, collector, result


def test_checkpoint_does_not_persist_json_escaped_secret(tmp_path: Path) -> None:
    _run_with_escaped_secret(tmp_path, checkpoint=True)
    cp = (tmp_path / "cp.json").read_text(encoding="utf-8")
    assert SECRET not in cp


def test_bundle_export_does_not_persist_json_escaped_secret(tmp_path: Path) -> None:
    from ai_scan.evidence_graph import dump_bundle

    plan, collector, result = _run_with_escaped_secret(tmp_path, checkpoint=False)
    bundle = collector.build(
        plan=plan, canary=_ESCAPED_CANARY, run_id="run-1", coverage_gaps=result.coverage_gaps
    )
    assert SECRET not in dump_bundle(bundle)


# --- blocker 1 (final): surrogate pairs, nested/multiply-escaped, all bounded --

def _escape_variants(secret: str) -> list[str]:
    """A JSON body spelling ``secret`` in several escaped representations."""
    base = json.dumps({"answer": secret})
    unicode_escaped = json.dumps({"answer": secret}).encode("ascii", "backslashreplace").decode()
    o_escaped = base.replace("o", "\\u006f").replace("O", "\\u004f")
    nested = json.dumps({"payload": base})  # inner is a JSON *string* value
    double_nested = json.dumps({"outer": nested})
    return [base, unicode_escaped, o_escaped, nested, double_nested]


@pytest.mark.parametrize(
    "secret",
    [SECRET, _SURR_SECRET, 'Opaque"ReviewCredential7'],  # pragma: allowlist secret
)
def test_secret_never_recoverable_through_escape_representations(secret: str) -> None:
    for body in _escape_variants(secret):
        scrubbed = scrub_text(body, frozenset({secret}))
        # Not recoverable at any nesting after parsing, and still valid JSON.
        parsed = json.loads(scrubbed)
        assert secret not in json.dumps(parsed)
        # Recurse into any nested JSON-string values too.
        stack = [parsed]
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                try:
                    stack.append(json.loads(node))
                except (ValueError, TypeError):
                    assert secret not in node
            elif isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)


def test_scrub_is_bounded_on_deeply_nested_escaped_json() -> None:
    # Encode every character before nesting so the raw secret is absent until
    # more layers than the semantic cap have been decoded.
    encoded = "".join(f"\\u{ord(ch):04x}" for ch in SECRET)
    payload = json.dumps({"n": encoded})
    for _ in range(9):
        payload = json.dumps({"n": payload})
    assert len(payload) < 1_000_000
    assert SECRET not in payload
    out = scrub_text(payload, frozenset({SECRET}))
    assert out == REDACTED


def test_scrub_fails_closed_on_oversized_json_text() -> None:
    payload = json.dumps({"answer": "x" * 1_048_576})
    assert scrub_text(payload, frozenset({SECRET})) == "REDACTED"


def test_surrogate_secret_does_not_persist_in_report(
    reflector: ThreadingHTTPServer, tmp_path: Path
) -> None:
    # End-to-end: the server reflects the surrogate secret; it must not persist.
    dumped = _persist_and_read(
        reflector,
        "surrogate",
        {},
        json.dumps({"api_key": _SURR_SECRET, "input": "*"}),
        tmp_path,
    )
    assert _SURR_SECRET not in dumped


def test_benign_json_body_is_unchanged_positive_control() -> None:
    body = json.dumps({"answer": "hello world", "n": 5, "ok": True})
    assert scrub_text(body, frozenset({SECRET})) == body


# --- blocker 2 (final): order-independent, no-drop key disambiguation ----------


@pytest.mark.parametrize("reverse", [False, True])
def test_scrubbed_key_collision_is_order_independent_and_lossless(reverse: bool) -> None:
    sec = SECRET
    items = [("X-" + sec, "first"), ("X-REDACTED", "second")]
    if reverse:
        items = list(reversed(items))
    out = scrub_structure(dict(items), frozenset({sec}))
    assert len(out) == 2  # nothing dropped
    assert sorted(out.values()) == ["first", "second"]
    assert sec not in json.dumps(out)


def test_scrubbed_key_map_is_deterministic_across_orders() -> None:
    from ai_scan.transport.redaction import scrubbed_key_map

    sec = SECRET
    keys = ["X-" + sec, "X-REDACTED", "Y-" + sec]
    a = scrubbed_key_map(keys, frozenset({sec}))
    b = scrubbed_key_map(list(reversed(keys)), frozenset({sec}))
    assert a == b  # same mapping regardless of order
    assert len(set(a.values())) == len(keys)  # injective — no collisions


def test_scrubbed_key_second_order_collision_is_lossless_and_deterministic() -> None:
    secret_key = "X-" + SECRET
    items = [
        (secret_key, "secret-key-entry"),
        ("X-REDACTED", "ordinary-collider"),
        ("X-REDACTED#374ede3d", "preexisting-suffix"),
    ]
    forward = scrub_structure(dict(items), frozenset({SECRET}))
    reverse = scrub_structure(dict(reversed(items)), frozenset({SECRET}))
    assert forward == reverse
    assert len(forward) == len(items)
    assert set(forward.values()) == {value for _, value in items}


def test_scrubbed_key_hash_collision_is_lossless() -> None:
    # These distinct keys share the current bounded disambiguator; injectivity
    # must not rely on hash uniqueness.
    first = "opaque-review-021502"
    second = "opaque-review-022440"
    out = scrub_structure(
        {first: "first", second: "second"}, frozenset({first, second})
    )
    assert len(out) == 2
    assert set(out.values()) == {"first", "second"}


def test_non_colliding_scrubbed_key_keeps_clean_name_positive_control() -> None:
    out = scrub_structure({"X-" + SECRET: "v"}, frozenset({SECRET}))
    assert list(out) == ["X-REDACTED"]  # no needless disambiguation suffix
