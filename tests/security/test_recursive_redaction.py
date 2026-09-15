"""Milestone 3: adversarial coverage of the central recursive redaction boundary.

Table-driven / property-style tests over whole defect classes, not single
examples: sensitive field names, headers/cookies/query/URLs/redirect locations,
credential-format literals (incl. repeated percent-encoding and Unicode
surroundings), reflected known secrets, deep/mixed nesting, aliases, cycles,
non-string keys, unsupported types, canary preservation, a seeded-secret corpus,
and the exception path.
"""

from __future__ import annotations

import json
import secrets as _secrets
from urllib.parse import quote

import pytest

from ai_scan.targets import normalize_target
from ai_scan.transport import (
    RedactionError,
    Transport,
    TransportConfig,
    TransportError,
)
from ai_scan.transport.redaction import (
    REDACTED,
    redact_headers,
    redact_url,
    redact_value,
    scrub_text,
)

# Credential-format literals spanning the supported families.
SECRET_LITERALS = [
    "AKIA1234567890ABCDEF",  # pragma: allowlist secret
    "ASIA1234567890ABCDEF",  # pragma: allowlist secret
    "sk-abcdef0123456789XYZ",
    "ghp_abcdefghijklmnopqrstuvwxyz0123",  # pragma: allowlist secret
    "xoxb-abcdef-123456-ABCDEF",  # pragma: allowlist secret
    "-----BEGIN RSA PRIVATE KEY-----",  # pragma: allowlist secret
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
    "Bearer abcdef0123456789ABCDEF",
]

SENSITIVE_KEYS = [
    "authorization", "Authorization", "AUTHORIZATION",
    "cookie", "Set-Cookie", "api_key", "apiKey", "X-Api-Key",
    "token", "access_token", "refreshToken", "password", "passwd",
    "secret", "client_secret", "credential", "sessionId", "signature",
    "private_key",
]


# --- credential-format literals are redacted anywhere ------------------------


@pytest.mark.parametrize("secret", SECRET_LITERALS)
def test_secret_literal_scrubbed_in_string(secret: str) -> None:
    assert secret not in scrub_text(f"leak={secret};end")


@pytest.mark.parametrize("secret", SECRET_LITERALS)
def test_secret_literal_scrubbed_when_nested(secret: str) -> None:
    blob = {"a": [{"b": f"x {secret} y"}], "c": ("t", secret)}
    assert secret not in json.dumps(redact_value(blob))


@pytest.mark.parametrize("secret", SECRET_LITERALS)
def test_secret_literal_scrubbed_through_percent_encoding(secret: str) -> None:
    once = quote(secret, safe="")
    twice = quote(once, safe="")
    assert secret not in scrub_text(once)
    assert secret not in scrub_text(twice)


# --- sensitive field names redact their value regardless of content ----------


@pytest.mark.parametrize("key", SENSITIVE_KEYS)
def test_sensitive_field_value_redacted(key: str) -> None:
    out = redact_value({key: "whatever-value-1234567890"})
    assert out[key] == REDACTED


def test_non_sensitive_field_preserved() -> None:
    out = redact_value({"name": "benign", "count": 3, "flag": True, "note": None})
    assert out == {"name": "benign", "count": 3, "flag": True, "note": None}


# --- precision: benign token-like field names must be preserved --------------

BENIGN_KEYS = [
    "author", "authentication_method", "token_count", "session_notes",
    "accessibility", "monkey", "content_type", "user_agent", "note",
    "description", "count", "accessToken_count", "authors",
    # generic `key` suffix must NOT be treated as a credential
    "sort_key", "primary_key", "keyboard_key", "sortKey", "key", "partition_key",
]

CREDENTIAL_KEYS = [
    "authorization", "Authorization", "api_key", "apiKey", "X-Api-Key",
    "access_token", "refreshToken", "client_secret", "password", "passwd",
    "cookie", "Set-Cookie", "x-auth-token", "signature", "private_key",
    "session", "session_id", "sessionId", "X-Acme-Access-Token", "bearer",
    # credential-qualified `*_key` must be redacted
    "access_key", "secret_key", "signing_key", "encryption_key", "apiKey",
    "client_key", "sshKey", "consumer_key",
]


@pytest.mark.parametrize("key", BENIGN_KEYS)
def test_benign_field_preserved(key: str) -> None:
    out = redact_value({key: "ordinary-value-123"})
    assert out[key] == "ordinary-value-123", f"{key} wrongly redacted"


@pytest.mark.parametrize("key", CREDENTIAL_KEYS)
def test_credential_field_redacted(key: str) -> None:
    out = redact_value({key: "ordinary-value-123"})
    assert out[key] == REDACTED, f"{key} not redacted"


# --- headers / cookies -------------------------------------------------------


@pytest.mark.parametrize("header", ["Authorization", "cookie", "X-Api-Key", "X-Session-Token"])
def test_header_value_redacted(header: str) -> None:
    assert redact_headers({header: "sensitive", "Accept": "application/json"})[header] == REDACTED


def test_non_sensitive_header_preserved() -> None:
    assert redact_headers({"Accept": "application/json"})["Accept"] == "application/json"


# --- URLs / redirect locations ------------------------------------------------


def test_url_userinfo_stripped() -> None:
    url = "https://user:pass@api.example.com/x?a=1"  # pragma: allowlist secret
    assert "user:pass" not in redact_url(url)


@pytest.mark.parametrize("param", ["token", "api_key", "access_token", "sig", "session"])
def test_secret_query_param_redacted(param: str) -> None:
    redacted = redact_url(f"https://api.example.com/x?{param}=SUPERSECRETVALUE&q=keep")
    assert "SUPERSECRETVALUE" not in redacted
    assert "q=keep" in redacted


@pytest.mark.parametrize(
    "encoded_key",
    ["%74oken", "%2574oken", "ap%69_key", "authoriz%61tion"],
)
def test_encoded_sensitive_query_key_redacted(encoded_key: str) -> None:
    # Encoded (and twice-encoded) sensitive keys must still be classified.
    redacted = redact_url(f"https://api.example.com/x?{encoded_key}=SUPERSECRETVALUE")
    assert "SUPERSECRETVALUE" not in redacted


def test_url_secret_values_collects_encoded_and_userinfo() -> None:
    from ai_scan.transport.redaction import url_secret_values

    url = "https://u:PASSWORDSECRET@api.example.com/x?%74oken=TOKSECRET"  # pragma: allowlist secret
    vals = url_secret_values(url)
    assert "PASSWORDSECRET" in vals
    assert "TOKSECRET" in vals


def _over_encode(seed: str, layers: int) -> str:
    # Seed contains an encodable char so each quote() genuinely adds a layer.
    value = seed
    for _ in range(layers):
        value = quote(value, safe="")
    return value


@pytest.mark.parametrize("layers", [65, 80])
def test_over_encoded_url_component_fails_closed(layers: int) -> None:
    over = _over_encode("a b", layers)
    assert redact_url(f"https://api.example.com/x?{over}=v") == REDACTED
    assert redact_url(f"https://api.example.com/x?k={over}") == REDACTED


def test_over_encoded_path_fails_closed() -> None:
    over = _over_encode("a b", 80)
    assert redact_url(f"https://api.example.com/seg{over}") == REDACTED


# --- URL-bearing fields are redacted recursively -----------------------------


@pytest.mark.parametrize("key", ["url", "uri", "href", "location", "redirect_location",
                                 "request_url", "response_url", "callbackUrl"])
def test_nested_url_field_query_secret_redacted(key: str) -> None:
    blob = {"outer": [{key: "https://api.example.com/x?token=SUPERSECRETVALUE&q=keep"}]}
    out = redact_value(blob)
    dumped = json.dumps(out)
    assert "SUPERSECRETVALUE" not in dumped
    assert "q=keep" in dumped  # benign param preserved


def test_nested_redirect_location_userinfo_redacted() -> None:
    url = "https://user:pass@api.example.com/x"  # pragma: allowlist secret
    out = redact_value({"redirect_location": url})
    assert "user:pass" not in json.dumps(out)


def test_url_field_list_redacted() -> None:
    out = redact_value({"urls": ["https://api.example.com/a?api_key=SECRET1",
                                 "https://api.example.com/b?q=ok"]})
    dumped = json.dumps(out)
    assert "SECRET1" not in dumped
    assert "q=ok" in dumped


def test_over_encoded_nested_url_fails_closed() -> None:
    over = "a b"
    for _ in range(80):
        over = quote(over, safe="")
    out = redact_value({"url": f"https://api.example.com/x?{over}=v"})
    assert out["url"] == REDACTED


# --- reflected known secrets -------------------------------------------------


def test_reflected_known_secret_replaced_in_place() -> None:
    secret = "opaque-runtime-" + _secrets.token_hex(8)  # pragma: allowlist secret
    text = f"prefix {secret} suffix"
    out = scrub_text(text, frozenset({secret}))
    assert secret not in out
    assert "prefix" in out and "suffix" in out  # surrounding evidence preserved


def test_reflected_known_secret_redacted_even_when_encoded() -> None:
    secret = "opaque-runtime-" + _secrets.token_hex(8)  # pragma: allowlist secret
    out = scrub_text(quote(secret, safe=""), frozenset({secret}))
    assert secret not in out


# --- canary (non-secret) evidence is preserved -------------------------------


def test_canary_preserved() -> None:
    canary = "AISCAN-DEADBEEFCAFEBABE"
    text = f"model said: {canary} exactly"
    assert canary in scrub_text(text)
    assert canary in json.dumps(redact_value({"reply": text}))


# --- structure: nesting, mixed containers, aliases, cycles, bad types --------


def test_deeply_nested_mixed_containers() -> None:
    secret = SECRET_LITERALS[0]
    blob = {"l": [[{"m": [{"token": "x", "deep": f"{secret}"}]}]]}
    out = redact_value(blob)
    dumped = json.dumps(out)
    assert secret not in dumped
    assert out["l"][0][0]["m"][0]["token"] == REDACTED


def test_alias_non_cyclic_is_allowed() -> None:
    shared = {"note": "ok"}
    blob = {"a": shared, "b": shared}  # same object twice, not a cycle
    out = redact_value(blob)
    assert out["a"] == out["b"] == {"note": "ok"}


def test_cyclic_structure_fails_closed() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    with pytest.raises(RedactionError):
        redact_value(cycle)


def test_cyclic_list_fails_closed() -> None:
    items: list[object] = []
    items.append(items)
    with pytest.raises(RedactionError):
        redact_value({"items": items})


def test_non_string_mapping_key_fails_closed() -> None:
    with pytest.raises(RedactionError):
        redact_value({1: "x"})


@pytest.mark.parametrize("bad", [b"bytes", {1, 2}, object(), 3j])
def test_unsupported_type_fails_closed(bad: object) -> None:
    with pytest.raises(RedactionError):
        redact_value({"field": bad})


# --- Unicode -----------------------------------------------------------------


def test_unicode_text_preserved_secret_removed() -> None:
    secret = SECRET_LITERALS[2]
    text = f"café ☕ {secret} — déjà vu"
    out = scrub_text(text)
    assert secret not in out


# --- seeded-secret corpus cannot appear anywhere -----------------------------


def _seeded_corpus() -> tuple[list[str], dict[str, object]]:
    seeds = [f"SEED-{_secrets.token_hex(10)}" for _ in range(40)]
    it = iter(seeds)
    blob = {
        "headers": {"Authorization": next(it), "X-Trace": next(it)},
        "url": f"https://api.example.com/p?token={next(it)}&keep=1",
        "messages": [
            {"role": "user", "content": f"see {next(it)}"},
            {"role": "tool", "arguments": {"api_key": next(it), "q": next(it)}},
            {"role": "tool", "result": [{"secret": next(it)}, f"blob {next(it)}"]},
        ],
        "nested": [[[{"password": next(it), "deep": f"z {next(it)} z"}]]],
        "encoded": quote(next(it), safe=""),
    }
    return seeds, blob


def test_seeded_corpus_absent_from_serialized_redaction() -> None:
    seeds, blob = _seeded_corpus()
    known = frozenset(seeds)
    # Redact recursively with the reflected seeds known.
    out = redact_value(_scrub_all(blob, known))
    dumped = json.dumps(out)
    leaked = [s for s in seeds if s in dumped]
    assert not leaked, f"{len(leaked)} seeded secrets leaked: {leaked[:3]}"


def _scrub_all(value: object, known: frozenset[str]) -> object:
    # Apply known-secret scrubbing to every string first (models reflected
    # secrets), then structural redaction handles field names/patterns.
    if isinstance(value, str):
        return scrub_text(value, known)
    if isinstance(value, dict):
        return {k: _scrub_all(v, known) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_all(v, known) for v in value]
    return value


# --- exception path does not leak (adjacent code path) -----------------------


def test_transport_error_message_has_no_secret() -> None:
    transport = Transport(TransportConfig(timeout=0.3, max_retries=0))
    target = normalize_target("http://127.0.0.1:9/chat")
    with pytest.raises(TransportError) as exc:
        transport.send(
            target, method="POST", prompt="x", body_template="*",
            headers={"Authorization": "Bearer super-secret-abc123def456"},
        )
    assert "super-secret-abc123def456" not in str(exc.value)


def test_invalid_method_exception_has_no_secret() -> None:
    # The invalid-method library path rejects before sending; its exception must
    # not echo a secret-bearing header.
    transport = Transport(TransportConfig())
    target = normalize_target("http://127.0.0.1:9/chat")
    with pytest.raises(TransportError) as exc:
        transport.send(
            target, method="DELETE", prompt="x", body_template="*",
            headers={"Authorization": "Bearer super-secret-abc123def456"},
        )
    assert "super-secret-abc123def456" not in str(exc.value)


@pytest.mark.parametrize(
    "method",
    [
        "Bearer sk-abcdef0123456789",
        "AKIA1234567890ABCDEF",  # pragma: allowlist secret
        "Bearer ghp_abcdefghijklmnopqrst0",  # pragma: allowlist secret
    ],
)
def test_secret_like_invalid_method_not_leaked_library(method: str) -> None:
    transport = Transport(TransportConfig())
    target = normalize_target("http://127.0.0.1:9/chat")
    with pytest.raises(TransportError) as exc:
        transport.send(target, method=method, prompt="x", body_template="*")
    msg = str(exc.value)
    assert "sk-abcdef0123456789" not in msg
    assert "AKIA1234567890ABCDEF" not in msg  # pragma: allowlist secret
    assert "ghp_abcdefghijklmnopqrst0" not in msg  # pragma: allowlist secret


def test_secret_like_invalid_method_not_leaked_cli(mock_server, tmp_path, capsys) -> None:
    from ai_scan import cli
    from tests.conftest import MockRequest, MockResponse

    def app(req: MockRequest) -> MockResponse:
        return MockResponse(status=200, body=b"{}")

    server = mock_server(app)
    url = f"{server.base_url}/chat"
    code = cli.main(
        ["fingerprint", "--target", url,
         "--method", "Bearer sk-abcdef0123456789"],
    )
    out = capsys.readouterr().out
    assert code == cli.EXIT_RUNTIME_ERROR
    assert "sk-abcdef0123456789" not in out


def test_opaque_reflected_secret_scrubbed_across_sinks(mock_server) -> None:
    # An opaque (non-pattern) credential we send is collected from the request
    # header and scrubbed from the response body AND an ordinary response header,
    # then from the exchange record (every evidence sink).
    from tests.conftest import MockRequest, MockResponse

    opaque = "opaque-" + _secrets.token_hex(12)  # matches no credential pattern

    def reflecting(req: MockRequest) -> MockResponse:
        sent = req.headers.get("Authorization", "")
        token = sent.split()[-1] if sent else ""
        return MockResponse(
            status=200,
            body=json.dumps({"echo": f"you sent {token}"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Echo": token},
        )

    server = mock_server(reflecting)
    transport = Transport(TransportConfig())
    resp = transport.send(
        normalize_target(f"{server.base_url}/chat"),
        method="POST", prompt="x", body_template='{"input": "*"}',
        headers={"Authorization": f"Bearer {opaque}"},
    )
    assert opaque not in json.dumps(resp.evidence())
    assert opaque not in json.dumps(resp.to_record().to_dict())


def test_cli_assess_output_and_report_have_no_seeded_secret(mock_server, tmp_path) -> None:
    # Public CLI sink: a credential the target reflects must not reach the
    # console summary or the written report.
    from ai_scan import cli
    from tests.conftest import MockRequest, MockResponse

    seed = "AKIA1234567890ABCDEF"  # credential-format literal  # pragma: allowlist secret

    def reflecting(req: MockRequest) -> MockResponse:
        return MockResponse(
            status=200,
            body=json.dumps({"reply": f"echo {seed}"}).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-Leak-Token": seed},
        )

    server = mock_server(reflecting)
    url = f"{server.base_url}/chat"
    out = tmp_path / "report.json"
    import contextlib as _ctx
    import io

    buf = io.StringIO()
    with _ctx.redirect_stdout(buf):
        cli.main(["assess", "--target", url, "--out", str(out)])
    assert seed not in buf.getvalue()
    assert seed not in out.read_text(encoding="utf-8")
