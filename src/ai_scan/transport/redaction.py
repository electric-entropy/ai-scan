"""Central, recursive redaction — a domain boundary, not an HTTP helper.

Everything that may carry a secret is redacted here before it can reach an
exception message, console/log text, or a persisted record:

* sensitive headers/cookies (by explicit name and token-like name patterns),
* secret-like query-parameter values and URL userinfo,
* credential literals matched by format (API keys, Bearer tokens, AWS keys,
  private keys, JWTs), detected even through repeated percent-encoding,
* reflected known-secret values supplied by the caller,
* recursively, inside nested containers (tool arguments/results, model
  messages, JSON/form fields).

Redaction fails **closed**: cyclic structures, non-string mapping keys, and
unsupported value types raise :class:`RedactionError` rather than risk leaking.
Non-secret canary evidence (e.g. ``AISCAN-…`` tokens) is preserved so
deterministic validation still works.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from ai_scan.transport.provider_semantics import audit_json, decide_provider_semantics

REDACTED = "REDACTED"
_DECODE_CAP = 64


class RedactionError(Exception):
    """Raised when a value cannot be safely redacted (fail closed)."""


# Credential classification is by normalized *tokens*, not substrings — so
# benign names like ``author``, ``authentication_method``, ``token_count``,
# ``session_notes``, ``accessibility``, and ``monkey`` are NOT treated as
# secrets, while real credential keys still are.
#
# A key is sensitive iff its last normalized token is a credential word, or its
# full normalized form is an explicit credential key.
# NOTE: bare ``key`` is deliberately NOT a credential suffix — that would
# destroy benign ``sort_key``/``primary_key``/``keyboard_key`` evidence. A
# ``*_key`` field is sensitive only when qualified by a credential word (see
# ``_KEY_QUALIFIERS``).
_CREDENTIAL_SUFFIX_TOKENS = frozenset(
    {
        "authorization",
        "auth",
        "token",
        "secret",
        "password",
        "passwd",
        "pwd",
        "credential",
        "credentials",
        "cookie",
        "signature",
        "sig",
        "apikey",
        "bearer",
        "session",
    }
)

# Qualifiers that make a trailing ``key`` token a credential (``api_key``,
# ``access_key``, ``private_key``, ``signing_key``, …).
_KEY_QUALIFIERS = frozenset(
    {
        "api",
        "access",
        "private",
        "secret",
        "signing",
        "sign",
        "client",
        "encryption",
        "encrypt",
        "auth",
        "session",
        "consumer",
        "app",
        "credential",
        "bearer",
        "ssh",
        "gpg",
        "pgp",
        "cert",
    }
)
_CREDENTIAL_EXACT_KEYS = frozenset(
    {
        "authorization",
        "proxy_authorization",
        "cookie",
        "set_cookie",
        "token",
        "secret",
        "password",
        "credential",
        "credentials",
        "signature",
        "x_api_key",
        "api_key",
        "apikey",
        "x_auth_token",
        "x_amz_security_token",
        "x_goog_api_key",
        "session_id",
        "sessionid",
        "session_token",
    }
)

_DELIMITERS = re.compile(r"[^0-9A-Za-z]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _key_tokens(key: str) -> list[str]:
    """Normalize a header/field/query key to lowercase tokens.

    Splits on delimiters (``-``, ``_``, space, …) and camelCase boundaries:
    ``"X-Api-Key"`` → ``["x", "api", "key"]``; ``"refreshToken"`` →
    ``["refresh", "token"]``; ``"token_count"`` → ``["token", "count"]``.
    """
    spaced = _CAMEL_BOUNDARY.sub(" ", _DELIMITERS.sub(" ", key))
    return [t.lower() for t in spaced.split() if t]


def _is_credential_key(key: str) -> bool:
    tokens = _key_tokens(key)
    if not tokens:
        return False
    if "_".join(tokens) in _CREDENTIAL_EXACT_KEYS:
        return True
    last = tokens[-1]
    if last in _CREDENTIAL_SUFFIX_TOKENS:
        return True
    # A trailing ``key`` is a credential only when credential-qualified, so
    # ``api_key``/``access_key``/``private_key`` redact while ``sort_key``,
    # ``primary_key``, and ``keyboard_key`` are preserved.
    if last == "key" and len(tokens) >= 2 and tokens[-2] in _KEY_QUALIFIERS:
        return True
    return False

# Credential literal formats (narrow: never match 64-hex digests or canaries).
_SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"\bsk-[A-Za-z0-9]{12,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{8,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+]{16,}"),
)


def is_sensitive_header(name: str) -> bool:
    return _is_credential_key(name)


def is_sensitive_query_key(key: str) -> bool:
    return _is_credential_key(key)


def _is_sensitive_field(key: str) -> bool:
    return _is_credential_key(key)


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of ``headers`` with sensitive values replaced."""
    return {
        key: (REDACTED if is_sensitive_header(key) else value)
        for key, value in headers.items()
    }


def _decode_to_fixed_point(text: str) -> tuple[str, bool]:
    """Percent-decode ``text`` to a fixed point.

    Returns ``(decoded, suspicious)`` where ``suspicious`` is True if decoding
    was still changing the string when the bounded cap was reached (too many
    encoding layers to resolve — treat as hostile).
    """
    current = text
    for _ in range(_DECODE_CAP):
        decoded = unquote(current)
        if decoded == current:
            return current, False
        current = decoded
    return current, True


def redact_url(url: str) -> str:
    """Redact userinfo and secret-like query parameters from ``url``.

    Query keys and values are recursively percent-decoded before classification,
    so an encoded sensitive key (``%74oken``) is still caught. If any component
    is encoded beyond the bounded cap, the whole URL fails closed to ``REDACTED``.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return REDACTED
    _, path_suspicious = _decode_to_fixed_point(parts.path)
    if path_suspicious:
        return REDACTED
    netloc = parts.netloc
    if "@" in netloc:  # strip any userinfo entirely
        netloc = netloc.rsplit("@", 1)[1]
    if parts.query:
        out_pairs: list[tuple[str, str]] = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            decoded_key, key_suspicious = _decode_to_fixed_point(key)
            _, value_suspicious = _decode_to_fixed_point(value)
            if key_suspicious or value_suspicious:
                return REDACTED
            sensitive = is_sensitive_query_key(key) or is_sensitive_query_key(decoded_key)
            out_pairs.append((key, REDACTED if sensitive else value))
        query = urlencode(out_pairs)
    else:
        query = parts.query
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


# Authentication scheme keywords that prefix a credential but are not
# themselves secret. Excluded from component tracking so the ordinary word
# (``Bearer``, ``Basic``, …) is never scrubbed out of benign evidence, while
# the credential that follows it is tracked regardless of how short it is.
_AUTH_SCHEME_WORDS = frozenset(
    {
        "bearer",
        "basic",
        "digest",
        "negotiate",
        "ntlm",
        "token",
        "mac",
        "hoba",
        "mutual",
        "apikey",
        "aws4-hmac-sha256",
    }
)


_COOKIE_HEADER_KEYS = frozenset({"cookie", "set_cookie"})
# Cookie *attributes* are structural, not credentials — never track their values
# as secrets (tracking ``Path=/`` would scrub every ``/``).
_COOKIE_ATTRS = frozenset(
    {
        "path",
        "domain",
        "expires",
        "max-age",
        "secure",
        "httponly",
        "samesite",
        "version",
        "comment",
        "priority",
    }
)


def _is_cookie_header(name: str) -> bool:
    return "_".join(_key_tokens(name)) in _COOKIE_HEADER_KEYS


def _cookie_secret_values(value: str) -> set[str]:
    """Credential values from a ``Cookie`` header, by cookie syntax not whitespace."""
    out: set[str] = set()
    for pair in value.split(";"):
        name, sep, cval = pair.strip().partition("=")
        if not sep:
            continue
        if name.strip().lower() in _COOKIE_ATTRS:
            continue
        cval = cval.strip()
        if cval and cval.lower() not in _AUTH_SCHEME_WORDS:
            out.update(_value_variants(cval))
    return out


def sensitive_header_values(headers: dict[str, str]) -> frozenset[str]:
    """Sensitive request-header secret values, for body/response scrubbing.

    Collects the full value *and* each credential component — regardless of
    length — so a scheme-prefixed credential (``Bearer <token>``, ``Basic
    <b64>``) is caught even when the target reflects only the bare token. A
    ``Cookie`` header is split by cookie syntax (``name=value`` pairs), not
    whitespace, so the bare cookie value is tracked (and cookie *attributes* are
    not). Known authentication-scheme keywords are excluded so the scheme word
    itself is never treated as a secret.
    """
    values: set[str] = set()
    for key, value in headers.items():
        if is_sensitive_header(key) and value:
            values.add(value)
            if _is_cookie_header(key):
                values.update(_cookie_secret_values(value))
            else:
                for part in value.split():
                    if part and part.lower() not in _AUTH_SCHEME_WORDS:
                        values.add(part)
    return frozenset(values)


def url_secret_values(url: str) -> frozenset[str]:
    """Collect secret values from a URL for body scrubbing.

    Uses the same fixed-point decoding and sensitive-key logic as
    :func:`redact_url`: userinfo (password), and the values of query parameters
    whose key is sensitive (raw *or* recursively decoded). Both the raw and
    decoded value forms are collected so a reflected secret is caught however it
    is encoded.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return frozenset()
    values: set[str] = set()
    if parts.password:
        values.update(_value_variants(parts.password))
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        decoded_key, _ = _decode_to_fixed_point(key)
        if is_sensitive_query_key(key) or is_sensitive_query_key(decoded_key):
            if value:
                values.update(_value_variants(value))
    return frozenset(values)


def body_secret_values(
    body: bytes | str | None, content_type: str | None = None
) -> frozenset[str]:
    """Collect credential values from a structured JSON or form request body.

    A credential placed in a request body (``{"api_key": "<opaque>"}`` or
    ``token=<opaque>``) must be tracked as a known secret *before* sending, so a
    target that reflects the body cannot leak it into the response, evidence, or
    stored record. Classification uses the same credential-key logic as headers
    and URLs. Values are expanded through :func:`_value_variants` so an encoded
    reflection is caught. Unparseable bodies contribute nothing (fail open only
    on *collection* — the value scrubbers remain the enforcement boundary).
    """
    if not body:
        return frozenset()
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    ctype = (content_type or "").lower()
    values: set[str] = set()

    def _harvest_json() -> bool:
        # Harvest during parsing via an object hook so that *every* occurrence of
        # a duplicated credential key is collected — ``json.loads`` alone keeps
        # only the last value, dropping an earlier secret from the inventory.
        def _hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            for key, val in pairs:
                if isinstance(key, str) and _is_credential_key(key):
                    _collect_leaf_strings(val, values)
            return dict(pairs)

        try:
            json.loads(text, object_pairs_hook=_hook)
        except (ValueError, TypeError):
            return False
        return True

    def _harvest_form() -> None:
        for key, value in parse_qsl(text, keep_blank_values=True):
            if value and _is_credential_key(key):
                values.update(_value_variants(value))

    if "json" in ctype:
        _harvest_json()
    elif "form-urlencoded" in ctype:
        _harvest_form()
    else:
        # Unknown/absent content-type: try JSON, then fall back to form parsing.
        if not _harvest_json():
            _harvest_form()
    return frozenset(v for v in values if v)


def _collect_leaf_strings(node: Any, out: set[str]) -> None:
    """Collect every string leaf under ``node`` (the value of a credential key)."""
    if isinstance(node, str):
        if node:
            out.update(_value_variants(node))
    elif isinstance(node, dict):
        for value in node.values():
            _collect_leaf_strings(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_leaf_strings(item, out)


def _value_variants(value: str) -> set[str]:
    """All spellings of a secret value a target might reflect.

    ``parse_qsl`` form-decodes query values (``+`` → space, ``%XX`` → byte).
    This expands a decoded value back across the raw form, its fully
    percent-decoded form, and the ``+``↔space form-encoding swap of each — so
    ``opaque+secret`` and ``opaque secret`` (and their percent-encoded
    equivalents) are all tracked together.
    """
    variants: set[str] = set()
    seeds = {value}
    decoded, _ = _decode_to_fixed_point(value)
    seeds.add(decoded)
    for seed in seeds:
        if not seed:
            continue
        variants.add(seed)
        variants.add(seed.replace(" ", "+"))
        variants.add(seed.replace("+", " "))
    return {v for v in variants if v}


def _matches_secret_pattern(text: str) -> bool:
    return any(p.search(text) for p in _SECRET_PATTERNS)


# Every simple JSON string escape (``\\"``, ``\\n`` …). ``\\uXXXX`` (and
# surrogate pairs) are handled by the scanner below.
_JSON_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
# Maximum JSON-string nesting depth and text size we will semantically
# decode/redact. These bounds prevent hostile evidence from turning redaction
# into an unbounded memory/CPU sink; oversized input fails closed.
_JSON_NEST_CAP = 8
_JSON_TEXT_SIZE_CAP = 1_048_576


def _json_unescape_once(text: str) -> str:
    """One pass of JSON string-escape decoding, combining surrogate pairs.

    ``\\uD83D\\uDD11`` becomes the astral codepoint (🔑), not two lone
    surrogates, so a secret containing non-BMP characters is still seen.
    """
    if "\\" not in text:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt == "u" and i + 6 <= n:
            try:
                code = int(text[i + 2 : i + 6], 16)
            except ValueError:
                out.append(ch)
                i += 1
                continue
            # High surrogate followed by a low surrogate → combine.
            if 0xD800 <= code <= 0xDBFF and text[i + 6 : i + 8] == "\\u" and i + 12 <= n:
                try:
                    low = int(text[i + 8 : i + 12], 16)
                except ValueError:
                    low = 0
                if 0xDC00 <= low <= 0xDFFF:
                    combined = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                    out.append(chr(combined))
                    i += 12
                    continue
            out.append(chr(code))
            i += 6
            continue
        if nxt in _JSON_SIMPLE_ESCAPES:
            out.append(_JSON_SIMPLE_ESCAPES[nxt])
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _json_unescape_fixed(text: str) -> tuple[str, bool]:
    """Decode JSON string escapes to a fixed point (bounded).

    Multiply-escaped input (``\\\\u004f`` → ``\\u004f`` → ``O``) is decoded
    repeatedly until stable. Returns ``(decoded, suspicious)`` where
    ``suspicious`` is True if it was still changing at the cap (treat as hostile).
    """
    current = text
    for _ in range(_JSON_NEST_CAP):
        nxt = _json_unescape_once(current)
        if nxt == current:
            return current, False
        current = nxt
    return current, True


def _redact_json_embedded(
    text: str, known_secrets: frozenset[str], depth: int
) -> str | None:
    """Redact secrets *inside* a JSON document, keeping the output valid JSON.

    Parsing decodes every escape (surrogate pairs included), so ``_scrub``
    removes the secret in all parsed occurrences — including nested JSON encoded
    as a string value, via the ``depth``-bounded recursion through ``scrub_text``.
    Re-serializing yields valid, secret-free JSON. Returns ``None`` when ``text``
    is not a JSON document, so the caller falls back to whole-string redaction.
    """
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    scrubbed = _scrub(parsed, known_secrets, (), depth)
    try:
        return json.dumps(scrubbed, ensure_ascii=False)
    except (ValueError, TypeError):  # pragma: no cover - scrubbed is JSON-safe
        return None


def scrub_text(
    text: str, known_secrets: frozenset[str] = frozenset(), *, _depth: int = 0
) -> str:
    """Redact credential literals and reflected known secrets from ``text``.

    A credential-format match redacts the whole string. Known reflected secrets
    are replaced in place so surrounding (non-secret) evidence is preserved. A
    secret recoverable only after peeling percent-encoding, or JSON string
    escaping (``\\uXXXX`` incl. surrogate pairs, simple escapes, and
    multiply/nested-encoded JSON, all to a bounded fixed point), is redacted:
    *inside* the JSON when ``text`` is a JSON document (so it stays valid), else
    the whole string is redacted (fail closed). ``_depth`` bounds nested-JSON
    recursion.
    """
    if len(text) > _JSON_TEXT_SIZE_CAP:
        return REDACTED
    decoded, suspicious = _decode_to_fixed_point(text)
    if suspicious:
        return REDACTED
    if _matches_secret_pattern(text) or (decoded != text and _matches_secret_pattern(decoded)):
        return REDACTED
    secrets = sorted((s for s in known_secrets if s), key=len, reverse=True)
    result = text
    for secret in secrets:
        if secret in result:
            result = result.replace(secret, REDACTED)
        elif decoded != text and secret in decoded:
            # Present only once percent-decoding is peeled away — fail closed.
            return REDACTED
    # Any secret still recoverable from the (raw-redacted) string via a bounded
    # fixed-point JSON unescape — mixed raw+escaped, surrogate pairs, and
    # nested/double-encoded JSON — is redacted *inside* the JSON so the persisted
    # body stays valid, falling back to whole-string redaction when the text is
    # not a JSON document or nesting exceeds the cap.
    residual, residual_suspicious = _json_unescape_fixed(result)
    # Still-changing escape layers at the semantic cap are unresolved hostile
    # input.  The known secret may be hidden beyond the partially decoded value,
    # so visibility at this intermediate layer is not a safe acceptance test.
    if residual_suspicious:
        return REDACTED
    if residual != result and any(secret in residual for secret in secrets):
        if _depth >= _JSON_NEST_CAP:
            return REDACTED
        embedded = _redact_json_embedded(text, frozenset(secrets), _depth + 1)
        return embedded if embedded is not None else REDACTED
    return result


def redact_value(value: Any, known_secrets: frozenset[str] = frozenset()) -> Any:
    """Recursively redact ``value``, failing closed on unsafe structures.

    Applies credential **key-name** redaction (a field named like a credential
    has its value redacted) *and* value scrubbing. Use this for untrusted
    request/response data.
    """
    return _redact(value, frozenset(known_secrets), ())


def scrub_structure(value: Any, known_secrets: frozenset[str] = frozenset()) -> Any:
    """Recursively scrub secret *values* without key-name redaction.

    A value-only final pass for tool-produced structures (e.g. a report), where
    redacting by field name would destroy benign metadata (a block literally
    named ``authorization``). Credential literals, reflected known secrets, and
    URL-field query secrets are still redacted; fails closed on unsafe input.
    """
    return _scrub(value, frozenset(known_secrets), ())


def scrub_provider_envelope(
    text: str,
    known_secrets: frozenset[str] = frozenset(),
    *,
    raw_body_digest: str | None = None,
    raw_body_length: int | None = None,
    decode_valid: bool = True,
    truncated: bool = False,
    status: int = 200,
    redirected: bool = False,
) -> str:
    """Return a metadata-preserving, model-text-free JSON provider envelope.

    Provider text is used in memory by the adapter before this persistence view
    is built. Persistence is a strict allowlist: fixed role/completion enums,
    bounded integer usage counters, and an opaque commitment to the exact raw
    body. Unknown fields and every semantic text/container are dropped wholesale.
    """
    if (raw_body_digest is None) != (raw_body_length is None):
        return REDACTED
    if raw_body_digest is not None and (
        not isinstance(raw_body_digest, str)
        or len(raw_body_digest) != 64
        or any(ch not in "0123456789abcdef" for ch in raw_body_digest)
        or isinstance(raw_body_length, bool)
        or not isinstance(raw_body_length, int)
        or raw_body_length < 0
        or raw_body_length > (1 << 63) - 1
    ):
        return REDACTED
    decision = decide_provider_semantics(
        text,
        raw_body_digest=raw_body_digest,
        raw_body_length=raw_body_length,
        decode_valid=decode_valid,
        truncated=truncated,
        status=status,
        redirected=redirected,
    )
    _ = known_secrets
    return audit_json(decision)


def _short_key_hash(key: str) -> str:
    """A short, stable, order-independent disambiguator for a mapping key."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def scrubbed_key_map(keys: list[str], known: frozenset[str]) -> dict[str, str]:
    """Map each original mapping key to a scrubbed, collision-free output key.

    A credential can hide in an untrusted key name (e.g. a reflected response
    header ``X-<secret>``); the key text is scrubbed. Disambiguation is
    **order-independent and deterministic**: whenever two or more original keys
    would land on the same scrubbed name (including a scrubbed secret key
    colliding with an already-safe key), *every* colliding original gets a stable
    suffix derived from its own content — so no entry is ever silently dropped
    or overwritten, regardless of iteration order.
    """
    if len(set(keys)) != len(keys):
        raise RedactionError("duplicate source mapping keys cannot be disambiguated")

    scrubbed = {key: scrub_text(key, known) for key in keys}
    collisions = Counter(scrubbed.values())
    candidates = {
        key: (
            f"{scrubbed[key]}#{_short_key_hash(key)}"
            if collisions[scrubbed[key]] > 1
            else scrubbed[key]
        )
        for key in keys
    }

    # A generated suffix can itself equal an existing scrubbed key, and bounded
    # hashes can collide. Resolve every resulting collision deterministically by
    # original-key sort order, repeating for adversarial collision chains. With
    # N unique source keys, at most N rounds can absorb a finite chain; otherwise
    # fail closed rather than permit a silent overwrite.
    for _ in range(len(keys) + 1):
        groups: dict[str, list[str]] = {}
        for key, candidate in candidates.items():
            groups.setdefault(candidate, []).append(key)
        duplicate_groups = [group for group in groups.values() if len(group) > 1]
        if not duplicate_groups:
            return candidates
        for group in duplicate_groups:
            for rank, key in enumerate(sorted(group)):
                candidates[key] = (
                    f"{candidates[key]}#{_short_key_hash(key)}#{rank}"
                )
    raise RedactionError("mapping keys cannot be disambiguated safely")


def _scrub_mapping(
    value: dict[str, Any],
    known: frozenset[str],
    chain: tuple[int, ...],
    depth: int,
    *,
    redact_by_name: bool,
) -> dict[str, Any]:
    for key in value:
        if not isinstance(key, str):
            raise RedactionError(f"non-string mapping key: {type(key).__name__}")
    key_map = scrubbed_key_map(list(value.keys()), known)
    out: dict[str, Any] = {}
    for key, item in value.items():
        safe_key = key_map[key]
        if redact_by_name and _is_sensitive_field(key):
            out[safe_key] = REDACTED
        elif _is_url_field(key):
            out[safe_key] = _redact_urls(item, known, chain, depth)
        else:
            out[safe_key] = (
                _redact(item, known, chain, depth)
                if redact_by_name
                else _scrub(item, known, chain, depth)
            )
    return out


def _scrub(value: Any, known: frozenset[str], ancestors: tuple[int, ...], depth: int = 0) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return scrub_text(value, known, _depth=depth)
    if isinstance(value, (dict, list, tuple)):
        vid = id(value)
        if vid in ancestors:
            raise RedactionError("cyclic structure cannot be scrubbed safely")
        chain = (*ancestors, vid)
        if isinstance(value, dict):
            return _scrub_mapping(value, known, chain, depth, redact_by_name=False)
        return [_scrub(item, known, chain, depth) for item in value]
    raise RedactionError(f"unsupported value type for scrubbing: {type(value).__name__}")


def _redact(value: Any, known: frozenset[str], ancestors: tuple[int, ...], depth: int = 0) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return scrub_text(value, known, _depth=depth)
    if isinstance(value, (dict, list, tuple)):
        vid = id(value)
        if vid in ancestors:
            raise RedactionError("cyclic structure cannot be redacted safely")
        chain = (*ancestors, vid)
        if isinstance(value, dict):
            return _scrub_mapping(value, known, chain, depth, redact_by_name=True)
        return [_redact(item, known, chain, depth) for item in value]
    raise RedactionError(f"unsupported value type for redaction: {type(value).__name__}")


# URL-bearing field names whose string values must also pass through redact_url
# (so secret query params / userinfo are redacted inside nested structures).
_URL_FIELD_SUFFIX = frozenset(
    {"url", "urls", "uri", "uris", "href", "hrefs", "location", "locations"}
)


def _is_url_field(key: str) -> bool:
    tokens = _key_tokens(key)
    return bool(tokens) and tokens[-1] in _URL_FIELD_SUFFIX


def _redact_urls(
    value: Any, known: frozenset[str], ancestors: tuple[int, ...], depth: int = 0
) -> Any:
    """Redact a URL-bearing field: route strings through redact_url + scrub."""
    if isinstance(value, str):
        return scrub_text(redact_url(value), known, _depth=depth)
    if isinstance(value, list):
        return [_redact_urls(item, known, ancestors, depth) for item in value]
    return _redact(value, known, ancestors, depth)
