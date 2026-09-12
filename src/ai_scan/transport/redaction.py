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

import re
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

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


def sensitive_header_values(headers: dict[str, str]) -> frozenset[str]:
    """Sensitive request-header secret values, for body/response scrubbing.

    Collects the full value *and* each of its whitespace-separated components —
    regardless of length — so a scheme-prefixed credential (``Bearer <token>``,
    ``Basic <b64>``) is caught even when the target reflects only the bare
    token, and even when that token is short (``Bearer abc123`` → ``abc123``).
    Known authentication-scheme keywords are excluded so the scheme word itself
    is never treated as a secret.
    """
    values: set[str] = set()
    for key, value in headers.items():
        if is_sensitive_header(key) and value:
            values.add(value)
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


def scrub_text(text: str, known_secrets: frozenset[str] = frozenset()) -> str:
    """Redact credential literals and reflected known secrets from ``text``.

    A credential-format match redacts the whole string. Known reflected secrets
    are replaced in place so surrounding (non-secret) evidence is preserved; but
    if a known secret is present only once percent-encoding is peeled away — or
    the string is encoded beyond the bounded cap (fail closed) — the whole
    string is redacted.
    """
    decoded, suspicious = _decode_to_fixed_point(text)
    if suspicious:
        return REDACTED
    if _matches_secret_pattern(text) or (decoded != text and _matches_secret_pattern(decoded)):
        return REDACTED
    result = text
    for secret in sorted((s for s in known_secrets if s), key=len, reverse=True):
        if secret in result:
            result = result.replace(secret, REDACTED)
        elif decoded != text and secret in decoded:
            return REDACTED
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


def _scrub(value: Any, known: frozenset[str], ancestors: tuple[int, ...]) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return scrub_text(value, known)
    if isinstance(value, (dict, list, tuple)):
        vid = id(value)
        if vid in ancestors:
            raise RedactionError("cyclic structure cannot be scrubbed safely")
        chain = (*ancestors, vid)
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise RedactionError(f"non-string mapping key: {type(key).__name__}")
                if _is_url_field(key):
                    out[key] = _redact_urls(item, known, chain)
                else:
                    out[key] = _scrub(item, known, chain)
            return out
        return [_scrub(item, known, chain) for item in value]
    raise RedactionError(f"unsupported value type for scrubbing: {type(value).__name__}")


def _redact(value: Any, known: frozenset[str], ancestors: tuple[int, ...]) -> Any:
    if value is None or isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return scrub_text(value, known)
    if isinstance(value, (dict, list, tuple)):
        vid = id(value)
        if vid in ancestors:
            raise RedactionError("cyclic structure cannot be redacted safely")
        chain = (*ancestors, vid)
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise RedactionError(f"non-string mapping key: {type(key).__name__}")
                if _is_sensitive_field(key):
                    out[key] = REDACTED
                elif _is_url_field(key):
                    out[key] = _redact_urls(item, known, chain)
                else:
                    out[key] = _redact(item, known, chain)
            return out
        return [_redact(item, known, chain) for item in value]
    raise RedactionError(f"unsupported value type for redaction: {type(value).__name__}")


# URL-bearing field names whose string values must also pass through redact_url
# (so secret query params / userinfo are redacted inside nested structures).
_URL_FIELD_SUFFIX = frozenset(
    {"url", "urls", "uri", "uris", "href", "hrefs", "location", "locations"}
)


def _is_url_field(key: str) -> bool:
    tokens = _key_tokens(key)
    return bool(tokens) and tokens[-1] in _URL_FIELD_SUFFIX


def _redact_urls(value: Any, known: frozenset[str], ancestors: tuple[int, ...]) -> Any:
    """Redact a URL-bearing field: route strings through redact_url + scrub."""
    if isinstance(value, str):
        return scrub_text(redact_url(value), known)
    if isinstance(value, list):
        return [_redact_urls(item, known, ancestors) for item in value]
    return _redact(value, known, ancestors)
