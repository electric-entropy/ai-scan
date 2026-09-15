"""Strict, fail-closed loading of configuration/plan documents.

Every document is validated against a packaged, versioned JSON Schema *before*
any active object or network traffic is created. Loading rejects, up front:

* malformed JSON, **duplicate object keys**, and **non-finite numbers** (the
  ``NaN``/``Infinity`` literals *and* exponent overflow such as ``1e999``);
* an **unsupported schema version** (no packaged schema for it);
* **unknown fields** (schemas set ``additionalProperties: false``);
* **invalid or unbounded limits** (schema ``minimum``/``maximum`` bounds);
* **type confusion** in ``const``/``enum`` (integer ``1`` never satisfies ``true``);
* **non-normalized or unsafe URLs/scopes** (credentials, fragments, wrong scheme,
  or a non-canonical origin), via ``x-url`` / ``x-origin`` annotations;
* **naive or mis-ordered timestamps** (``x-datetime`` requires tz-aware RFC 3339);
* **path traversal**, including recursively percent-decoded (``%2e%2e``) forms;
* **embedded secret literals** (API keys, Bearer tokens, AWS-style credentials,
  private keys, JWTs) — secrets must be supplied by reference, never inlined.

Only a compact, explicit subset of JSON Schema is supported — enough for the
platform's own schemas, with no third-party dependency.
"""

from __future__ import annotations

import json
import math
import re
import unicodedata
from datetime import datetime
from importlib import resources
from typing import Any
from urllib.parse import unquote, urlsplit

from ai_scan.core.errors import ConfigError
from ai_scan.targets import TargetError, normalize_target

# Document kinds and the schema versions packaged for each. Evidence and finding
# are schema **v2** (the new run-path shapes), never conflated with report v1.
SUPPORTED_SCHEMAS: dict[str, frozenset[int]] = {
    "target": frozenset({1}),
    "engagement": frozenset({1}),
    "plan": frozenset({1}),
    "pack": frozenset({1}),
    "evidence": frozenset({2}),
    "finding": frozenset({2}),
}

# Credential-literal markers. Deliberately narrow (real credential formats) so
# they never collide with legitimate config values such as 64-hex digests.
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
_TRAVERSAL = re.compile(r"(?:^|[\\/])\.\.(?:[\\/]|$)")
# Unicode general categories forbidden in URLs: control, format, surrogate,
# private-use, and unassigned code points.
_FORBIDDEN_URL_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})
# Strict RFC 3339: date, 'T' separator, time, optional fractional seconds, and a
# required timezone (`Z` or `±HH:MM`). Excludes the space separator and naive forms.
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


# --- strict JSON parsing ------------------------------------------------------


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ConfigError(f"Duplicate JSON key: {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(token: str) -> Any:
    raise ConfigError(f"Non-finite JSON literal not allowed: {token}")


def _strict_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ConfigError(f"Non-finite JSON number not allowed: {token}")
    return value


def load_json_strict(text: str) -> Any:
    """Parse JSON, rejecting duplicate object keys and non-finite numbers."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_strict_float,
        )
    except ConfigError:
        raise
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Malformed JSON: {exc}") from exc


# --- packaged schema access ---------------------------------------------------


def load_schema(kind: str, version: int) -> dict[str, Any]:
    """Load the packaged schema for ``kind``/``version``."""
    if kind not in SUPPORTED_SCHEMAS or version not in SUPPORTED_SCHEMAS[kind]:
        raise ConfigError(f"Unsupported schema {kind!r} version {version!r}")
    resource = resources.files("ai_scan.schemas").joinpath(f"{kind}-v{version}.schema.json")
    try:
        raw = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging bug
        raise ConfigError(f"Missing packaged schema for {kind} v{version}") from exc
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):  # pragma: no cover - packaging bug
        raise ConfigError(f"Packaged schema for {kind} v{version} is not an object")
    return parsed


# --- type-aware equality (bool is not int) -----------------------------------


def _json_equal(value: Any, expected: Any) -> bool:
    """JSON-type-aware equality: boolean ``true`` never equals integer ``1``."""
    if isinstance(expected, bool) or isinstance(value, bool):
        return isinstance(value, bool) and isinstance(expected, bool) and value == expected
    return bool(value == expected)


# --- minimal JSON Schema validation ------------------------------------------


def _type_ok(value: Any, json_type: str) -> bool:
    if json_type == "object":
        return isinstance(value, dict)
    if json_type == "array":
        return isinstance(value, list)
    if json_type == "string":
        return isinstance(value, str)
    if json_type == "boolean":
        return isinstance(value, bool)
    if json_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if json_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if json_type == "null":
        return value is None
    raise ConfigError(f"Schema error: unknown type {json_type!r}")  # pragma: no cover


def _validate(value: Any, schema: dict[str, Any], path: str) -> None:
    if "const" in schema and not _json_equal(value, schema["const"]):
        raise ConfigError(f"{path}: must equal {schema['const']!r}")
    if "enum" in schema and not any(_json_equal(value, opt) for opt in schema["enum"]):
        raise ConfigError(f"{path}: {value!r} is not one of {schema['enum']}")

    json_type = schema.get("type")
    if json_type is not None and not _type_ok(value, json_type):
        raise ConfigError(f"{path}: expected {json_type}, got {type(value).__name__}")

    if json_type in ("integer", "number"):
        _validate_number(value, schema, path)
    elif json_type == "string":
        _validate_string(value, schema, path)
    elif json_type == "array":
        _validate_array(value, schema, path)
    elif json_type == "object":
        _validate_object(value, schema, path)


def _validate_number(value: Any, schema: dict[str, Any], path: str) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ConfigError(f"{path}: non-finite number is not allowed")
    if "minimum" in schema and value < schema["minimum"]:
        raise ConfigError(f"{path}: {value} < minimum {schema['minimum']}")
    if "maximum" in schema and value > schema["maximum"]:
        raise ConfigError(f"{path}: {value} > maximum {schema['maximum']}")
    if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
        raise ConfigError(f"{path}: {value} <= exclusiveMinimum {schema['exclusiveMinimum']}")
    if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
        raise ConfigError(f"{path}: {value} >= exclusiveMaximum {schema['exclusiveMaximum']}")


def _validate_string(value: str, schema: dict[str, Any], path: str) -> None:
    if "minLength" in schema and len(value) < schema["minLength"]:
        raise ConfigError(f"{path}: shorter than minLength {schema['minLength']}")
    if "maxLength" in schema and len(value) > schema["maxLength"]:
        raise ConfigError(f"{path}: longer than maxLength {schema['maxLength']}")
    pattern = schema.get("pattern")
    if pattern is not None and not re.search(pattern, value):
        raise ConfigError(f"{path}: does not match pattern {pattern!r}")
    if schema.get("x-url"):
        _check_url(value, path, origin_only=False)
    if schema.get("x-origin"):
        _check_url(value, path, origin_only=True)
    if schema.get("x-datetime"):
        _check_datetime(value, path)
    if schema.get("x-secret-scan"):
        # Field-aware: secret literals are rejected only in secret-bearing/
        # reference fields (e.g. an env reference), never in free-text/payload.
        for secret in _SECRET_PATTERNS:
            if secret.search(value):
                raise ConfigError(f"{path}: embedded secret literal is not allowed here")


def _validate_array(value: list[Any], schema: dict[str, Any], path: str) -> None:
    if "minItems" in schema and len(value) < schema["minItems"]:
        raise ConfigError(f"{path}: fewer than minItems {schema['minItems']}")
    if "maxItems" in schema and len(value) > schema["maxItems"]:
        raise ConfigError(f"{path}: more than maxItems {schema['maxItems']}")
    item_schema = schema.get("items")
    if isinstance(item_schema, dict):
        for i, item in enumerate(value):
            _validate(item, item_schema, f"{path}[{i}]")


def _validate_object(value: dict[str, Any], schema: dict[str, Any], path: str) -> None:
    properties: dict[str, Any] = schema.get("properties", {})
    for required in schema.get("required", []):
        if required not in value:
            raise ConfigError(f"{path}: missing required field {required!r}")
    additional = schema.get("additionalProperties", True)
    for key, item in value.items():
        if key in properties:
            _validate(item, properties[key], f"{path}.{key}")
        elif additional is False:
            raise ConfigError(f"{path}: unknown field {key!r}")
        elif isinstance(additional, dict):
            _validate(item, additional, f"{path}.{key}")


# --- semantic validation ------------------------------------------------------


def _check_url(value: str, path: str, *, origin_only: bool) -> None:
    for ch in value:
        # Reject whitespace and every Unicode control/format/surrogate/private-use/
        # unassigned character (not just ASCII C0/DEL).
        if ch.isspace() or unicodedata.category(ch) in _FORBIDDEN_URL_CATEGORIES:
            raise ConfigError(
                f"{path}: URL must not contain whitespace or "
                f"control/format/surrogate/private/unassigned characters"
            )
    try:
        target = normalize_target(value)
    except TargetError as exc:
        raise ConfigError(f"{path}: invalid HTTP(S) URL ({exc})") from exc
    # normalize_target already rejects credentials, fragments, and non-HTTP(S).
    parts = urlsplit(value)
    if "%" in parts.netloc:
        raise ConfigError(f"{path}: URL host/authority must not be percent-encoded")
    if origin_only:
        # A scope must be exactly its canonical origin: no path/query and already
        # normalized (lowercased host, no default port).
        if value != target.origin:
            raise ConfigError(
                f"{path}: scope must be a bare, normalized origin, e.g. {target.origin}"
            )
    else:
        # An endpoint may carry a path, but its *origin* must be canonical. Compare
        # the value's literal origin (not a startswith prefix, which would accept
        # a non-canonical ":443"/uppercase-host form) against the normalized origin.
        raw_origin = f"{parts.scheme}://{parts.netloc}"
        if raw_origin != target.origin:
            raise ConfigError(
                f"{path}: URL origin is not canonical (expected {target.origin})"
            )


def _check_datetime(value: str, path: str) -> datetime:
    # Enforce strict RFC 3339 (T separator + timezone) before delegating to
    # fromisoformat, which would otherwise accept a space separator / naive form.
    if not _RFC3339.fullmatch(value):
        raise ConfigError(f"{path}: not a strict RFC 3339 timestamp: {value!r}")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConfigError(f"{path}: invalid RFC 3339 timestamp {value!r} ({exc})") from exc
    if parsed.tzinfo is None:  # pragma: no cover - regex already requires a tz
        raise ConfigError(f"{path}: timestamp must be timezone-aware: {value!r}")
    return parsed


_DECODE_CAP = 64  # anti-DoS ceiling; a fixed point is reached far sooner


def _decoded_has_traversal(value: str) -> bool:
    """Traversal check that percent-decodes to a **fixed point** first.

    Repeatedly ``unquote``s (catching ``%2e%2e``, double-encoded ``%252e`` …)
    until the string stops changing, checking each layer. The iteration ceiling
    only guards against pathological input; the loop normally ends at the fixed
    point well before it.
    """
    current = value
    for _ in range(_DECODE_CAP):
        if _TRAVERSAL.search(current):
            return True
        decoded = unquote(current)
        if decoded == current:  # fixed point reached: decision is final
            return bool(_TRAVERSAL.search(current))
        current = decoded
    # Cap hit while decoding still changes the string: too many encoding layers
    # to resolve — reject as suspicious rather than accept.
    return True


def _scan_traversal(value: Any, path: str) -> None:
    """Reject path traversal in any string (field-independent); secrets are
    handled field-aware via the ``x-secret-scan`` schema annotation."""
    if isinstance(value, str):
        if _decoded_has_traversal(value):
            raise ConfigError(
                f"{path}: path traversal or excessive percent-encoding is not allowed"
            )
    elif isinstance(value, dict):
        for key, item in value.items():
            _scan_traversal(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _scan_traversal(item, f"{path}[{i}]")


# Per-kind timestamp-ordering invariants (start must not be after end).
_TIME_ORDERING: dict[str, tuple[str, str]] = {
    "engagement": ("issued_at", "expires_at"),
}


def _check_time_ordering(doc: dict[str, Any], kind: str) -> None:
    pair = _TIME_ORDERING.get(kind)
    if pair is None:
        return
    start_key, end_key = pair
    if start_key in doc and end_key in doc:
        start = _check_datetime(doc[start_key], f"$.{start_key}")
        end = _check_datetime(doc[end_key], f"$.{end_key}")
        if start > end:
            raise ConfigError(f"{start_key} ({doc[start_key]}) is after {end_key} ({doc[end_key]})")


# --- plan semantics -----------------------------------------------------------
#
# An executable plan is the canonical runtime :class:`Plan` artifact, validated by
# ``_validate_runtime_plan`` (strict parse + load_plan + verify_plan_integrity) — an
# exact policy/registry-derived match, not a user-tightened policy document. The
# former ``_validate_plan_policy`` "tightening" path has been removed (audit A1.1).


# --- target structure semantics (discriminated unions) -----------------------


def _check_secret_ref(ref: dict[str, Any], where: str) -> None:
    has_env = "env" in ref
    has_fd = "fd" in ref
    if has_env == has_fd:
        raise ConfigError(f"{where}: each reference must name exactly one of 'env' or 'fd'")


def _validate_target_semantics(doc: dict[str, Any]) -> None:
    request = doc.get("request", {})
    marker = request.get("prompt_marker")
    body_template = request.get("body_template")
    # GET carries the marker in the URL/query, never a body template.
    if request.get("method") == "GET" and "body_template" in request:
        raise ConfigError("GET requests must not define a body_template")
    if body_template is not None and marker is not None and marker not in body_template:
        raise ConfigError("request.body_template must contain the declared prompt_marker")

    response = doc.get("response", {})
    extract = response.get("extract")
    # Exactly the extractor matching the discriminator may be present.
    if extract == "json_path":
        if "json_path" not in response:
            raise ConfigError("response.extract='json_path' requires response.json_path")
        if "regex" in response:
            raise ConfigError("response.extract='json_path' must not define response.regex")
    elif extract == "regex":
        if "regex" not in response:
            raise ConfigError("response.extract='regex' requires response.regex")
        if "json_path" in response:
            raise ConfigError("response.extract='regex' must not define response.json_path")
    elif extract == "raw_body":
        if "json_path" in response or "regex" in response:
            raise ConfigError("response.extract='raw_body' must not define json_path or regex")

    session = doc.get("session")
    if isinstance(session, dict):
        mode = session.get("mode")
        if mode == "stateful" and "session_header" not in session:
            raise ConfigError("a stateful session requires session.session_header")
        if mode == "stateless" and "session_header" in session:
            raise ConfigError("a stateless session must not define session_header")

    for ref in request.get("header_refs", []):
        _check_secret_ref(ref, "request.header_refs")


def _validate_runtime_plan(text: str) -> dict[str, Any]:
    """Validate the canonical *runtime* plan artifact — the same one the runner runs.

    A plan document is the executable :class:`~ai_scan.orchestration.planner.Plan`:
    strict-parsed (duplicate keys / non-finite rejected), semantically constructed
    and digest-verified by ``load_plan``, then checked by ``verify_plan_integrity``
    to be exactly the canonical policy/registry-derived plan for its mode. There is
    no separate "tightening" path: an executable plan must match policy exactly.
    """
    from ai_scan.orchestration.planner import (
        PlanError,
        load_plan,
        plan_to_dict,
        verify_plan_integrity,
    )

    data = load_json_strict(text)
    if not isinstance(data, dict):
        raise ConfigError("Plan document must be a JSON object")
    try:
        plan = load_plan(data)
        verify_plan_integrity(plan)
    except PlanError as exc:
        raise ConfigError(f"invalid plan: {exc}") from exc
    return plan_to_dict(plan)


_SEMANTIC_VALIDATORS = {
    "target": _validate_target_semantics,
}


# --- public entry point -------------------------------------------------------


def load_document(text: str, kind: str) -> dict[str, Any]:
    """Strictly parse and validate a document of ``kind``.

    Raises:
        ConfigError: On any strict-loading or validation failure (the CLI maps
            this to exit code ``1`` before constructing any active object).
    """
    if kind == "plan":
        return _validate_runtime_plan(text)

    doc = load_json_strict(text)
    if not isinstance(doc, dict):
        raise ConfigError("Top-level document must be a JSON object")

    version = doc.get("schema_version")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ConfigError("Document must declare an integer 'schema_version'")

    schema = load_schema(kind, version)  # rejects unsupported versions
    _validate(doc, schema, path="$")
    _scan_traversal(doc, path="$")
    _check_time_ordering(doc, kind)
    semantic = _SEMANTIC_VALIDATORS.get(kind)
    if semantic is not None:
        semantic(doc)
    return doc
