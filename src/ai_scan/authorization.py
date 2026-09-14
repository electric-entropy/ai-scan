"""Fail-closed authorization gate and target-bound authorization receipts.

Two authorization paths exist:

* **Interactive** — the operator must type an exact, origin-specific
  confirmation phrase for the current run. Anything else denies.
* **Receipt** — a pre-created, target-bound record enabling non-interactive
  (headless/CI) runs. A receipt binds the normalized origin, client,
  engagement, creation time, and expiry, protected by a canonical-JSON
  SHA-256 digest.

The digest is **tamper-evident, not authenticated**: it detects accidental
edits and corruption, but a determined party who recomputes the digest can
forge a receipt. This is a documented MVP limitation (see SECURITY.md);
authenticated signatures are deferred.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from ai_scan.targets import Target, TargetError, normalize_target
from ai_scan.transport.redaction import scrub_text

CONFIRM_PREFIX = "I confirm I am authorized to assess"

# Strict RFC 3339: a ``T`` separator and an explicit timezone are required, so a
# naive or space-separated timestamp is rejected.
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$")
_RECEIPT_FIELDS = frozenset(
    {"version", "origin", "client", "engagement", "created_at", "expires", "digest",
     "plan_digest", "target"}
)


class AuthorizationError(Exception):
    """Raised when authorization is denied, invalid, expired, or tampered."""


def confirmation_phrase(target: Target) -> str:
    """The exact phrase the operator must type to authorize ``target``."""
    return f"{CONFIRM_PREFIX} {target.origin}"


def interactive_authorize(target: Target, prompt: Callable[[str], str]) -> bool:
    """Prompt for the exact confirmation phrase for ``target``.

    Args:
        target: The normalized target being authorized.
        prompt: A callable receiving the prompt message and returning the
            operator's response (injected for testability; defaults to
            :func:`input` in the CLI).

    Returns:
        ``True`` only if the response equals the confirmation phrase
        (surrounding whitespace ignored); ``False`` otherwise.
    """
    expected = confirmation_phrase(target)
    message = (
        f"Authorization required for {target.origin}\n"
        f"Type exactly: {expected}\n> "
    )
    try:
        answer = prompt(message)
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip() == expected


SUPPORTED_RECEIPT_VERSION = 1


def _canonical_payload(
    version: int, origin: str, client: str, engagement: str, expires: str, created_at: str,
    plan_digest: str | None = None, target: str | None = None,
) -> bytes:
    """Canonical JSON bytes over the integrity-protected fields (digest excluded).

    ``plan_digest``/``target`` are included only when the receipt is plan-bound,
    so an origin-only receipt's canonical payload (and digest) is unchanged.
    """
    payload = {
        "client": client,
        "created_at": created_at,
        "engagement": engagement,
        "expires": expires,
        "origin": origin,
        "version": version,
    }
    if plan_digest is not None:
        payload["plan_digest"] = plan_digest
    if target is not None:
        payload["target"] = target
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_digest(
    version: int, origin: str, client: str, engagement: str, expires: str, created_at: str,
    plan_digest: str | None = None, target: str | None = None,
) -> str:
    return hashlib.sha256(
        _canonical_payload(
            version, origin, client, engagement, expires, created_at, plan_digest, target
        )
    ).hexdigest()


@dataclass(frozen=True)
class Receipt:
    """A target-bound authorization receipt.

    Attributes:
        origin: The normalized origin the receipt authorizes.
        client: Client the engagement is for.
        engagement: Engagement identifier.
        created_at: ISO-8601 UTC creation timestamp.
        expires: Expiry date, ``YYYY-MM-DD`` (inclusive).
        digest: SHA-256 over the canonical payload of the fields above.
    """

    origin: str
    client: str
    engagement: str
    created_at: str
    expires: str
    digest: str
    version: int = SUPPORTED_RECEIPT_VERSION
    # Optional tamper-evident binding to an exact executable plan + target. This
    # is content-digest binding, NOT a cryptographic signature.
    plan_digest: str | None = None
    target: str | None = None

    @classmethod
    def create(
        cls,
        target: Target,
        client: str,
        engagement: str,
        expires: str,
        created_at: str | None = None,
        plan_digest: str | None = None,
    ) -> Receipt:
        """Create a receipt bound to ``target``, computing its digest.

        When ``plan_digest`` is supplied the receipt is additionally bound to that
        exact plan digest and the exact target URL (tamper-evidence, not a
        signature), which is what lets it authorize a Kitchen Sink run.
        """
        _validate_expiry_format(expires)
        stamp = created_at or datetime.now(UTC).isoformat()
        _validate_created_at(stamp)
        origin = target.origin
        bound_target = target.url if plan_digest is not None else None
        version = SUPPORTED_RECEIPT_VERSION
        digest = _compute_digest(
            version, origin, client, engagement, expires, stamp, plan_digest, bound_target
        )
        return cls(
            origin=origin,
            client=client,
            engagement=engagement,
            created_at=stamp,
            expires=expires,
            digest=digest,
            version=version,
            plan_digest=plan_digest,
            target=bound_target,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (including the stored digest)."""
        data: dict[str, Any] = {
            "version": self.version,
            "origin": self.origin,
            "client": self.client,
            "engagement": self.engagement,
            "created_at": self.created_at,
            "expires": self.expires,
            "digest": self.digest,
        }
        # Emit plan binding only when present, so origin-only receipts stay stable.
        if self.plan_digest is not None:
            data["plan_digest"] = self.plan_digest
        if self.target is not None:
            data["target"] = self.target
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Receipt:
        """Rebuild a receipt from a dict, validating version, timestamp, digest.

        The stored ``digest`` is intentionally *not* trusted here; the digest
        carried on the returned object is recomputed from the content so that
        integrity is checked by comparing against the stored value in
        :func:`validate_receipt`. The version must be exactly the supported
        version and ``created_at`` must parse, independently of the digest.
        """
        unknown = set(data) - _RECEIPT_FIELDS
        if unknown:
            # Closed schema: an unknown field (count only, never echoed) is a
            # tamper/format signal and fails closed.
            raise AuthorizationError(
                f"Receipt has unknown field(s) not permitted ({len(unknown)} present)."
            )
        try:
            version = data["version"]
            origin = str(data["origin"])
            client = str(data["client"])
            engagement = str(data["engagement"])
            created_at = str(data["created_at"])
            expires = str(data["expires"])
            stored_digest = str(data["digest"])
        except (KeyError, TypeError) as exc:
            raise AuthorizationError("Receipt is missing required fields.") from exc

        if not isinstance(version, int) or isinstance(version, bool):
            raise AuthorizationError("Receipt version must be an integer.")
        if version != SUPPORTED_RECEIPT_VERSION:
            raise AuthorizationError(
                f"Unsupported receipt version {version}; expected "
                f"{SUPPORTED_RECEIPT_VERSION}."
            )
        _validate_created_at(created_at)

        plan_digest = data.get("plan_digest")
        bound_target = data.get("target")
        if plan_digest is not None and not isinstance(plan_digest, str):
            raise AuthorizationError("Receipt plan_digest must be a string.")
        if bound_target is not None and not isinstance(bound_target, str):
            raise AuthorizationError("Receipt target must be a string.")
        # A bound target is only meaningful alongside a plan_digest (and vice versa).
        if (plan_digest is None) != (bound_target is None):
            raise AuthorizationError("Receipt plan_digest and target must be bound together.")

        recomputed = _compute_digest(
            version, origin, client, engagement, expires, created_at, plan_digest, bound_target
        )
        if not _constant_time_equal(recomputed, stored_digest):
            raise AuthorizationError("Receipt integrity check failed (digest mismatch).")

        return cls(
            origin=origin,
            client=client,
            engagement=engagement,
            created_at=created_at,
            expires=expires,
            digest=recomputed,
            version=version,
            plan_digest=plan_digest,
            target=bound_target,
        )


def _constant_time_equal(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a, b)


def _validate_expiry_format(expires: str) -> date:
    try:
        return date.fromisoformat(expires)
    except (ValueError, TypeError) as exc:
        raise AuthorizationError(
            f"Receipt expiry {scrub_text(str(expires))!r} is not a valid "
            f"YYYY-MM-DD date."
        ) from exc


def _validate_created_at(created_at: str) -> datetime:
    # Strict RFC 3339 with an explicit timezone; a naive or space-separated
    # timestamp is rejected (it would otherwise parse via fromisoformat).
    if not isinstance(created_at, str) or not _RFC3339.fullmatch(created_at):
        raise AuthorizationError(
            f"Receipt created_at {scrub_text(str(created_at))!r} is not a strict, "
            f"timezone-aware RFC 3339 timestamp."
        )
    try:
        parsed = datetime.fromisoformat(created_at)
    except (ValueError, TypeError) as exc:
        raise AuthorizationError(
            f"Receipt created_at {scrub_text(str(created_at))!r} is not a valid "
            f"ISO-8601 timestamp."
        ) from exc
    if parsed.tzinfo is None:  # pragma: no cover - regex already requires a tz
        raise AuthorizationError("Receipt created_at must be timezone-aware.")
    return parsed


def validate_receipt(
    receipt: Receipt, target: Target, now: date | None = None
) -> None:
    """Validate ``receipt`` for use against ``target``.

    Raises:
        AuthorizationError: If the receipt's origin does not exactly match the
            target origin, or the receipt has expired.
    """
    if receipt.origin != target.origin:
        raise AuthorizationError(
            "Receipt is bound to a different origin than the requested target."
        )
    expiry = _validate_expiry_format(receipt.expires)
    today = now or datetime.now(UTC).date()
    # Issuance bound: a receipt cannot be created in the future.
    created = _validate_created_at(receipt.created_at)
    if created.astimezone(UTC).date() > today:
        raise AuthorizationError("Receipt is issued in the future.")
    if today > expiry:
        raise AuthorizationError(f"Receipt expired on {receipt.expires}.")


def write_receipt(receipt: Receipt, path: str) -> None:
    """Write ``receipt`` to ``path`` as JSON with mode ``0600`` on POSIX."""
    data = json.dumps(receipt.to_dict(), indent=2, sort_keys=True)
    if os.name == "posix":
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(path, flags, 0o600)
        try:
            os.write(fd, data.encode("utf-8"))
        finally:
            os.close(fd)
        os.chmod(path, 0o600)
    else:  # pragma: no cover - non-POSIX fallback
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(data)


def load_receipt(path: str) -> Receipt:
    """Load and integrity-check a receipt from ``path``.

    Raises:
        AuthorizationError: If the file is missing, unreadable, not valid JSON,
            not a JSON object, missing fields, or fails the integrity check.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            raw = handle.read()
    except OSError as exc:
        raise AuthorizationError(f"Cannot read receipt file: {exc.strerror}.") from exc

    try:
        parsed = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise AuthorizationError("Receipt file is not valid JSON.") from exc

    if not isinstance(parsed, dict):
        raise AuthorizationError("Receipt file must contain a JSON object.")

    return Receipt.from_dict(parsed)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise AuthorizationError("Receipt file has a duplicate JSON key.")
        seen.add(key)
    return dict(pairs)


def authorize_for_target(
    raw_target: str,
    *,
    receipt_path: str | None,
    non_interactive: bool,
    prompt: Callable[[str], str] | None = None,
) -> Target:
    """Resolve authorization for ``raw_target``, failing closed.

    Returns the normalized :class:`Target` on success. Raises
    :class:`AuthorizationError` on any denial so callers can map it to exit
    code ``2`` *before* any transport is constructed.
    """
    try:
        target = normalize_target(raw_target)
    except TargetError as exc:
        raise AuthorizationError(str(exc)) from exc

    if receipt_path is not None:
        receipt = load_receipt(receipt_path)
        validate_receipt(receipt, target)
        return target

    if non_interactive:
        raise AuthorizationError(
            "Non-interactive run requires a valid --auth-receipt; refusing to "
            "prompt. No network traffic sent."
        )

    ask = prompt if prompt is not None else input
    if not interactive_authorize(target, ask):
        raise AuthorizationError("Authorization denied by operator.")
    return target
