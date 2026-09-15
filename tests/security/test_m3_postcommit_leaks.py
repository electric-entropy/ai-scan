"""Regressions for the four Milestone 3 post-commit redaction leaks.

Each test reproduces one reported leak directly, so a regression re-opens the
exact hole it closed:

2. Short credential components (``Bearer abc123`` → ``abc123``) dropped by a
   length floor, while the scheme word must *not* be scrubbed.
3. ``HttpResponse.evidence()`` redirect_location redacted by URL-key only, so a
   reflected known secret in a non-sensitive position survived.
4. URL secret collection missing form-decoded / plus↔space variants, letting
   ``opaque+secret`` and ``opaque secret`` bypass each other.
"""

from __future__ import annotations

from ai_scan.transport import HttpResponse
from ai_scan.transport.redaction import (
    REDACTED,
    scrub_text,
    sensitive_header_values,
    url_secret_values,
)

# A credential-format literal that scrub_text redacts on sight (gh token family).
_CRED = "ghp_1234567890abcdefABCDEF12"  # pragma: allowlist secret


# --- Fix 2: short credential components tracked; scheme word is not -----------

def test_short_bearer_component_is_tracked_as_secret() -> None:
    values = sensitive_header_values({"Authorization": "Bearer abc123"})
    # The bare credential, short though it is, must be collected...
    assert "abc123" in values
    # ...so a reflection of just the token is scrubbed from evidence.
    assert scrub_text("response echo: abc123", values) == "response echo: REDACTED"
    # ...but the auth scheme word must NOT be a tracked secret (would redact
    # the ordinary word "Bearer" everywhere).
    assert "Bearer" not in values
    assert "bearer" not in {v.lower() for v in values}
    assert scrub_text("uses Bearer auth", values) == "uses Bearer auth"


# --- Fix 3: evidence() redirect_location scrubs known secrets -----------------

def test_evidence_redirect_location_scrubs_known_secret() -> None:
    # Opaque (non-credential-format) known value in a NON-sensitive query key,
    # so only known-value scrubbing — not URL-key redaction — can catch it.
    credential_value = "opaqueSessionValue9182"
    resp = HttpResponse(
        status=302,
        body="",
        headers={},
        redirected=True,
        redirect_location=f"https://mock.local/callback?next={credential_value}",
        truncated=False,
        request_line={"method": "GET", "url": "https://mock.local/"},
        known_secrets=frozenset({credential_value}),
    )
    location = resp.evidence()["response"]["redirect_location"]
    assert credential_value not in location
    assert REDACTED in location


def test_evidence_redirect_location_redacts_sensitive_query_without_known_secret() -> None:
    credential_value = "opaqueSessionValue9182"
    resp = HttpResponse(
        status=302,
        body="",
        headers={},
        redirected=True,
        redirect_location=f"https://mock.local/callback?token={credential_value}",
        truncated=False,
        request_line={"method": "GET", "url": "https://mock.local/"},
        known_secrets=frozenset(),
    )
    location = resp.evidence()["response"]["redirect_location"]
    assert credential_value not in location
    assert "token=REDACTED" in location


# --- Fix 4: raw / percent-decoded / form-decoded / plus↔space variants --------

def test_url_secret_values_covers_plus_and_space_variants() -> None:
    plus = url_secret_values("http://mock.local/?token=opaque+secret")
    # Both the form-decoded (space) and wire (plus) spellings must be present,
    # so whichever the target reflects is scrubbed.
    assert "opaque secret" in plus
    assert "opaque+secret" in plus

    pct = url_secret_values("http://mock.local/?token=opaque%20secret")
    assert "opaque secret" in pct
    assert "opaque+secret" in pct
