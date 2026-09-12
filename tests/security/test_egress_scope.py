"""Adversarial egress-scope enforcement (per-connection, fail-closed).

Every physical attempt re-checks the authorized origin, path, IP family, and
the host's *resolved* IPs. DNS rebinding, mixed public/private answers, and
SSRF-style name→private resolutions are rejected as ``blocked`` scope errors,
and a rejected attempt performs no socket I/O.
"""

from __future__ import annotations

import pytest

from ai_scan.targets import normalize_target
from ai_scan.transport._errors import ScopeError
from ai_scan.transport.broker import RequestBroker
from ai_scan.transport.budgets import AttemptKind, BudgetLedger
from ai_scan.transport.scope_guard import ScopeGuard
from tests.unit.transport._fakes import FakeResponse, RecordingOpener

NAMED = normalize_target("http://api.example.test:8443/chat")
PUBLIC_IP = "93.184.216.34"


def _guard(target, resolver, **kw) -> ScopeGuard:
    return ScopeGuard(target=target, resolver=resolver, **kw)


# --- origin / path --------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://api.example.test:8443/chat",   # scheme change
        "http://api.example.test:8443/admin",   # path escape
        "http://api.example.test:9999/chat",    # port change
        "http://evil.example.test:8443/chat",   # host change
        "http://api.example.test.evil:8443/chat",  # suffix smuggling
    ],
)
def test_off_origin_or_off_path_is_blocked(url) -> None:
    guard = _guard(NAMED, lambda h: [PUBLIC_IP])
    with pytest.raises(ScopeError):
        guard.authorize(url)


def test_in_scope_public_name_is_authorized() -> None:
    guard = _guard(NAMED, lambda h: [PUBLIC_IP])
    endpoint = guard.authorize(NAMED.url)
    assert endpoint.ip == PUBLIC_IP
    assert endpoint.family == 4


# --- DNS rebinding / mixed zones / SSRF -----------------------------------------

def test_dns_rebinding_between_attempts_is_blocked() -> None:
    answers = iter([[PUBLIC_IP], ["10.0.0.5"]])
    guard = _guard(NAMED, lambda h: next(answers), allow_private=True)
    guard.authorize(NAMED.url)  # pins PUBLIC_IP
    with pytest.raises(ScopeError, match="rebinding"):
        guard.authorize(NAMED.url)  # answer changed → rebinding


def test_mixed_public_and_private_answer_is_blocked() -> None:
    guard = _guard(NAMED, lambda h: [PUBLIC_IP, "10.0.0.5"], allow_private=True)
    with pytest.raises(ScopeError, match="mix of public and private"):
        guard.authorize(NAMED.url)


def test_named_host_resolving_to_private_is_ssrf_blocked_by_default() -> None:
    guard = _guard(NAMED, lambda h: ["169.254.169.254"])  # cloud metadata
    with pytest.raises(ScopeError, match="private address"):
        guard.authorize(NAMED.url)


def test_named_host_to_private_allowed_only_with_explicit_grant() -> None:
    guard = _guard(NAMED, lambda h: ["10.0.0.5"], allow_private=True)
    endpoint = guard.authorize(NAMED.url)
    assert endpoint.ip == "10.0.0.5"


# --- IP family ------------------------------------------------------------------

def test_disallowed_ip_family_is_blocked() -> None:
    guard = _guard(NAMED, lambda h: ["2606:2800:220:1:248:1893:25c8:1946"],
                   allowed_families=frozenset({4}))
    with pytest.raises(ScopeError, match="family IPv6"):
        guard.authorize(NAMED.url)


def test_non_ip_resolution_is_blocked() -> None:
    guard = _guard(NAMED, lambda h: ["not-an-ip"])
    with pytest.raises(ScopeError):
        guard.authorize(NAMED.url)


def test_empty_resolution_is_blocked() -> None:
    guard = _guard(NAMED, lambda h: [])
    with pytest.raises(ScopeError):
        guard.authorize(NAMED.url)


# --- HTTPS IP-pinning: named-host fails closed, IP literal is allowed -----------

def test_named_host_https_fails_closed_before_socket_io() -> None:
    # The guard can validate the resolved IP, but the broker cannot pin a named
    # HTTPS connection to it (urllib would re-resolve at TLS connect, and an
    # authority rewrite would break SNI/cert validation). Fail closed.
    https_named = normalize_target("https://api.example.test/chat")
    opener = RecordingOpener(FakeResponse())
    broker = RequestBroker(
        ledger=BudgetLedger(max_requests=8),
        guard=_guard(https_named, lambda h: [PUBLIC_IP]),
        timeout=1.0,
        max_response_bytes=1024,
        opener=opener,
    )
    with pytest.raises(ScopeError, match="HTTPS") as exc:
        broker.fetch(url=https_named.url, method="GET", data=None, headers={},
                     kind=AttemptKind.INITIAL)
    assert opener.calls == [], "must not connect via the unpinned hostname"
    assert exc.value.outcome == "blocked"


def test_ip_literal_https_is_allowed_in_scope() -> None:
    # An IP-literal HTTPS target has no name to re-resolve, so it stays allowed.
    https_literal = normalize_target("https://93.184.216.34/chat")
    opener = RecordingOpener(FakeResponse(status=200, body=b"ok"))
    broker = RequestBroker(
        ledger=BudgetLedger(max_requests=8),
        guard=ScopeGuard(target=https_literal),
        timeout=1.0,
        max_response_bytes=1024,
        opener=opener,
    )
    result = broker.fetch(
        url=https_literal.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL
    )
    assert result.status == 200
    assert len(opener.calls) == 1


# --- broker integration: a blocked attempt performs no socket I/O ---------------

def test_broker_blocks_scope_violation_without_touching_socket() -> None:
    ledger = BudgetLedger(max_requests=8)
    opener = RecordingOpener(FakeResponse())
    broker = RequestBroker(
        ledger=ledger,
        guard=_guard(NAMED, lambda h: ["169.254.169.254"]),  # SSRF
        timeout=1.0,
        max_response_bytes=1024,
        opener=opener,
    )
    with pytest.raises(ScopeError) as exc:
        broker.fetch(url=NAMED.url, method="GET", data=None, headers={}, kind=AttemptKind.INITIAL)
    assert opener.calls == []
    assert exc.value.outcome == "blocked"
    # The blocked attempt is still counted so totals remain accurate.
    assert exc.value.totals == {
        "initial": 1, "retry": 0, "control": 0, "confirmation": 0, "redirect": 0, "total": 1
    }
