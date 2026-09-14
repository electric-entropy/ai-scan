"""Tests for target normalization and origin-boundary enforcement."""

from __future__ import annotations

import pytest

from ai_scan.targets import Target, TargetError, normalize_target, same_origin


def test_accepts_http_and_https() -> None:
    assert normalize_target("http://example.com/path").scheme == "http"
    assert normalize_target("https://example.com/path").scheme == "https"


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "gopher://x"])
def test_rejects_non_http_schemes(url: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(url)


def test_lowercases_hostname() -> None:
    assert normalize_target("https://EXAMPLE.COM/API").host == "example.com"


def test_removes_default_ports() -> None:
    assert normalize_target("http://example.com:80/").port == 80
    assert normalize_target("http://example.com:80/").origin == "http://example.com"
    assert normalize_target("https://example.com:443/").origin == "https://example.com"


def test_retains_non_default_ports() -> None:
    t = normalize_target("http://example.com:8080/x")
    assert t.port == 8080
    assert t.origin == "http://example.com:8080"


def test_rejects_embedded_credentials() -> None:
    with pytest.raises(TargetError):
        normalize_target("http://user:pass@example.com/")  # pragma: allowlist secret


def test_rejects_missing_host() -> None:
    with pytest.raises(TargetError):
        normalize_target("http:///path")


def test_rejects_fragments() -> None:
    with pytest.raises(TargetError):
        normalize_target("http://example.com/path#frag")


@pytest.mark.parametrize("url", ["http://example.com:70000/", "http://example.com:abc/"])
def test_rejects_malformed_ports(url: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(url)


def test_same_origin_exact_match() -> None:
    a = normalize_target("https://example.com:443/one")
    b = normalize_target("https://example.com/two")
    assert same_origin(a, b)


def test_subdomains_are_different_origins() -> None:
    a = normalize_target("https://example.com/")
    b = normalize_target("https://api.example.com/")
    assert not same_origin(a, b)


def test_scheme_mismatch_is_different_origin() -> None:
    a = normalize_target("http://example.com/")
    b = normalize_target("https://example.com/")
    assert not same_origin(a, b)


def test_port_mismatch_is_different_origin() -> None:
    a = normalize_target("http://example.com:8080/")
    b = normalize_target("http://example.com:9090/")
    assert not same_origin(a, b)


def test_target_is_frozen() -> None:
    t = normalize_target("https://example.com/")
    with pytest.raises((AttributeError, TypeError)):
        t.host = "evil.com"  # type: ignore[misc]


def test_ipv6_host_is_bracketed_in_origin_and_url() -> None:
    t = normalize_target("http://[::1]:8080/x")
    assert t.host == "::1"
    assert t.port == 8080
    assert t.origin == "http://[::1]:8080"
    assert t.url == "http://[::1]:8080/x"


def test_ipv6_default_port_origin_has_no_port() -> None:
    t = normalize_target("https://[2001:db8::1]/path")
    assert t.origin == "https://[2001:db8::1]"
    assert t.url == "https://[2001:db8::1]/path"


def test_ipv6_same_origin_and_distinct_ports() -> None:
    a = normalize_target("http://[::1]:8080/a")
    b = normalize_target("http://[::1]:8080/b")
    c = normalize_target("http://[::1]:9090/a")
    assert same_origin(a, b)
    assert not same_origin(a, c)


def test_ipv6_is_canonicalized_for_origin_matching() -> None:
    # Compressed and expanded forms of the same address share one origin.
    a = normalize_target("http://[::1]:8080/a")
    b = normalize_target("http://[0:0:0:0:0:0:0:1]:8080/b")
    assert a.host == "::1"
    assert b.host == "::1"
    assert same_origin(a, b)


def test_ipv6_uppercase_is_lowercased_canonically() -> None:
    t = normalize_target("http://[2001:DB8::AbCd]/x")
    assert t.host == "2001:db8::abcd"
    assert t.origin == "http://[2001:db8::abcd]"


@pytest.mark.parametrize(
    "url",
    [
        "http://[gggg::1]/",       # invalid hex group
        "http://[]/",              # empty literal
        "http://[::1/",            # unclosed bracket
        "http://[1:2:3]/",         # too few groups / malformed
        "http://[::1]:abc/",       # malformed port on a valid literal
    ],
)
def test_malformed_ipv6_literals_are_rejected(url: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://[fe80::1%25eth0]/",  # percent-encoded zone id
        "http://[fe80::1%eth0]/",    # raw zone id
    ],
)
def test_ipv6_zone_identifiers_are_rejected(url: str) -> None:
    with pytest.raises(TargetError):
        normalize_target(url)


def test_ipv6_non_default_port_is_bracketed_with_port() -> None:
    t = normalize_target("https://[2001:db8::1]:8443/x")
    assert t.origin == "https://[2001:db8::1]:8443"
    assert t.port == 8443


def test_target_roundtrip_fields() -> None:
    t = normalize_target("https://example.com:8443/a/b?q=1")
    assert isinstance(t, Target)
    assert t.scheme == "https"
    assert t.host == "example.com"
    assert t.port == 8443
    assert t.origin == "https://example.com:8443"
