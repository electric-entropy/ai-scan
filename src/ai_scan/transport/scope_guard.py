"""Per-connection egress scope enforcement.

A :class:`ScopeGuard` is bound to the single in-scope :class:`Target` for a
run and is consulted by the broker *on every physical attempt*, before any
socket I/O. It enforces, per attempt:

* canonical scheme, host, and effective port (exact same-origin);
* the target's request path (a redirect or rewritten path is out of scope);
* that the host's *resolved* IPs stay in scope — every resolution is re-checked,
  so DNS rebinding (a changed answer between attempts) is rejected;
* IPv4/IPv6 family constraints;
* no mixed public/private answer set;
* no resolution to a private/internal address for a *named* host unless
  explicitly granted (an IP-literal target permits exactly its own address).

The Target defines the allowed zone: an operator who names a
loopback literal may reach loopback; a public hostname that resolves to a
private address is treated as SSRF and blocked. Name resolution uses an injected
``resolver`` so rebinding and mixed-zone answers are testable without real DNS.
All denials raise :class:`ScopeError` (message is secret-free).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from ai_scan.targets import Target, TargetError, normalize_target, same_origin
from ai_scan.transport._errors import ScopeError

# Resolves a hostname to a list of textual IP addresses.
Resolver = Callable[[str], list[str]]

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class ResolvedEndpoint:
    """The vetted address the broker must connect to for an attempt."""

    target: Target
    ip: str
    family: int  # 4 or 6
    host_is_literal: bool


def _as_ip(value: str) -> _IpAddress | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def _is_internal(ip: _IpAddress) -> bool:
    """True for any non-globally-routable address (loopback, RFC1918, link-local…)."""
    return not ip.is_global


def default_resolver(host: str) -> list[str]:
    """Resolve ``host`` to unique IP strings via the system resolver."""
    seen: list[str] = []
    for info in socket.getaddrinfo(host, None):
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


@dataclass
class ScopeGuard:
    """Re-checks every attempt against the in-scope target.

    Attributes:
        target: The single in-scope, normalized target for the run.
        resolver: Hostname → IP strings (injected for testability).
        allow_private: Permit a *named* host to resolve to internal IPs.
        allowed_families: Permitted IP families (4 and/or 6).
    """

    target: Target
    resolver: Resolver = default_resolver
    allow_private: bool = False
    allowed_families: frozenset[int] = frozenset({4, 6})
    _pinned: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def check(self, url: str) -> ResolvedEndpoint:
        """Validate ``url`` and its resolved IPs; return the pinned endpoint.

        Raises:
            ScopeError: On any origin, path, family, privacy, or rebinding
                violation. The message never contains the untrusted URL.
        """
        self._check_origin_and_path(url)

        host = self.target.host
        literal = _as_ip(host)
        if literal is not None:
            resolved = [literal]
        else:
            resolved = self._resolve(host)

        self._check_family(resolved)
        self._check_privacy(resolved, host_is_literal=literal is not None)
        self._check_rebinding(host, resolved)

        chosen = resolved[0]
        return ResolvedEndpoint(
            target=self.target,
            ip=chosen.compressed,
            family=chosen.version,
            host_is_literal=literal is not None,
        )

    # -- individual checks (each fails closed with a secret-free message) ------

    def _check_origin_and_path(self, url: str) -> None:
        try:
            candidate = normalize_target(url)
        except TargetError as exc:
            raise ScopeError("request URL is not a canonical in-scope target") from exc
        if not same_origin(candidate, self.target):
            raise ScopeError("request origin is outside the target scope")
        if candidate.path != self.target.path:
            raise ScopeError("request path is outside the target scope")

    def _resolve(self, host: str) -> list[_IpAddress]:
        answers = list(self.resolver(host))
        if not answers:
            raise ScopeError("target host did not resolve to any address")
        resolved: list[_IpAddress] = []
        for answer in answers:
            ip = _as_ip(answer)
            if ip is None:
                raise ScopeError("name resolution returned a non-IP address")
            resolved.append(ip)
        return resolved

    def _check_family(self, resolved: list[_IpAddress]) -> None:
        for ip in resolved:
            if ip.version not in self.allowed_families:
                raise ScopeError(f"resolved IP family IPv{ip.version} is not permitted")

    def _check_privacy(self, resolved: list[_IpAddress], *, host_is_literal: bool) -> None:
        privacy = {_is_internal(ip) for ip in resolved}
        if len(privacy) > 1:
            raise ScopeError("host resolves to a mix of public and private addresses")
        is_internal = privacy == {True}
        # A named host resolving to an internal address is SSRF unless granted.
        # An IP-literal target permits exactly its own (possibly internal)
        # address, so the operator's explicit choice stands.
        if is_internal and not host_is_literal and not self.allow_private:
            raise ScopeError("target host resolves to a private address; not granted")

    def _check_rebinding(self, host: str, resolved: list[_IpAddress]) -> None:
        answer_key = tuple(sorted(ip.compressed for ip in resolved))
        # The guard is shared for the whole transport lifetime, so the pin is
        # read-modify-written under a lock to stay consistent under concurrency.
        with self._lock:
            previous = self._pinned.get(host)
            if previous is not None and previous != answer_key:
                raise ScopeError(
                    "DNS rebinding detected: host resolution changed between attempts"
                )
            self._pinned[host] = answer_key
