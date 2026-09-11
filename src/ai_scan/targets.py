"""Target URL normalization and exact-origin boundary enforcement.

A :class:`Target` captures the security-relevant identity of a URL: scheme,
lowercased host, and effective port. Origin comparison is exact — subdomains,
scheme changes, and port changes are all distinct origins. Anything that could
smuggle scope escape (embedded credentials, missing host, fragments, malformed
ports, non-HTTP schemes) is rejected at normalization time.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetError(ValueError):
    """Raised when a target URL is invalid or unsafe to normalize."""


@dataclass(frozen=True)
class Target:
    """A normalized, origin-comparable HTTP(S) target.

    Attributes:
        scheme: ``http`` or ``https``.
        host: Lowercased hostname (no credentials, no port).
        port: Effective port (explicit, or the scheme default).
        path: Request path (may be empty).
        query: Raw query string without the leading ``?`` (may be empty).
        url: The reconstructed normalized URL.
    """

    scheme: str
    host: str
    port: int
    path: str
    query: str
    url: str

    @property
    def origin(self) -> str:
        """The canonical origin string, omitting default ports.

        IPv6 hosts are wrapped in brackets so the authority is unambiguous.
        """
        formatted = _format_host(self.host)
        if self.port == _DEFAULT_PORTS[self.scheme]:
            return f"{self.scheme}://{formatted}"
        return f"{self.scheme}://{formatted}:{self.port}"


def normalize_target(raw: str) -> Target:
    """Parse and normalize ``raw`` into a :class:`Target`.

    Raises:
        TargetError: If the URL uses a disallowed scheme, embeds credentials,
            lacks a host, carries a fragment, or has a malformed/out-of-range
            port.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TargetError("Target URL must be a non-empty string.")

    # urlsplit validates bracketed IPv6 literals eagerly and raises ValueError
    # for malformed ones (e.g. unclosed brackets); surface as TargetError.
    try:
        parts = urlsplit(raw.strip())
    except ValueError as exc:
        raise TargetError(f"Malformed target URL: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise TargetError(f"Unsupported scheme {scheme!r}; only http/https allowed.")

    if parts.fragment:
        raise TargetError("Target URL must not contain a fragment.")

    # Accessing username/hostname/port parses the netloc, which raises
    # ValueError for a malformed IPv6 literal — surface it as a TargetError.
    try:
        has_credentials = (
            parts.username is not None or parts.password is not None or "@" in parts.netloc
        )
        host = parts.hostname
        raw_port = parts.port
    except ValueError as exc:
        raise TargetError(f"Target URL has a malformed host or port: {exc}") from exc

    if has_credentials:
        raise TargetError("Target URL must not embed credentials.")

    if not host:
        raise TargetError("Target URL must include a host.")
    host = _normalize_host(host.lower())

    port = raw_port if raw_port is not None else _DEFAULT_PORTS[scheme]
    if not (1 <= port <= 65535):
        raise TargetError(f"Target port {port} is out of range.")

    path = parts.path
    query = parts.query

    normalized = _reconstruct(scheme, host, port, path, query)
    return Target(
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        query=query,
        url=normalized,
    )


def _normalize_host(host: str) -> str:
    """Canonicalize a host; validate and compress IPv6 literals.

    IPv6 literals (identified by a ``:``) are validated and rewritten to their
    canonical compressed form so that equivalent spellings share one origin.
    Zone identifiers (``%zone``) reference a local interface, not a remote
    target, and are rejected. Malformed literals are rejected.
    """
    if ":" not in host:
        return host
    if "%" in host:
        raise TargetError("IPv6 zone identifiers are not supported as targets.")
    try:
        return ipaddress.IPv6Address(host).compressed
    except ValueError as exc:
        raise TargetError(f"Malformed IPv6 target literal: {host!r}.") from exc


def _format_host(host: str) -> str:
    """Bracket IPv6 literals so they are unambiguous in an authority."""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _reconstruct(scheme: str, host: str, port: int, path: str, query: str) -> str:
    formatted = _format_host(host)
    authority = formatted if port == _DEFAULT_PORTS[scheme] else f"{formatted}:{port}"
    url = f"{scheme}://{authority}{path}"
    if query:
        url = f"{url}?{query}"
    return url


def same_origin(a: Target, b: Target) -> bool:
    """Return ``True`` iff ``a`` and ``b`` share scheme, host, and effective port."""
    return (a.scheme, a.host, a.port) == (b.scheme, b.host, b.port)
