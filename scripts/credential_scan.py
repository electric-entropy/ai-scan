"""Deterministic local credential scanner (release gate).

Scans a directory tree for credential-shaped values before packaging/commit. It
covers assignment-style secrets, common provider token prefixes, bearer/basic
auth headers, credential URLs, screaming-env-style values, and private-key
blocks. It fails closed on binary/oversized/unreadable files (which could hide a
secret) unless their path is explicitly allowlisted.

Design notes:
- No third-party dependencies; pure stdlib so it can run as an early CI gate.
- Never emits a raw secret value: every finding carries only a redacted,
  fixed-length fingerprint of the matched span.
- The scanner deliberately scans ``tests/`` too, so a secret in a new/untracked
  fixture is caught before it is committed. Intentional dummy fixtures must be
  narrowly allowlisted by relative path.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 5_000_000

DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "node_modules",
        ".eggs",
    }
)

# High-confidence provider token shapes — flagged regardless of entropy.
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    (
        "auth-header",
        re.compile(r"(?i)authorization\s*:\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}"),
    ),
    (
        "credential-url",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s/:@]+:[^\s/:@]{4,}@[^\s/]+"),
    ),
)

# Assignment/env shapes — flagged only when the value looks like a real secret.
_ASSIGNMENT_KEYWORDS = (
    r"api[_-]?key",
    r"secret(?:[_-]?key)?",
    r"access[_-]?key",
    r"auth[_-]?token",
    r"client[_-]?secret",
    r"password",
    r"passwd",
    r"pwd",
    r"token",
)
_KEY_COMPONENT = r"(?:" + "|".join(_ASSIGNMENT_KEYWORDS) + r")"
# Match a whole key identifier that CONTAINS a secret keyword as a delimited
# component, so snake/dotted/camel keys (aws_secret_access_key, client.secret,
# apiKey) are covered — a plain `\bsecret\b` misses underscore-joined keys.
_QUOTED_ASSIGNMENT = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:[A-Za-z0-9]+[_.\-])*"
    + _KEY_COMPONENT
    + r"(?:[_.\-][A-Za-z0-9]+)*\s*[:=]\s*(['\"])(?P<val>[^'\"]{8,})\1"
)
_ENV_ASSIGNMENT = re.compile(
    r"(?m)^[A-Z][A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY)[A-Z0-9_]*"
    r"\s*=\s*(?P<val>\S{8,})\s*$"
)

# A line carrying this marker holds an intentional dummy credential (e.g. a
# redaction test vector). It is the ONLY allowlist mechanism — narrow, explicit,
# and line-level. Any credential-shaped line WITHOUT the marker is flagged, in
# every file including tests, so a new/untracked secret is caught before commit.
_ALLOWLIST_MARKER = re.compile(r"pragma:\s*allowlist\s+secret", re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    """One credential-shaped hit. ``redacted`` never contains the raw value."""

    path: str
    line: int
    kind: str
    redacted: str


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_secret(value: str) -> bool:
    """Heuristic: does a quoted/bare value look like a real secret (not a name)?"""
    v = value.strip()
    if len(v) < 12 or " " in v or "\t" in v:
        return False
    if re.fullmatch(r"[A-Z0-9_]+", v):  # SCREAMING_SNAKE constant / dummy id
        return False
    if re.fullmatch(r"[a-z_]+", v):  # plain lowercase words / identifiers
        return False
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", v) and "_" in v:  # snake_case identifier
        return False
    return _entropy(v) >= 3.0


def _redact(span: str) -> str:
    digest = hashlib.sha256(span.encode("utf-8")).hexdigest()[:12]
    return f"[redacted len={len(span)} sha256:{digest}]"


def scan_text(text: str, *, path: str = "<memory>") -> list[Finding]:
    """Return findings for one text blob (line numbers are 1-indexed)."""
    findings: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        if _ALLOWLIST_MARKER.search(line):
            continue
        for kind, pattern in _TOKEN_PATTERNS:
            for match in pattern.finditer(line):
                findings.append(Finding(path, lineno, kind, _redact(match.group(0))))
        for match in _QUOTED_ASSIGNMENT.finditer(line):
            value = match.group("val")
            if _looks_secret(value):
                findings.append(Finding(path, lineno, "assignment-secret", _redact(value)))
    # Env-style assignments can be matched per-line as well.
    for lineno, line in enumerate(lines, 1):
        if _ALLOWLIST_MARKER.search(line):
            continue
        env_match = _ENV_ASSIGNMENT.match(line)
        if env_match and _looks_secret(env_match.group("val").strip("'\"")):
            findings.append(Finding(path, lineno, "env-secret", _redact(env_match.group("val"))))
    return findings


def _iter_files(root: Path, skip_dirs: frozenset[str]) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.relative_to(root).parts):
            continue
        yield path


def scan_tree(
    root: Path,
    *,
    allowlist: frozenset[str] = frozenset(),
    skip_dirs: frozenset[str] = DEFAULT_SKIP_DIRS,
) -> list[Finding]:
    """Scan ``root`` recursively. Fails closed on unreadable/oversized files.

    ``allowlist`` holds POSIX relative paths (relative to ``root``) that are
    intentional and fully suppressed. Keep it narrow and test-covered.
    """
    root = Path(root)
    findings: list[Finding] = []
    for path in _iter_files(root, skip_dirs):
        rel = path.relative_to(root).as_posix()
        if rel in allowlist:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            findings.append(Finding(rel, 0, "unreadable", "[stat failed]"))
            continue
        if size > MAX_FILE_BYTES:
            findings.append(Finding(rel, 0, "unreadable", f"[oversized {size} bytes]"))
            continue
        try:
            raw = path.read_bytes()
        except OSError:
            findings.append(Finding(rel, 0, "unreadable", "[read failed]"))
            continue
        if b"\x00" in raw:
            findings.append(Finding(rel, 0, "unreadable", "[binary]"))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(Finding(rel, 0, "unreadable", "[non-utf8]"))
            continue
        for finding in scan_text(text, path=rel):
            findings.append(finding)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a tree for credential-shaped values.")
    parser.add_argument("--root", default=".", help="directory to scan")
    parser.add_argument(
        "--allow",
        action="append",
        default=[],
        help="relative path to allowlist (repeatable); intentional dummies only",
    )
    args = parser.parse_args(argv)
    findings = scan_tree(Path(args.root), allowlist=frozenset(args.allow))
    if findings:
        print(f"credential scan found {len(findings)} issue(s):")
        for f in findings:
            # Never print the raw value — only path/line/kind + redacted fingerprint.
            print(f"  {f.path}:{f.line}: {f.kind} {f.redacted}")
        return 1
    print("credential scan clean")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
