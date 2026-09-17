"""ai-scan: CLI-only LLM security-assessment tool.

Behavioral model fingerprinting and safe, canary-based prompt-injection testing.
CLI only; unattended by design. Every request is confined to the exact target you
specify, and all evidence is redacted fail-closed.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path


def _version() -> str:
    try:
        return metadata.version("ai-scan")
    except metadata.PackageNotFoundError:
        try:
            import tomllib

            pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            version = data.get("project", {}).get("version")
        except Exception:
            return "0+unknown"
        if isinstance(version, str) and version:
            return version
        return "0+unknown"


__version__ = _version()
