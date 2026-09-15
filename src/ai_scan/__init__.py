"""ai-scan: CLI-only LLM security-assessment tool.

Behavioral model fingerprinting and safe, canary-based prompt-injection testing.
CLI only; unattended by design. Every request is confined to the exact target you
specify, and all evidence is redacted fail-closed.
"""

from __future__ import annotations

__version__ = "0.1.0"
