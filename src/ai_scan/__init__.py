"""ai-scan: CLI-only authorized LLM assessment tool.

Behavioral model fingerprinting and safe, canary-based prompt-injection testing
for explicitly authorized security assessment. CLI only; fails closed unless
authorization is confirmed interactively or supplied via a target-bound receipt.
"""

from __future__ import annotations

__version__ = "0.1.0"
