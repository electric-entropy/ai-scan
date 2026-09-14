"""Make the top-level `scripts/` release-gate package importable in tests.

The release tooling is intentionally NOT part of the shipped `ai_scan` runtime
package (it is a release gate), so it lives at the repo root and is added to
``sys.path`` here rather than installed.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
