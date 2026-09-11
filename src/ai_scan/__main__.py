"""Enable ``python -m ai_scan``."""

from __future__ import annotations

import sys

from ai_scan.cli import main

if __name__ == "__main__":
    sys.exit(main())
