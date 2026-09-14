"""Reproducible-build gate: build the wheel twice and compare hashes.

A real reproducibility check — not a claim. It builds the wheel twice under a
fixed ``SOURCE_DATE_EPOCH`` and ``PYTHONHASHSEED`` into separate output
directories and compares the artifact SHA-256. Any divergence fails the gate,
so the project only claims reproducibility that is actually enforced.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# 2024-01-01T00:00:00Z — a fixed epoch so archive timestamps are deterministic.
DEFAULT_EPOCH = "1704067200"


class ReproducibilityError(Exception):
    """Raised when a reproducibility build cannot be performed."""


@dataclass(frozen=True)
class ReproResult:
    reproducible: bool
    wheel_name: str
    first_sha256: str
    second_sha256: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _build_wheel(root: Path, outdir: Path, epoch: str) -> Path:
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = epoch
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Build backend state lives in-tree; clear it so each build starts clean.
    for stale in (root / "build", *root.glob("src/*.egg-info")):
        if stale.exists():
            shutil.rmtree(stale)
    try:
        subprocess.run(
            [
                sys.executable, "-m", "build", "--wheel", "--no-isolation",
                "--outdir", str(outdir), str(root),
            ],
            check=True,
            capture_output=True,
            env=env,
            text=True,
        )
    except subprocess.CalledProcessError as exc:  # pragma: no cover - build env issue
        raise ReproducibilityError(f"wheel build failed: {exc.stderr[-500:]}") from exc
    wheels = sorted(outdir.glob("*.whl"))
    if len(wheels) != 1:
        raise ReproducibilityError(f"expected exactly one wheel, found {len(wheels)}")
    return wheels[0]


def check_reproducible(root: Path | None = None, epoch: str = DEFAULT_EPOCH) -> ReproResult:
    """Build the wheel twice and compare hashes."""
    root = root or _repo_root()
    with tempfile.TemporaryDirectory() as tmp:
        out1 = Path(tmp) / "build1"
        out2 = Path(tmp) / "build2"
        out1.mkdir()
        out2.mkdir()
        wheel1 = _build_wheel(root, out1, epoch)
        wheel2 = _build_wheel(root, out2, epoch)
        h1 = _sha256(wheel1)
        h2 = _sha256(wheel2)
        if wheel1.name != wheel2.name:
            raise ReproducibilityError("wheel names differ between builds")
        return ReproResult(h1 == h2, wheel1.name, h1, h2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify the wheel builds reproducibly.")
    parser.add_argument("--epoch", default=DEFAULT_EPOCH, help="fixed SOURCE_DATE_EPOCH")
    args = parser.parse_args(argv)
    try:
        result = check_reproducible(epoch=args.epoch)
    except ReproducibilityError as exc:
        print(f"reproducibility check failed: {exc}")
        return 1
    if not result.reproducible:
        print(
            f"NOT reproducible: {result.wheel_name} "
            f"{result.first_sha256} != {result.second_sha256}"
        )
        return 1
    print(f"reproducible: {result.wheel_name} sha256={result.first_sha256}")
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    raise SystemExit(main())
