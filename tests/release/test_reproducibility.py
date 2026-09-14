"""W3 — reproducible-build check: two builds under a fixed environment match."""

from __future__ import annotations

import pytest
from scripts import reproducible_build as rb


@pytest.mark.slow
def test_wheel_is_reproducible_across_two_builds() -> None:
    result = rb.check_reproducible()
    assert result.reproducible, (result.first_sha256, result.second_sha256)
    assert result.first_sha256 == result.second_sha256
    assert result.wheel_name.endswith(".whl")


def test_main_reports_success() -> None:
    # main() performs the double build and returns 0 only when hashes match.
    assert rb.main([]) == 0
