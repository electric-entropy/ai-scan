"""Malformed baselines are not evidence of resolved findings."""

import copy
import json

import pytest

from ai_scan import cli
from ai_scan.reporting.diff import compare_baselines

BASE = {
    "schema_version": "1.0-baseline",
    "target_origin": "http://127.0.0.1",
    "confirmed_findings": {
        "finding:direct:confirmed": {
            "family": "direct", "status": "confirmed", "severity": "medium"
        }
    },
    "analyst_leads": {},
}


@pytest.mark.parametrize("field,value", [
    ("schema_version", None), ("schema_version", 1), ("schema_version", "2"),
    ("target_origin", None), ("target_origin", 1), ("target_origin", "https://other.test"),
    ("target_origin", "http://127.0.0.1/path"),
    ("confirmed_findings", []), ("confirmed_findings", None),
    ("confirmed_findings", {"x": {}}), ("analyst_leads", []),
    ("extra", True),
])
def test_invalid_baselines_reject_at_python_and_cli(tmp_path, field, value):
    bad = copy.deepcopy(BASE)
    bad[field] = value
    with pytest.raises((ValueError, TypeError)):
        compare_baselines(BASE, bad)
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(json.dumps(BASE))
    new.write_text(json.dumps(bad))
    assert cli.main(["baseline", "diff", "--old", str(old), "--new", str(new)]) == 1


@pytest.mark.parametrize("field", list(BASE))
def test_missing_fields_rejected(field):
    bad = copy.deepcopy(BASE)
    del bad[field]
    with pytest.raises((ValueError, TypeError)):
        compare_baselines(BASE, bad)


def test_empty_same_origin_baseline_resolves():
    empty = dict(BASE, confirmed_findings={})
    assert compare_baselines(BASE, empty)["resolved_confirmed"] == ["finding:direct:confirmed"]


def test_duplicate_json_keys_reject_at_cli(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"schema_version":"1.0-baseline","schema_version":"1.0-baseline"}')
    assert cli.main(["baseline", "diff", "--old", str(path), "--new", str(path)]) == 1
