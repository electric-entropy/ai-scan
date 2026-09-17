"""Subprocess pytest runner for fail-closed cumulative acceptance matrices."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PytestMatrixResult:
    collected: tuple[str, ...]
    passed: int
    stdout: str
    stderr: str


class PytestMatrixError(AssertionError):
    """Raised when a cumulative pytest matrix does not execute cleanly."""


_PLUGIN = r'''
from __future__ import annotations

import json
import os

_STATE = {
    "collected": [],
    "deselected": 0,
    "reports": [],
}


def pytest_collection_modifyitems(session, config, items):
    _STATE["collected"] = [item.nodeid for item in items]


def pytest_deselected(items):
    _STATE["deselected"] += len(items)


def pytest_runtest_logreport(report):
    _STATE["reports"].append(
        {
            "nodeid": report.nodeid,
            "when": report.when,
            "outcome": report.outcome,
            "wasxfail": bool(getattr(report, "wasxfail", False)),
        }
    )


def pytest_sessionfinish(session, exitstatus):
    _STATE["exitstatus"] = int(exitstatus)
    with open(os.environ["AI_SCAN_PYTEST_MATRIX_REPORT"], "w", encoding="utf-8") as fh:
        json.dump(_STATE, fh, sort_keys=True)
'''


def _as_sorted_nodeids(nodeids: Iterable[str]) -> tuple[str, ...]:
    normalized = tuple(nodeids)
    if not normalized:
        raise PytestMatrixError("zero expected nodes")
    for nodeid in normalized:
        if not isinstance(nodeid, str) or not nodeid:
            raise PytestMatrixError(f"invalid node id: {nodeid!r}")
        if nodeid.startswith("/") or ".." in Path(nodeid).parts:
            raise PytestMatrixError(f"node id must be repo-relative: {nodeid}")
    duplicates = sorted(nodeid for nodeid, count in Counter(normalized).items() if count > 1)
    if duplicates:
        raise PytestMatrixError(f"duplicate expected nodes: {duplicates}")
    return tuple(sorted(normalized))


def _require_int_field(
    data: Mapping[str, object], *, field: str, allowed_values: set[int] | None = None
) -> int:
    value = data[field]
    if not isinstance(value, int) or isinstance(value, bool):
        raise PytestMatrixError(f"invalid {field}: {value!r}")
    if value < 0 or (allowed_values is not None and value not in allowed_values):
        raise PytestMatrixError(f"invalid {field}: {value!r}")
    return value


def _require_report_payload(data: Any, *, label: str) -> Mapping[str, object]:
    if not isinstance(data, dict):
        raise PytestMatrixError(f"invalid report payload for {label}: {data!r}")
    expected_keys = {"collected", "deselected", "reports", "exitstatus"}
    actual_keys = set(data)
    missing = expected_keys - actual_keys
    extra = actual_keys - expected_keys
    if missing:
        if missing == {"reports"}:
            raise PytestMatrixError(f"missing reports for {label}")
        raise PytestMatrixError(
            f"missing report payload fields for {label}: {sorted(missing)}"
        )
    if extra:
        raise PytestMatrixError(
            f"unexpected report payload fields for {label}: {sorted(extra)}"
        )
    return data


def _require_report_entry(entry: object, *, label: str, index: int) -> dict[str, object]:
    if not isinstance(entry, dict):
        raise PytestMatrixError(
            f"invalid report entry for {label} at index {index}: {entry!r}"
        )
    expected_keys = {"nodeid", "when", "outcome", "wasxfail"}
    actual_keys = set(entry)
    missing = expected_keys - actual_keys
    extra = actual_keys - expected_keys
    if missing:
        raise PytestMatrixError(
            f"invalid report entry for {label} at index {index}: missing {sorted(missing)}"
        )
    if extra:
        raise PytestMatrixError(
            f"invalid report entry for {label} at index {index}: extra {sorted(extra)}"
        )
    nodeid = entry["nodeid"]
    when = entry["when"]
    outcome = entry["outcome"]
    wasxfail = entry["wasxfail"]
    if not isinstance(nodeid, str) or not nodeid:
        raise PytestMatrixError(
            f"invalid report nodeid for {label} at index {index}: {nodeid!r}"
        )
    if not isinstance(when, str):
        raise PytestMatrixError(
            f"invalid report phase for {label} at index {index}: {when!r}"
        )
    if not isinstance(outcome, str) or outcome not in {"passed", "failed", "skipped", "error"}:
        raise PytestMatrixError(
            f"invalid report outcome for {label} at index {index}: {outcome!r}"
        )
    if not isinstance(wasxfail, bool):
        raise PytestMatrixError(
            f"invalid report wasxfail for {label} at index {index}: {wasxfail!r}"
        )
    return entry


def run_pytest_matrix(
    *,
    repo: Path,
    expected_nodeids: Iterable[str],
    label: str,
    timeout_seconds: int = 240,
    extra_pytest_args: tuple[str, ...] = (),
) -> PytestMatrixResult:
    """Collect and run exactly ``expected_nodeids`` in a bounded pytest subprocess.

    The call fails closed if collection differs from the manifest, pytest deselects
    anything, any selected test skips/xfails/xpasses/errors/fails, the subprocess
    exits nonzero, or no selected node reaches a passing call report.
    """

    repo = repo.resolve()
    expected = _as_sorted_nodeids(expected_nodeids)
    with tempfile.TemporaryDirectory(prefix=f"{label}-") as tmp:
        tmp_path = Path(tmp)
        plugin = tmp_path / "ai_scan_matrix_plugin.py"
        report = tmp_path / "matrix-report.json"
        plugin.write_text(textwrap.dedent(_PLUGIN), encoding="utf-8")

        env = os.environ.copy()
        env["AI_SCAN_PYTEST_MATRIX_REPORT"] = str(report)
        pythonpath = env.get("PYTHONPATH")
        env["PYTHONPATH"] = (
            str(tmp_path) if not pythonpath else str(tmp_path) + os.pathsep + pythonpath
        )
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "ai_scan_matrix_plugin",
            "-q",
            "--tb=short",
            *extra_pytest_args,
            *expected,
        ]
        try:
            completed = subprocess.run(
                cmd,
                cwd=repo,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise PytestMatrixError(
                f"pytest subprocess timed out for {label} after {timeout_seconds}s"
            ) from exc
        if not report.is_file():
            raise PytestMatrixError(
                f"pytest subprocess failed before writing report for {label}: "
                f"exit={completed.returncode}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
            )
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise PytestMatrixError(f"invalid JSON report for {label}: {exc}") from exc

    data = _require_report_payload(data, label=label)
    collected_raw = data.get("collected", [])
    if not isinstance(collected_raw, list) or not all(
        isinstance(nodeid, str) and nodeid for nodeid in collected_raw
    ):
        raise PytestMatrixError(f"invalid collected nodes for {label}: {collected_raw!r}")
    collected = tuple(collected_raw)
    duplicate_collected = sorted(
        nodeid for nodeid, count in Counter(collected).items() if count > 1
    )
    if duplicate_collected:
        raise PytestMatrixError(
            f"duplicate collected nodes for {label}: {duplicate_collected}"
        )
    collected_set = set(collected)
    expected_set = set(expected)
    missing = expected_set - collected_set
    extra = collected_set - expected_set
    if missing:
        raise PytestMatrixError(
            f"missing expected nodes for {label}: {sorted(missing)}\n"
            f"exit={completed.returncode}\nSTDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    if extra:
        raise PytestMatrixError(f"unexpected collected nodes for {label}: {sorted(extra)}")
    deselected = _require_int_field(data, field="deselected")
    if deselected:
        raise PytestMatrixError(f"deselected nodes for {label}: {deselected}")
    exitstatus = _require_int_field(
        data, field="exitstatus", allowed_values={0, 1, 2, 3, 4, 5}
    )
    if exitstatus != completed.returncode:
        raise PytestMatrixError(
            f"pytest subprocess/report status mismatch for {label}: "
            f"returncode={completed.returncode} exitstatus={exitstatus}"
        )
    if exitstatus != 0:
        raise PytestMatrixError(
            f"pytest report failed for {label}: exitstatus={exitstatus}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    if tuple(sorted(collected)) != expected:
        raise PytestMatrixError(
            f"collected nodes for {label} did not match expected exactly: "
            f"expected={list(expected)} collected={list(collected)}"
        )

    reports_raw = data["reports"]
    if not isinstance(reports_raw, list):
        raise PytestMatrixError(f"invalid reports for {label}: {reports_raw!r}")
    reports = [
        _require_report_entry(report_entry, label=label, index=index)
        for index, report_entry in enumerate(reports_raw)
    ]
    bad: list[str] = []
    phase_reports: dict[str, dict[str, list[dict[str, object]]]] = {
        nodeid: {"setup": [], "call": [], "teardown": []} for nodeid in expected
    }
    for report_entry in reports:
        nodeid = report_entry["nodeid"]
        when = report_entry["when"]
        outcome = report_entry["outcome"]
        wasxfail = report_entry["wasxfail"]
        assert isinstance(nodeid, str)
        assert isinstance(when, str)
        if nodeid not in expected_set:
            bad.append(f"unexpected report node {nodeid!r} {when} {outcome}")
            continue
        if when not in {"setup", "call", "teardown"}:
            bad.append(f"unexpected report phase {nodeid} {when} {outcome}")
            continue
        if wasxfail:
            bad.append(f"{nodeid} {when} xfail/xpass")
        if outcome in {"failed", "error"}:
            bad.append(f"{nodeid} {when} {outcome}")
        if outcome == "skipped":
            bad.append(f"{nodeid} {when} skipped")
        phase_reports[nodeid][when].append(report_entry)

    passed_calls: list[str] = []
    for nodeid in expected:
        node_phase_reports = phase_reports[nodeid]
        complete_phase_set = True
        for phase in ("setup", "call", "teardown"):
            phase_entries = node_phase_reports[phase]
            if not phase_entries:
                bad.append(f"zero {phase} outcomes for {nodeid}")
                complete_phase_set = False
                continue
            if len(phase_entries) > 1:
                bad.append(f"multiple {phase} outcomes for {nodeid}: {len(phase_entries)}")
                complete_phase_set = False
                continue
            phase_report = phase_entries[0]
            if phase_report["outcome"] != "passed" or phase_report["wasxfail"]:
                bad.append(f"non-passing {phase} node: {nodeid} {phase_report['outcome']}")
                complete_phase_set = False
        if complete_phase_set:
            passed_calls.append(nodeid)

    not_executed = expected_set - set(passed_calls)
    if not_executed:
        bad.append(f"zero executed/non-passing call nodes: {sorted(not_executed)}")
    if bad:
        raise PytestMatrixError(f"pytest matrix {label} had non-passing results: {bad}")
    if completed.returncode != 0:
        raise PytestMatrixError(
            f"pytest subprocess failed for {label}: exit={completed.returncode}\n"
            f"STDOUT:\n{completed.stdout}\nSTDERR:\n{completed.stderr}"
        )
    if not passed_calls:
        raise PytestMatrixError(f"zero executed nodes for {label}")

    return PytestMatrixResult(
        collected=tuple(sorted(collected)),
        passed=len(passed_calls),
        stdout=completed.stdout,
        stderr=completed.stderr,
    )
