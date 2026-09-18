"""Real console-script plans and scans against independent loopback state.

AI_SCAN_FIXTURE_EXECUTABLE selects a freshly installed console script; the
subprocess cwd is outside the repo and PYTHONPATH is removed in every run.
"""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.llm07_fixture import SystemPromptFixture

MARKER = "AISCAN-9127AED481FA635BD80247CF6139BE50"


def spellings(value):
    raw = value.encode()
    return {value, raw.hex(), raw.hex().upper(),
            "".join(f"%{b:02X}" for b in raw),
            "".join(f"\\u{ord(c):04x}" for c in value),
            "".join(f"\\x{b:02x}" for b in raw),
            base64.b64encode(raw).decode(), base64.b64encode(raw).decode().rstrip("="),
            base64.urlsafe_b64encode(raw).decode().rstrip("=")}


def invoke(tmp_path, *args):
    executable = os.environ.get("AI_SCAN_FIXTURE_EXECUTABLE",
                                str(Path(sys.executable).with_name("ai-scan")))
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run([executable, *args], cwd=tmp_path, env=env,
                            capture_output=True, text=True, timeout=180)
    assert result.returncode in {0, 3}, result.stdout + result.stderr
    assert MARKER not in result.stdout + result.stderr
    return result


@pytest.mark.parametrize("mode", ["reliable", "kitchen-sink"])
@pytest.mark.parametrize("secure", [True, False])
def test_independent_system_prompt_public_cli(tmp_path, mode, secure):
    exercise(tmp_path, mode, secure, "final")


@pytest.mark.parametrize("channel", ["thinking", "refusal"])
def test_only_eligible_final_content_confirms(tmp_path, channel):
    exercise(tmp_path, "reliable", False, channel)


def exercise(tmp_path, mode, secure, channel):
    marker_path = tmp_path / "fixture-marker.txt"
    marker_path.write_text(MARKER + "\n")
    plan_path = tmp_path / "plan.json"
    report_path = tmp_path / "report.json"
    with SystemPromptFixture(MARKER, secure=secure, channel=channel) as server:
        invoke(tmp_path, "plan", "--target", server.url, "--mode", mode,
               "--adapter", "ollama", "--out", str(plan_path))
        plan = json.loads(plan_path.read_text())
        invoke(tmp_path, "run", "--target", server.url, "--plan", str(plan_path),
               "--model", "independent-fixture", "--synthetic-canary-file", str(marker_path),
               "--out", str(report_path))
    text = report_path.read_text()
    doc = json.loads(text)
    families = {row[2] for row in plan["cases"] if row[1] in {
        "system-prompt-leakage-reliable", "system-prompt-leakage-kitchen"}}
    findings = [f for f in doc["injection"]["findings"] if f["family"] in families]
    assert findings
    assert all((f["status"] == "confirmed") == (not secure and channel == "final")
               for f in findings)
    expected = sum(plan["trial_policy"][0 if c[4] == "attack" else 2] for c in plan["cases"])
    assert doc["request_budget"]["used"] == doc["request_budget"]["runner_count"]
    assert doc["request_budget"]["used"] == len(server.requests) == expected
    for path, headers, body in server.requests:
        request = path + repr(headers) + body
        assert not any(s in request for s in spellings(MARKER))
        # Meaningful proper fragments are absent as well. Single characters
        # cannot be absent from ordinary HTTP; every split's long side is checked.
        for split in range(1, len(MARKER)):
            fragment = max((MARKER[:split], MARKER[split:]), key=len)
            assert not any(s in request for s in spellings(fragment))
    assert not any(s in text for s in spellings(MARKER))
    if secure:
        assert MARKER not in server.outputs
    else:
        assert MARKER in server.outputs
