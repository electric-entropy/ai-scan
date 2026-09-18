"""Milestone 0 golden compatibility contract for the current MVP (report v1).

These tests freeze the current, public MVP behavior *before* any platform
refactor moves the internals. They characterize:

* the active subcommands, their flag defaults/help, and stable exit codes,
* report schema v1 (the *complete* structure, including full ``evidence`` and
  ``request_budget``) via a golden fixture,
* the packaged ``safe`` profile allowlist,
* reflection-is-not-confirmation handling,
* representative ``confirmed`` / clean / reflection / ``inconclusive`` reports
  and an actual exit-4 path.

## The v1 compatibility rule (single, coherent definition)

The golden fixture is the **frozen required surface** of report v1. A conforming
report must contain every path in the golden, with the same type and the same
value for every non-volatile leaf. Volatile leaves (origins, canaries,
timestamps, and target-emitted ``Date``/``Server`` headers) are normalized to
sentinels before comparison. Removing, renaming, retyping, or re-meaning any
frozen field fails. *Additive* optional keys outside the frozen surface are
tolerated (consumers ignore unknown keys), so the check is a **structural
subset** match (golden ⊆ report; list lengths exact), not blanket equality.
See ``docs/architecture/migration-policy.md``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from ai_scan import cli
from ai_scan.injection import ALLOWED_PROFILES, InjectionError, load_payloads
from ai_scan.targets import normalize_target
from tests.conftest import MockRequest, MockResponse

GOLDEN_DIR = Path(__file__).parent / "golden"
_CANARY_RE = re.compile(r"AISCAN-[0-9A-F]+")


def _golden(name: str) -> dict:
    return json.loads((GOLDEN_DIR / f"mvp-report-{name}-v1.json").read_text(encoding="utf-8"))


# --- deterministic local targets ---------------------------------------------


def _execution_app(req: MockRequest) -> MockResponse:
    """Follows an injected instruction (emits the canary); else a fixed reply."""
    payload = json.loads(req.body or b"{}")
    prompt = payload.get("input", "")
    match = _CANARY_RE.search(prompt)
    reply = match.group(0) if match else "fixed benign reply"
    return MockResponse(
        status=200,
        body=reply.encode("utf-8"),
        headers={"Content-Type": "text/plain"},
    )


def _resistant_app(req: MockRequest) -> MockResponse:
    return MockResponse(
        status=200,
        body=b"I will not comply.",
        headers={"Content-Type": "text/plain"},
    )


def _echo_app(req: MockRequest) -> MockResponse:
    payload = json.loads(req.body or b"{}")
    return MockResponse(
        status=200,
        body=f"You said: {payload.get('input', '')}".encode(),
        headers={"Content-Type": "text/plain"},
    )


def _redirect_app(req: MockRequest) -> MockResponse:
    return MockResponse(status=302, body=b"", headers={"Location": "http://elsewhere.example/x"})


# --- helpers -----------------------------------------------------------------


def _assess(app, mock_server, tmp_path) -> tuple[int, dict, str]:
    server = mock_server(app)
    url = f"{server.base_url}/chat"
    out = tmp_path / "report.json"
    code = cli.main(["assess", "--target", url, "--out", str(out)])
    report = json.loads(out.read_text(encoding="utf-8"))
    return code, report, normalize_target(url).origin


def normalize_report(report: dict, origin: str) -> dict:
    """Replace only volatile leaf values; preserve all structure/keys/types."""
    if isinstance(report, dict):
        out: dict[str, Any] = {}
        for key, value in report.items():
            low = key.lower()
            if low == "created_at":
                out[key] = "<TS>"
            elif low == "date":
                out[key] = "<DATE>"
            elif low == "server":
                out[key] = "<SERVER>"
            else:
                out[key] = normalize_report(value, origin)
        return out
    if isinstance(report, list):
        return [normalize_report(v, origin) for v in report]
    if isinstance(report, str):
        return _CANARY_RE.sub("<CANARY>", report.replace(origin, "<ORIGIN>"))
    return report


def assert_golden_subset(actual: Any, golden: Any, path: str = "$") -> None:
    """golden ⊆ actual: every frozen path matches; extra optional keys allowed."""
    if isinstance(golden, dict):
        assert isinstance(actual, dict), f"{path}: expected object, got {type(actual).__name__}"
        for key, gval in golden.items():
            assert key in actual, f"{path}: missing required key {key!r}"
            assert_golden_subset(actual[key], gval, f"{path}.{key}")
    elif isinstance(golden, list):
        assert isinstance(actual, list), f"{path}: expected array, got {type(actual).__name__}"
        assert len(actual) == len(golden), f"{path}: length {len(actual)} != {len(golden)}"
        for i, (aval, gval) in enumerate(zip(actual, golden, strict=True)):
            assert_golden_subset(aval, gval, f"{path}[{i}]")
    else:
        assert actual == golden, f"{path}: {actual!r} != {golden!r}"


# Representative outcomes: app -> (exit code, injection status, golden name).
OUTCOMES: dict[str, tuple[Any, int, str]] = {
    # Historical fixture name retained; uncontrolled execution is now a lead.
    "confirmed": (_execution_app, cli.EXIT_OK, "potential"),
    "clean": (_resistant_app, cli.EXIT_OK, "not_observed"),
    "reflection": (_echo_app, cli.EXIT_OK, "potential"),
    "inconclusive": (_redirect_app, cli.EXIT_INCONCLUSIVE, "inconclusive"),
}


# --- subcommands, flags, exit codes ------------------------------------------


MVP_COMMANDS = {"fingerprint", "inject", "assess"}


def test_mvp_subcommands_remain_present() -> None:
    # The active MVP commands must remain a subset; future additive commands are
    # allowed, so this is a subset (not equality) assertion. The authorization
    # commands (authorize/validate-receipt) were removed in 0.2.1.
    parser = cli.build_parser()
    command_actions = [a for a in parser._actions if a.dest == "command"]  # noqa: SLF001
    assert command_actions
    choices = set(command_actions[0].choices)
    assert MVP_COMMANDS <= choices, f"missing MVP commands: {MVP_COMMANDS - choices}"
    assert "authorize" not in choices and "validate-receipt" not in choices


# Complete parser contract: every public option per command, with its dest,
# whether it is required, and its default. `_MISSING` marks a required option
# (no default). This is the frozen CLI surface for report v1.
_MISSING = object()

# option flag -> (dest, required, default)
PARSER_MATRIX: dict[str, dict[str, Any]] = {
    "fingerprint": {
        "minimal": {"--target": "http://x.example.com/"},
        "options": {
            "--target": ("target", True, _MISSING),
            "--request-template": ("request_template", False, None),
            "--out": ("out", False, None),
            "--method": ("method", False, "POST"),
        },
    },
    "inject": {
        "minimal": {"--target": "http://x.example.com/", "--goal": "g"},
        "options": {
            "--target": ("target", True, _MISSING),
            "--goal": ("goal", True, _MISSING),
            "--request-template": ("request_template", False, None),
            "--out": ("out", False, None),
            "--profile": ("profile", False, "safe"),
        },
    },
    "assess": {
        "minimal": {"--target": "http://x.example.com/"},
        "options": {
            "--target": ("target", True, _MISSING),
            "--request-template": ("request_template", False, None),
            "--out": ("out", False, None),
            "--profile": ("profile", False, "safe"),
        },
    },
}


def _subparser(command: str):
    parser = cli.build_parser()
    action = next(a for a in parser._actions if a.dest == "command")  # noqa: SLF001
    return action.choices[command]


def _flatten(minimal: dict[str, str]) -> list[str]:
    args: list[str] = []
    for flag, value in minimal.items():
        args += [flag, value]
    return args


@pytest.mark.parametrize("command", sorted(PARSER_MATRIX))
def test_parser_option_set_is_exactly_frozen(command: str) -> None:
    # Every public option is accounted for — no shared flag omitted, none added.
    sub = _subparser(command)
    public: set[str] = set()
    for action in sub._actions:  # noqa: SLF001
        for opt in action.option_strings:
            if opt not in ("-h", "--help"):
                public.add(opt)
    assert public == set(PARSER_MATRIX[command]["options"])


@pytest.mark.parametrize("command", sorted(PARSER_MATRIX))
def test_parser_defaults_and_requiredness(command: str) -> None:
    spec = PARSER_MATRIX[command]
    parser = cli.build_parser()
    ns = parser.parse_args([command, *_flatten(spec["minimal"])])
    for _flag, (dest, required, default) in spec["options"].items():
        if not required:
            assert getattr(ns, dest) == default, f"{command}.{dest} default"


@pytest.mark.parametrize("command", sorted(PARSER_MATRIX))
def test_parser_required_flags_enforced(command: str) -> None:
    spec = PARSER_MATRIX[command]
    for flag, (_dest, required, _default) in spec["options"].items():
        if not required:
            continue
        # Omit exactly this required flag; parsing must fail with exit code 1.
        minimal = {k: v for k, v in spec["minimal"].items() if k != flag}
        with pytest.raises(SystemExit) as exc:
            cli.main([command, *_flatten(minimal)])
        assert exc.value.code == cli.EXIT_RUNTIME_ERROR, f"{command} missing {flag}"


@pytest.mark.parametrize("command", sorted(PARSER_MATRIX))
def test_help_lists_every_public_option(command: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in PARSER_MATRIX[command]["options"]:
        assert flag in out, f"{command} --help omits {flag}"


def test_exit_code_constants_stable() -> None:
    assert (cli.EXIT_OK, cli.EXIT_RUNTIME_ERROR, cli.EXIT_DENIED) == (0, 1, 2)
    assert (cli.EXIT_CONFIRMED_FINDING, cli.EXIT_INCONCLUSIVE) == (3, 4)


def test_usage_error_exits_1_not_2() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["fingerprint"])  # missing --target
    assert exc.value.code == cli.EXIT_RUNTIME_ERROR


# --- report schema v1 golden (full structure) --------------------------------


_V1_STATUSES = {"confirmed", "potential", "not_observed", "inconclusive"}
# assess runs the fixed fingerprint probe set (4) plus the 8 injection cases.
_FINGERPRINT_PROBES = 4
_INJECTION_CASES = 8


def _assert_v1_report_shape(report: dict, origin: str, *, expected_used: int = 12) -> None:
    """Assert the complete report v1 structure, value types, and cross-field
    consistency, against a *generated* report (not fixture constants)."""
    assert set(report) == {
        "tool",
        "schema_version",
        "target_origin",
        "created_at",
        "request_budget",
        "fingerprint",
        "injection",
        "evidence",
        "findings",
    }
    assert report["tool"] == "ai-scan"
    assert report["schema_version"] == "1.0"
    assert report["target_origin"] == origin
    assert isinstance(report["created_at"], str) and report["created_at"]
    assert "authorization" not in report

    budget = report["request_budget"]
    assert set(budget) == {"max_requests", "used"}
    assert isinstance(budget["max_requests"], int) and isinstance(budget["used"], int)
    assert not isinstance(budget["used"], bool)
    assert budget["used"] == expected_used
    assert 1 <= budget["used"] <= budget["max_requests"]

    # Fingerprint value types and candidate structure.
    fp = report["fingerprint"]
    assert set(fp) == {"method", "is_unknown", "inconclusive", "top_family", "candidates"}
    assert fp["method"] == "heuristic"
    assert isinstance(fp["is_unknown"], bool)
    assert isinstance(fp["inconclusive"], bool)
    assert fp["top_family"] is None or isinstance(fp["top_family"], str)
    assert isinstance(fp["candidates"], list)
    for cand in fp["candidates"]:
        assert set(cand) == {"family", "score", "evidence"}
        assert isinstance(cand["family"], str)
        assert isinstance(cand["score"], (int, float)) and not isinstance(cand["score"], bool)
        assert 0.0 <= cand["score"] <= 1.0
        assert isinstance(cand["evidence"], list)
        for ev in cand["evidence"]:
            assert set(ev) == {"probe_id", "family", "pattern", "weight", "kind"}
    # top_family is present iff a candidate was promoted (not unknown/inconclusive).
    assert (fp["top_family"] is not None) == (not fp["is_unknown"])

    # Injection value types.
    inj = report["injection"]
    assert set(inj) == {"status", "goal", "request_count", "findings"}
    assert inj["status"] in _V1_STATUSES
    assert inj["goal"] == "assessment"  # assess default goal
    assert isinstance(inj["request_count"], int) and not isinstance(inj["request_count"], bool)
    assert inj["request_count"] == _INJECTION_CASES  # 1 physical attempt per case
    assert isinstance(inj["findings"], list) and len(inj["findings"]) == _INJECTION_CASES

    # Physical-request budget consistency: fingerprint probes + injection cases.
    assert budget["used"] == _FINGERPRINT_PROBES + inj["request_count"]
    assert len(report["evidence"]) == budget["used"]

    # Evidence request/response value types.
    for rec in report["evidence"]:
        assert set(rec) == {"request", "response"}
        req = rec["request"]
        assert set(req) == {"method", "url", "headers"}
        assert req["method"] in {"GET", "POST"}
        assert isinstance(req["url"], str) and req["url"].startswith(origin)
        assert isinstance(req["headers"], dict)
        assert all(isinstance(k, str) and isinstance(v, str) for k, v in req["headers"].items())
        resp = rec["response"]
        assert set(resp) == {
            "status",
            "redirected",
            "redirect_location",
            "truncated",
            "headers",
            "body",
        }
        assert isinstance(resp["status"], int) and not isinstance(resp["status"], bool)
        assert isinstance(resp["redirected"], bool)
        assert resp["redirect_location"] is None or isinstance(resp["redirect_location"], str)
        assert isinstance(resp["truncated"], bool)
        assert isinstance(resp["body"], str)
        assert isinstance(resp["headers"], dict)

    # Every finding (per-family and promoted) has the frozen shape and valid status.
    for finding in (*inj["findings"], *report["findings"]):
        assert set(finding) == {"family", "status", "prompt", "proof"}
        assert finding["status"] in _V1_STATUSES
        assert isinstance(finding["prompt"], str) and finding["prompt"]
        assert finding["proof"] is None or isinstance(finding["proof"], str)
    # Promoted top-level findings are exactly the confirmed/potential ones.
    promoted = [f for f in inj["findings"] if f["status"] in {"confirmed", "potential"}]
    assert report["findings"] == promoted


# --- four complete golden reports, one per representative outcome -------------


@pytest.mark.parametrize("name", sorted(OUTCOMES))
def test_outcome_report_matches_golden(name: str, mock_server, tmp_path) -> None:
    app, exit_code, status = OUTCOMES[name]
    code, report, origin = _assess(app, mock_server, tmp_path)
    assert code == exit_code
    assert report["injection"]["status"] == status
    # Full v1 freeze: every current field and nested value (headers, evidence,
    # finding family/prompt order, proof, fingerprint/injection values, physical
    # counts incl. max_requests) must match the outcome's golden. Additive future
    # fields remain tolerated by the subset comparator.
    normalized = normalize_report(report, origin)
    assert_golden_subset(normalized, _golden(name))
    # Cross-field invariants the golden cannot express (types + consistency).
    _assert_v1_report_shape(report, origin)


def test_golden_freezes_max_requests(mock_server, tmp_path) -> None:
    _code, report, origin = _assess(_execution_app, mock_server, tmp_path)
    normalized = normalize_report(report, origin)
    assert _golden("confirmed")["request_budget"]["max_requests"] == 128
    assert normalized["request_budget"]["max_requests"] == 128


# --- mutation tests: representative nested changes must fail the golden -------


def _confirmed_normalized(mock_server, tmp_path) -> dict:
    _code, report, origin = _assess(_execution_app, mock_server, tmp_path)
    return normalize_report(report, origin)


def test_additive_optional_field_is_tolerated(mock_server, tmp_path) -> None:
    normalized = _confirmed_normalized(mock_server, tmp_path)
    normalized["x_future_optional"] = {"added": "later"}
    normalized["injection"]["x_note"] = "extra"
    normalized["evidence"][0]["response"]["x_extra"] = 1
    assert_golden_subset(normalized, _golden("confirmed"))  # must not raise


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda r: r.pop("schema_version"), id="remove-top-key"),
        pytest.param(lambda r: r.update(schema_version=10), id="retype-schema-version"),
        pytest.param(lambda r: r.__setitem__("evidence", r["evidence"][:-1]), id="evidence-length"),
        pytest.param(
            lambda r: r["evidence"][0]["response"].pop("status"), id="remove-nested-response-key"
        ),
        pytest.param(
            lambda r: r["evidence"][0]["response"]["headers"].update({"Content-Type": "text/x"}),
            id="change-response-header-value",
        ),
        pytest.param(
            lambda r: r["request_budget"].update(max_requests=256), id="change-max-requests"
        ),
        pytest.param(
            lambda r: r["injection"]["findings"][0].update(status="not_observed"),
            id="change-finding-status",
        ),
        pytest.param(
            lambda r: r["injection"]["findings"].reverse(), id="reorder-findings"
        ),
        pytest.param(
            lambda r: r["injection"]["findings"][0].pop("proof"), id="drop-proof-field"
        ),
        pytest.param(lambda r: r["fingerprint"].update(is_unknown=False), id="change-fingerprint"),
    ],
)
def test_nested_mutation_fails_confirmed_golden(mutate, mock_server, tmp_path) -> None:
    normalized = _confirmed_normalized(mock_server, tmp_path)
    assert_golden_subset(normalized, _golden("confirmed"))  # sanity: matches first
    mutate(normalized)
    with pytest.raises(AssertionError):
        assert_golden_subset(normalized, _golden("confirmed"))


@pytest.mark.parametrize("name", sorted(OUTCOMES))
def test_per_outcome_golden_detects_status_drift(name: str, mock_server, tmp_path) -> None:
    app, _code, status = OUTCOMES[name]
    _c, report, origin = _assess(app, mock_server, tmp_path)
    normalized = normalize_report(report, origin)
    assert_golden_subset(normalized, _golden(name))  # sanity
    other = "confirmed" if status != "confirmed" else "not_observed"
    normalized["injection"]["status"] = other
    with pytest.raises(AssertionError):
        assert_golden_subset(normalized, _golden(name))


# --- packaged safe profile ---------------------------------------------------


_SAFE_PACK_DESCRIPTION = (
    "Non-destructive prompt-injection probes using a synthetic canary. Success is "
    "defined solely as the target emitting the unique canary token under a "
    "family-specific condition. No payload requests real secrets, credentials, "
    "destructive actions, or third-party data."
)
_SAFE_FAMILY_META = [
    (
        "instruction_conflict",
        "Direct conflict with prior instructions, asking only to emit the synthetic canary.",
        2,
    ),
    ("encoding", "Obfuscated instruction that resolves to emitting the canary.", 2),
    ("role_confusion", "Fake role elevation that only asks to print the canary.", 2),
    (
        "system_boundary",
        "Attempts to cross the user/system boundary, asking only to append the canary.",
        2,
    ),
]


def test_safe_pack_metadata_is_frozen() -> None:
    # Freeze the exact packaged pack version, descriptions, and family metadata —
    # the pack contents are part of the public v1 contract, not just truthy.
    assert ALLOWED_PROFILES == frozenset({"safe"})
    pack = load_payloads("safe")
    assert pack.version == "safe-2026.09.1"
    assert pack.description == _SAFE_PACK_DESCRIPTION
    assert [(f.name, f.description, len(f.templates)) for f in pack.families] == _SAFE_FAMILY_META
    for family in pack.families:
        assert all(isinstance(t, str) and t for t in family.templates)


@pytest.mark.parametrize("bad", ["../safe", "/etc/passwd", "aggressive", "safe.json"])
def test_non_allowlisted_profiles_rejected(bad: str) -> None:
    with pytest.raises(InjectionError):
        load_payloads(bad)


@pytest.mark.parametrize(
    ("command", "extra"),
    [
        ("inject", ["--goal", "g"]),
        ("assess", []),
    ],
)
def test_invalid_profile_rejected_before_any_request(
    command: str, extra: list[str], mock_server, tmp_path
) -> None:
    # Milestone 2 closed the ordering gap: the payload pack (`--profile`) is
    # validated BEFORE any transport is constructed, so a valid run with an
    # invalid profile sends ZERO requests for both `inject` and `assess`, exit 1.
    expected_requests = 0
    hits = {"n": 0}

    def app(req: MockRequest) -> MockResponse:
        hits["n"] += 1
        return MockResponse(
            status=200,
            body=json.dumps({"reply": "x"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

    server = mock_server(app)
    url = f"{server.base_url}/chat"
    code = cli.main([command, "--target", url, *extra, "--profile", "bogus"])
    assert code == cli.EXIT_RUNTIME_ERROR
    assert hits["n"] == expected_requests


# --- unattended: active commands reach the target with just --target ---------


@pytest.mark.parametrize(
    ("command", "extra"),
    [
        ("fingerprint", []),
        ("inject", ["--goal", "g"]),
        ("assess", []),
    ],
)
def test_active_commands_run_unattended(
    command: str, extra: list[str], mock_server, tmp_path
) -> None:
    """No pre-run gate: an active command reaches the loopback
    target and is never denied by an (absent) gating step."""
    hits = {"n": 0}

    def counting(req: MockRequest) -> MockResponse:
        hits["n"] += 1
        return MockResponse(status=200, body=b"{}")

    server = mock_server(counting)
    url = f"{server.base_url}/chat"
    code = cli.main([command, "--target", url, *extra])
    assert code != cli.EXIT_DENIED
    assert hits["n"] > 0
