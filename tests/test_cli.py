"""CLI-level tests: help output, subcommand registration, exit codes."""

from __future__ import annotations

import subprocess
import sys
from importlib import metadata

import pytest

import ai_scan
from ai_scan import cli

SUBCOMMANDS = (
    "fingerprint",
    "inject",
    "assess",
    "plan",
    "run",
    "supply-chain-audit",
    "data-poisoning-audit",
    "output-handling-audit",
    "agency-audit",
)


def _run_module(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ai_scan", *args],
        capture_output=True,
        text=True,
    )


def test_module_help_succeeds_and_lists_all_subcommands() -> None:
    result = _run_module("--help")
    assert result.returncode == 0
    for name in SUBCOMMANDS:
        assert name in result.stdout


def test_help_via_main_lists_all_subcommands(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    for name in SUBCOMMANDS:
        assert name in captured.out


def test_no_command_returns_usage_error() -> None:
    exit_code = cli.main([])
    assert exit_code == cli.EXIT_RUNTIME_ERROR


def test_exit_code_constants_are_stable() -> None:
    assert cli.EXIT_OK == 0
    assert cli.EXIT_RUNTIME_ERROR == 1
    assert cli.EXIT_DENIED == 2
    assert cli.EXIT_CONFIRMED_FINDING == 3
    assert cli.EXIT_INCONCLUSIVE == 4


def test_source_tree_version_matches_package_metadata() -> None:
    assert ai_scan.__version__ == metadata.version("ai-scan") == "0.2.1"


def test_scope_denial_through_real_transport_maps_to_blocked(monkeypatch, capsys) -> None:
    # Real Transport.send() → broker → ScopeGuard SSRF block. Only the transport
    # construction seam is injected, to give the guard a resolver that returns a
    # private IP for the named host.
    from ai_scan.transport import RequestController, Transport, TransportConfig

    def fake_make(controller: RequestController) -> Transport:
        return Transport(
            TransportConfig(), controller=controller, resolver=lambda _h: ["169.254.169.254"]
        )

    monkeypatch.setattr(cli, "_make_transport", fake_make)
    rc = cli.main(["fingerprint", "--target", "http://scope.test/chat"])
    assert rc == cli.EXIT_DENIED
    out = capsys.readouterr().out
    assert "blocked:" in out and "physical attempts" in out


def test_budget_exhaustion_through_real_transport_maps_to_inconclusive(
    echo_server, monkeypatch, capsys
) -> None:
    # Real Transport.send() against a loopback mock, with a 1-request budget so
    # the second probe exhausts it and raises BudgetExceededError.
    from ai_scan.transport import RequestController, Transport, TransportConfig

    def fake_make(_controller: RequestController) -> Transport:
        tight = RequestController(max_requests=1, min_interval=0.0)
        return Transport(TransportConfig(), controller=tight)

    monkeypatch.setattr(cli, "_make_transport", fake_make)
    rc = cli.main(["fingerprint", "--target", f"{echo_server.base_url}/chat"])
    assert rc == cli.EXIT_INCONCLUSIVE
    out = capsys.readouterr().out
    assert "inconclusive:" in out and "physical attempts" in out


def test_argparse_missing_required_arg_exits_1() -> None:
    # argparse's own default is exit code 2, which collides with the denied code.
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["fingerprint"])  # missing required --target
    assert exc_info.value.code == cli.EXIT_RUNTIME_ERROR


def test_argparse_unknown_argument_exits_1() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["assess", "--target", "https://api.example.com/chat", "--bogus"])
    assert exc_info.value.code == cli.EXIT_RUNTIME_ERROR


def test_unknown_subcommand_exits_1() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["frobnicate"])
    assert exc_info.value.code == cli.EXIT_RUNTIME_ERROR
