"""CLI-level tests: help output, subcommand registration, exit codes."""

from __future__ import annotations

import subprocess
import sys

from ai_scan import cli

SUBCOMMANDS = ("authorize", "fingerprint", "inject", "assess", "validate-receipt")


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
    # argparse's --help action prints and raises SystemExit(0).
    import pytest

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
    assert cli.EXIT_AUTH_DENIED == 2
    assert cli.EXIT_CONFIRMED_FINDING == 3
    assert cli.EXIT_INCONCLUSIVE == 4


def test_authorize_creates_valid_receipt(tmp_path) -> None:
    out = tmp_path / "auth.json"
    target = "https://api.example.com:8443/chat"
    phrase = "I confirm I am authorized to assess https://api.example.com:8443"
    exit_code = cli.main(
        [
            "authorize",
            "--target",
            target,
            "--client",
            "Acme",
            "--engagement",
            "ENG-9",
            "--expires",
            "2999-01-01",
            "--out",
            str(out),
        ],
        prompt=lambda _msg: phrase,
    )
    assert exit_code == cli.EXIT_OK
    assert out.exists()
    # The created receipt validates non-interactively against the same target.
    rc = cli.main(["validate-receipt", "--auth-receipt", str(out), "--target", target])
    assert rc == cli.EXIT_OK


def test_authorize_denied_on_wrong_phrase(tmp_path) -> None:
    out = tmp_path / "auth.json"
    exit_code = cli.main(
        [
            "authorize",
            "--target",
            "https://api.example.com/chat",
            "--client",
            "Acme",
            "--engagement",
            "ENG-9",
            "--expires",
            "2999-01-01",
            "--out",
            str(out),
        ],
        prompt=lambda _msg: "nope",
    )
    assert exit_code == cli.EXIT_AUTH_DENIED
    assert not out.exists()


def test_non_interactive_without_receipt_exits_2() -> None:
    # Must fail closed before any transport/network work.
    exit_code = cli.main(
        ["fingerprint", "--target", "https://api.example.com/chat", "--non-interactive"],
        prompt=_should_not_prompt,
    )
    assert exit_code == cli.EXIT_AUTH_DENIED


def test_validate_receipt_wrong_target_exits_2(tmp_path) -> None:
    out = tmp_path / "auth.json"
    phrase = "I confirm I am authorized to assess https://api.example.com:8443"
    cli.main(
        [
            "authorize",
            "--target",
            "https://api.example.com:8443/chat",
            "--client",
            "Acme",
            "--engagement",
            "ENG-9",
            "--expires",
            "2999-01-01",
            "--out",
            str(out),
        ],
        prompt=lambda _msg: phrase,
    )
    rc = cli.main(
        ["validate-receipt", "--auth-receipt", str(out), "--target", "https://evil.example.com/chat"]
    )
    assert rc == cli.EXIT_AUTH_DENIED


def _should_not_prompt(_msg: str) -> str:
    raise AssertionError("prompt must not be called in non-interactive mode")


def _confirm_for(origin: str):
    return lambda _msg: f"I confirm I am authorized to assess {origin}"


def test_scope_denial_through_real_transport_maps_to_blocked(monkeypatch, capsys) -> None:
    # Real Transport.send() → broker → ScopeGuard SSRF block, not a monkeypatched
    # _run_active. Only the transport construction seam is injected, to give the
    # guard a resolver that returns a private IP for the named host.
    from ai_scan.transport import RequestController, Transport, TransportConfig

    def fake_make(controller: RequestController) -> Transport:
        return Transport(
            TransportConfig(), controller=controller, resolver=lambda _h: ["169.254.169.254"]
        )

    monkeypatch.setattr(cli, "_make_transport", fake_make)
    origin = "http://scope.test"
    rc = cli.main(["fingerprint", "--target", f"{origin}/chat"], prompt=_confirm_for(origin))
    assert rc == cli.EXIT_AUTH_DENIED
    out = capsys.readouterr().out
    assert "blocked:" in out and "physical attempts" in out


def test_budget_exhaustion_through_real_transport_maps_to_inconclusive(
    echo_server, monkeypatch, capsys
) -> None:
    # Real Transport.send() against a loopback mock, with a 1-request budget so
    # the second probe exhausts it and raises BudgetExceededError through the
    # real responder path.
    from ai_scan.transport import RequestController, Transport, TransportConfig

    def fake_make(_controller: RequestController) -> Transport:
        tight = RequestController(max_requests=1, min_interval=0.0)
        return Transport(TransportConfig(), controller=tight)

    monkeypatch.setattr(cli, "_make_transport", fake_make)
    origin = echo_server.base_url
    rc = cli.main(["fingerprint", "--target", f"{origin}/chat"], prompt=_confirm_for(origin))
    assert rc == cli.EXIT_INCONCLUSIVE
    out = capsys.readouterr().out
    assert "inconclusive:" in out and "physical attempts" in out


def test_argparse_missing_required_arg_exits_1() -> None:
    # argparse's own default is exit code 2, which collides with auth-denied.
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["fingerprint"])  # missing required --target
    assert exc_info.value.code == cli.EXIT_RUNTIME_ERROR


def test_argparse_unknown_argument_exits_1() -> None:
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["assess", "--target", "https://api.example.com/chat", "--bogus"])
    assert exc_info.value.code == cli.EXIT_RUNTIME_ERROR


def test_unknown_subcommand_exits_1() -> None:
    import pytest

    with pytest.raises(SystemExit) as exc_info:
        cli.main(["frobnicate"])
    assert exc_info.value.code == cli.EXIT_RUNTIME_ERROR
