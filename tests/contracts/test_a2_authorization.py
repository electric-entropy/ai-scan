"""Phase A2 — Kitchen Sink authorization gates and CLI exception scrubbing."""

from __future__ import annotations

import json

from ai_scan import cli
from ai_scan.authorization import Receipt, confirmation_phrase, write_receipt
from ai_scan.targets import normalize_target
from tests.conftest import MockResponse


def _receipt(tmp_path, url: str) -> str:
    path = tmp_path / "auth.json"
    write_receipt(
        Receipt.create(
            target=normalize_target(url), client="C", engagement="E", expires="2999-01-01"
        ),
        str(path),
    )
    return str(path)


class _Script:
    """A scripted prompt callable recording the messages it was shown."""

    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, message: str) -> str:
        self.prompts.append(message)
        return self._answers.pop(0) if self._answers else ""


def _ks_plan(tmp_path, url: str) -> tuple[str, int]:
    plan_path = tmp_path / "ks-plan.json"
    assert cli.main(
        ["plan", "--target", url, "--mode", "kitchen-sink", "--out", str(plan_path)]
    ) == cli.EXIT_OK
    budget = json.loads(plan_path.read_text(encoding="utf-8"))["limits"][0]
    return str(plan_path), int(budget)


# --- A2.1 / A2.3 receipt presence cannot bypass Kitchen Sink --------------------

def test_receipt_cannot_run_kitchen_sink_without_non_interactive_flag(
    mock_server, tmp_path, monkeypatch
) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, _ = _ks_plan(tmp_path, url)
    receipt = _receipt(tmp_path, url)
    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))

    # No --non-interactive: a v1 receipt must STILL not authorize kitchen-sink.
    rc = cli.main(["run", "--target", url, "--plan", plan_path, "--auth-receipt", receipt])
    assert rc == cli.EXIT_AUTH_DENIED
    assert constructed["n"] == 0


# --- A2.2 interactive Kitchen Sink requires a second confirmation ---------------

def test_interactive_kitchen_sink_requires_second_confirmation(
    mock_server, tmp_path, monkeypatch
) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, budget = _ks_plan(tmp_path, url)
    origin = normalize_target(url).origin
    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))

    # Correct origin phrase, but a wrong second (kitchen-sink) phrase → denied.
    script = _Script([confirmation_phrase(normalize_target(url)), "not the phrase"])
    rc = cli.main(["run", "--target", url, "--plan", plan_path], prompt=script)
    assert rc == cli.EXIT_AUTH_DENIED
    assert constructed["n"] == 0
    # Two prompts: origin phrase, then the kitchen-sink confirmation naming the
    # mode and the maximum physical request budget.
    assert len(script.prompts) == 2
    assert "kitchen-sink" in script.prompts[1]
    assert str(budget) in script.prompts[1]
    assert origin in script.prompts[0]


# --- A1.4 plan-bound receipt authorizes Kitchen Sink; mismatch rejected ---------

def _plan_bound_receipt(tmp_path, url: str, plan_digest: str) -> str:
    path = tmp_path / "pb.json"
    write_receipt(
        Receipt.create(
            target=normalize_target(url), client="C", engagement="E",
            expires="2999-01-01", plan_digest=plan_digest,
        ),
        str(path),
    )
    return str(path)


def _reliable_plan(tmp_path, url: str) -> tuple[str, int]:
    plan_path = tmp_path / "reliable-plan.json"
    assert cli.main(["plan", "--target", url, "--out", str(plan_path)]) == cli.EXIT_OK
    digest = json.loads(plan_path.read_text(encoding="utf-8"))["digest"]
    return str(plan_path), digest


def test_origin_only_receipt_cannot_run_reliable(mock_server, tmp_path, monkeypatch) -> None:
    # Blocker 1: an origin-only receipt must NOT authorize a reliable plan run;
    # fail closed before any transport is constructed.
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, _digest = _reliable_plan(tmp_path, url)
    receipt = _receipt(tmp_path, url)  # origin-only, no plan binding
    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))

    rc = cli.main(["run", "--target", url, "--plan", plan_path, "--auth-receipt", receipt,
                   "--non-interactive"])
    assert rc != cli.EXIT_OK
    assert constructed["n"] == 0  # rejected before transport


def test_receipt_bound_to_wrong_target_cannot_run(mock_server, tmp_path, monkeypatch) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, digest = _reliable_plan(tmp_path, url)
    # Correct plan digest, but bound to a different exact target (path).
    receipt = _plan_bound_receipt(tmp_path, f"{server.base_url}/other", digest)
    constructed = {"n": 0}
    monkeypatch.setattr(cli, "_make_transport", lambda c: constructed.__setitem__("n", 1))
    rc = cli.main(["run", "--target", url, "--plan", plan_path, "--auth-receipt", receipt,
                   "--non-interactive"])
    assert rc != cli.EXIT_OK
    assert constructed["n"] == 0


def test_plan_bound_receipt_authorizes_reliable_run(mock_server, tmp_path) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, digest = _reliable_plan(tmp_path, url)
    receipt = _plan_bound_receipt(tmp_path, url, digest)
    rc = cli.main(["run", "--target", url, "--plan", plan_path, "--auth-receipt", receipt,
                   "--non-interactive"])
    assert rc != cli.EXIT_AUTH_DENIED  # a correctly plan-bound receipt authorizes


def test_plan_bound_receipt_authorizes_kitchen_sink(mock_server, tmp_path) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, _ = _ks_plan(tmp_path, url)
    plan_digest = json.loads(open(plan_path, encoding="utf-8").read())["digest"]  # noqa: SIM115
    receipt = _plan_bound_receipt(tmp_path, url, plan_digest)
    rc = cli.main(
        ["run", "--target", url, "--plan", plan_path, "--auth-receipt", receipt,
         "--non-interactive"]
    )
    # Authorization is NOT denied for a correctly plan-bound Kitchen Sink receipt.
    assert rc != cli.EXIT_AUTH_DENIED


def test_receipt_bound_to_different_plan_is_rejected(mock_server, tmp_path) -> None:
    server = mock_server(lambda _req: MockResponse(status=200, body=b"{}"))
    url = f"{server.base_url}/chat"
    plan_path, _ = _ks_plan(tmp_path, url)
    receipt = _plan_bound_receipt(tmp_path, url, "e" * 64)  # wrong plan digest
    rc = cli.main(
        ["run", "--target", url, "--plan", plan_path, "--auth-receipt", receipt,
         "--non-interactive"]
    )
    assert rc == cli.EXIT_AUTH_DENIED  # blocked before transport


# --- A2.4 CLI exception sinks scrub secret-bearing text -------------------------

def test_validate_config_missing_file_error_scrubs_secret_path(tmp_path, capsys) -> None:
    secret_path = str(tmp_path / "sk-ABCDEFGHIJKLMNOPQRS.json")  # nonexistent, secret-like
    rc = cli.main(["validate-config", "--file", secret_path, "--kind", "plan"])
    out = capsys.readouterr()
    assert rc == cli.EXIT_RUNTIME_ERROR
    assert "sk-ABCDEFGHIJKLMNOPQRS" not in out.out
    assert "sk-ABCDEFGHIJKLMNOPQRS" not in out.err
