"""Bounded public-boundary regressions from the post-LLM10 review."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

import pytest

from ai_scan import cli
from ai_scan.adapters import ExtractionSpec, GenericHttpAdapter
from ai_scan.injection import ExchangeOutcome
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse


@pytest.fixture
def endpoint(monkeypatch):
    monkeypatch.setattr(cli, "_DEFAULT_MIN_INTERVAL", 0)
    state = {"mode": "plain", "hits": 0}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            state["hits"] += 1
            raw = self.rfile.read(int(self.headers["Content-Length"])).decode()
            match = re.search(r"AISCAN-[A-F0-9]{16}", raw)
            token = match.group() if match else "benign"
            mode = state["mode"]
            bodies = {
                "plain": token,
                "clean": "benign",
                "error": json.dumps({"error": {"message": token}}),
                "thinking": json.dumps({"message": {
                    "role": "assistant", "content": "I cannot comply", "thinking": token
                }, "done": False}),
                "metadata": json.dumps({"metadata": {"answer": token}}),
                "tool": json.dumps({"role": "tool", "content": token}),
                "malformed": '{"message": "' + token,
                "array": json.dumps([{"content": token}]),
                "encoded": json.dumps(json.dumps({"error": token})),
                "vertical_tab": "\v" + json.dumps({
                    "message": {"role": "assistant", "content": "benign", "thinking": token},
                    "done": False,
                }),
                "fenced_tilde": "~~~json\n" + json.dumps({"error": token}) + "\n~~~",
                "sse_comment": ": heartbeat\nevent: error\ndata: "
                + json.dumps({"error": token})
                + "\n\n",
                "percent_encoded": quote(json.dumps({"error": token})),
                "final": json.dumps({"message": {"role": "assistant", "content": token},
                                     "done": True, "done_reason": "stop"}),
            }
            body = bodies[mode].encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/chat", state
    server.shutdown()
    server.server_close()
    thread.join()


def invoke(command, target, tmp_path, *, adapter=None, checkpoint=None):
    out = tmp_path / "report.json"
    args = [command, "--target", target, "--out", str(out)]
    if command == "inject":
        args += ["--goal", "bounded regression"]
    if command == "run":
        plan = tmp_path / "plan.json"
        plan_args = ["plan", "--target", target, "--out", str(plan)]
        if adapter:
            plan_args += ["--adapter", adapter]
            args += ["--model", "local-fixture"]
        assert cli.main(plan_args) == 0
        args += ["--plan", str(plan)]
        if checkpoint:
            args += ["--checkpoint", str(checkpoint)]
    code = cli.main(args)
    return code, json.loads(out.read_text())


@pytest.mark.parametrize("command", ["inject", "assess", "run"])
@pytest.mark.parametrize(
    "mode", [
        "error", "thinking", "metadata", "tool", "malformed", "array", "encoded",
        "vertical_tab", "fenced_tilde", "sse_comment", "percent_encoded",
    ]
)
def test_generic_structured_response_is_inconclusive(endpoint, tmp_path, command, mode):
    target, state = endpoint
    state["mode"] = mode
    code, doc = invoke(command, target, tmp_path)
    assert code == 4
    assert doc["injection"]["status"] == "inconclusive"


@pytest.mark.parametrize(
    "mode,status,code", [("thinking", "inconclusive", 4), ("final", "confirmed", 3)]
)
def test_explicit_provider_semantics_preserved(endpoint, tmp_path, mode, status, code):
    target, state = endpoint
    state["mode"] = mode
    actual, doc = invoke("run", target, tmp_path, adapter="ollama")
    assert actual == code
    assert doc["injection"]["status"] == status


def test_plain_generic_controlled_run_can_confirm(endpoint, tmp_path):
    target, _ = endpoint
    code, doc = invoke("run", target, tmp_path)
    assert code == 3
    assert doc["injection"]["status"] == "confirmed"


@pytest.mark.parametrize("mode,path", [("json_pointer", "/metadata"), ("header", "X-Metadata")])
def test_generic_scalar_extraction_is_marked_ineligible_for_confirmation(mode, path):
    target = normalize_target("http://127.0.0.1:8000/chat")
    adapter = GenericHttpAdapter(target, extraction=ExtractionSpec(mode=mode, path=path))
    response = HttpResponse(
        status=200,
        body=json.dumps({"metadata": "AISCAN-0123456789ABCDEF"}),
        headers={"X-Metadata": "AISCAN-0123456789ABCDEF"},
        redirected=False,
        redirect_location=None,
        truncated=False,
        request_line={},
    )
    outcome = ExchangeOutcome(body=adapter.extract(response))
    assert outcome.transport_ok is False


@pytest.mark.parametrize("command", ["inject", "assess"])
def test_single_shot_is_only_an_analyst_lead(endpoint, tmp_path, command):
    target, _ = endpoint
    code, doc = invoke(command, target, tmp_path)
    assert code == 0
    assert doc["injection"]["status"] == "potential"
    assert all(f["status"] != "confirmed" for f in doc["injection"]["findings"])


def test_checkpoint_identity_rejection_is_explicit(endpoint, tmp_path, capsys):
    target, state = endpoint
    state["mode"] = "clean"
    checkpoint = tmp_path / "checkpoint.json"
    _, first = invoke("run", target, tmp_path, checkpoint=checkpoint)
    before = state["hits"]
    original = checkpoint.read_bytes()
    code, resumed = invoke("run", target, tmp_path, checkpoint=checkpoint)
    assert code == 4
    assert resumed["injection"]["status"] == "inconclusive"
    assert "checkpoint run identity mismatch" in capsys.readouterr().out
    budget = resumed["request_budget"]
    assert budget["used"] == budget["runner_count"] == first["injection"]["request_count"]
    assert budget["invocation_used"] == 0
    assert budget["reason"] == "checkpoint run identity mismatch"
    assert state["hits"] == before
    assert checkpoint.read_bytes() == original
