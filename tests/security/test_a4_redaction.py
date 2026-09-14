"""Phase A4 — request-body secret propagation and persistence redaction.

A credential value placed in a structured JSON/form *request body* must be
collected as a known secret before sending, so a loopback target that reflects
the body cannot leak it into the response, evidence, or exchange record. Run
checkpoints must recursively redact known/literal secrets before their atomic
write and stay mode 0600.
"""

from __future__ import annotations

import json
import os
import stat

from ai_scan.orchestration.checkpoint import Checkpoint, load_checkpoint, write_checkpoint_atomic
from ai_scan.targets import normalize_target
from ai_scan.transport import RequestController, Transport, TransportConfig
from ai_scan.transport.redaction import body_secret_values
from tests.conftest import MockRequest, MockResponse


def _echo(req: MockRequest) -> MockResponse:
    # Reflect the raw request body inside a JSON envelope (a vulnerable echo).
    payload = {"echoed": req.text}
    return MockResponse(
        status=200, body=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


# --- A4.1 request-body secret collection ---------------------------------------

def test_body_secret_values_collects_nested_json_and_form() -> None:
    js = json.dumps(
        {"outer": {"api_key": "SEC_NESTED"}, "password": "SEC_TOP", "note": "benign"}
    ).encode("utf-8")
    vals = body_secret_values(js, "application/json")
    assert "SEC_NESTED" in vals
    assert "SEC_TOP" in vals
    assert "benign" not in vals

    form = b"token=SEC_FORM&input=hello"
    vals2 = body_secret_values(form, "application/x-www-form-urlencoded")
    assert "SEC_FORM" in vals2
    assert "hello" not in vals2


def test_json_body_credential_is_redacted_from_reflected_response(mock_server) -> None:
    server = mock_server(_echo)
    target = normalize_target(f"{server.base_url}/v1/chat")
    transport = Transport(TransportConfig(), controller=RequestController(max_requests=4))
    resp = transport.send(
        target, method="POST", prompt="hi",
        body_template='{"api_key": "OPAQUEJSONSECRET", "input": "*"}',
    )
    assert "OPAQUEJSONSECRET" not in resp.body
    assert "OPAQUEJSONSECRET" in resp.known_secrets
    assert "OPAQUEJSONSECRET" not in json.dumps(resp.evidence())
    assert "OPAQUEJSONSECRET" not in json.dumps(resp.to_record().to_dict())


def test_form_body_credential_is_redacted_from_reflected_response(mock_server) -> None:
    server = mock_server(_echo)
    target = normalize_target(f"{server.base_url}/v1/chat")
    transport = Transport(TransportConfig(), controller=RequestController(max_requests=4))
    resp = transport.send(
        target, method="POST", prompt="hi",
        body_template="token=OPAQUEFORMSECRET&input=*",
        prompt_encoding="url",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert "OPAQUEFORMSECRET" not in resp.body
    assert "OPAQUEFORMSECRET" in resp.known_secrets


# --- A4.2 checkpoint persistence redaction + 0600 -------------------------------

def test_run_plan_checkpoint_redacts_reflected_secret(tmp_path) -> None:
    # The real runner path: a reflected opaque secret observed during the run must
    # not land in the checkpoint file (known secrets threaded into persistence).
    import re

    from ai_scan.injection import ExchangeOutcome, InjectionCase
    from ai_scan.orchestration import compile_plan, run_plan
    from ai_scan.targets import normalize_target

    secret = "opaqueReflectedRunSecret"  # pragma: allowlist secret
    plan = compile_plan(normalize_target("http://127.0.0.1:9/chat"), "reliable")
    checkpoint_path = str(tmp_path / "run.ckpt")

    def responder(case: InjectionCase) -> ExchangeOutcome:
        match = re.search(r"AISCAN-\S+", case.rendered_prompt)
        canary = match.group(0) if match else "AISCAN-x"
        # Target reflects the canary right next to an opaque credential value.
        return ExchangeOutcome(
            body=f"start {canary} {secret} end", known_secrets=frozenset({secret})
        )

    run_plan(plan, responder, canary="AISCAN-RUNCANARY", checkpoint_path=checkpoint_path)

    on_disk = open(checkpoint_path, encoding="utf-8").read()  # noqa: SIM115
    assert secret not in on_disk


def test_checkpoint_redacts_secrets_before_write_and_is_0600(tmp_path) -> None:
    secret = "opaqueRunSecretValue"  # pragma: allowlist secret
    digest_like = "d" * 64
    checkpoint = Checkpoint(
        plan_digest=digest_like,
        state="running",
        request_count=1,
        completed={
            "c1": {
                "family": "fam",
                "status": "potential",
                "prompt": "please disclose {canary}",
                "proof": f"model leaked {secret} and sk-ABCDEFGHIJKLMNOP here",
                "kind": "attack",
                "attack_trials": 1,
                "successes": 0,
            }
        },
        control_results={"fam": "clean"},
    )
    path = str(tmp_path / "run.ckpt")
    write_checkpoint_atomic(path, checkpoint, known_secrets=frozenset({secret}))

    on_disk = open(path, encoding="utf-8").read()  # noqa: SIM115
    assert secret not in on_disk
    assert "sk-ABCDEFGHIJKLMNOP" not in on_disk
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    # The scrubbed checkpoint still loads (digest sealed over the scrubbed body).
    loaded = load_checkpoint(path, expected_plan_digest=digest_like)
    assert loaded.completed["c1"]["status"] == "potential"
