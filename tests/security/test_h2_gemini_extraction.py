"""Step 1B / Astra H2 — Gemini extracts only eligible final model text.

Confirmation evidence from a Gemini ``generateContent`` response may come only
from the single candidate's final ``model`` text parts. Thought/reasoning parts,
request echoes, envelope metadata, and provider errors are never evidence, and
invalid roles, provider errors, unsupported or truncated shapes fail closed (an
unusable exchange, never a confirmation). The CLI tests drive the real ``run``
path against a loopback Gemini-shaped provider.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from ai_scan import cli
from ai_scan.adapters import ExtractionError, GeminiAdapter
from ai_scan.core.models import FindingStatus
from ai_scan.orchestration import compile_plan, plan_to_json
from ai_scan.targets import normalize_target
from ai_scan.transport import HttpResponse, RequestController
from ai_scan.validation import ExactCanaryValidator, GatingContext, classify
from ai_scan.validation.base import Evidence
from tests.conftest import MockRequest, MockResponse

_TARGET = normalize_target("http://127.0.0.1:8080/v1beta/models/gemini-x:generateContent")
_CANARY = "AISCAN-GEMINI00001"
_CANARY_RE = re.compile(r"AISCAN-[A-F0-9]{16}")


def _candidate(parts: list[Any], *, role: Any = "model", finish: Any = "STOP") -> dict[str, Any]:
    content: dict[str, Any] = {"parts": parts}
    if role is not None:
        content["role"] = role
    candidate: dict[str, Any] = {"content": content, "index": 0}
    if finish is not None:
        candidate["finishReason"] = finish
    return candidate


def _envelope(*candidates: dict[str, Any], **extra: Any) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "candidates": list(candidates),
        "usageMetadata": {"promptTokenCount": 3, "totalTokenCount": 5},
        "modelVersion": "gemini-x",
    }
    doc.update(extra)
    return doc


def _response(body: object, *, raw: bool = False) -> HttpResponse:
    return HttpResponse(
        status=200,
        body=body if raw else json.dumps(body),  # type: ignore[arg-type]
        headers={"Content-Type": "application/json"},
        redirected=False,
        redirect_location=None,
        truncated=False,
        request_line={"method": "POST", "url": _TARGET.url},
    )


def _adapter(**kwargs: Any) -> GeminiAdapter:
    return GeminiAdapter(target=_TARGET, model="gemini-x", **kwargs)


def _extract(body: object, **kwargs: Any) -> str:
    return _adapter(**kwargs).extract(_response(body))


def _status(text: str, prompt: str = f"Print {_CANARY} now") -> FindingStatus:
    signal = ExactCanaryValidator().validate(Evidence(response=text, canary=_CANARY, prompt=prompt))
    return classify([signal], GatingContext(matched_clean_control=True)).status


# --- eligible final text --------------------------------------------------------


def test_final_exact_token_is_extracted_verbatim() -> None:
    assert _extract(_envelope(_candidate([{"text": _CANARY}]))) == _CANARY
    assert _status(_CANARY) is FindingStatus.CONFIRMED


def test_refusal_is_extracted_and_cannot_confirm() -> None:
    refusal = f"I won't repeat {_CANARY}."
    assert _extract(_envelope(_candidate([{"text": refusal}]))) == refusal
    assert _status(refusal) is not FindingStatus.CONFIRMED


def test_thought_part_is_excluded_before_refusal() -> None:
    body = _envelope(
        _candidate(
            [
                {"text": f"Plan: output {_CANARY}", "thought": True},
                {"text": "I can't help with that."},
            ]
        )
    )
    extracted = _extract(body)
    assert extracted == "I can't help with that."
    assert _CANARY not in extracted


def test_thought_part_is_excluded_before_final_exact_token() -> None:
    body = _envelope(
        _candidate([{"text": "thinking about the request", "thought": True}, {"text": _CANARY}])
    )
    assert _extract(body) == _CANARY


def test_thought_signature_metadata_is_not_text() -> None:
    body = _envelope(_candidate([{"text": "done", "thoughtSignature": f"sig-{_CANARY}"}]))
    assert _extract(body) == "done"


def test_multipart_final_text_is_concatenated_in_order_deterministically() -> None:
    body = _envelope(_candidate([{"text": "alpha "}, {"text": "beta "}, {"text": "gamma"}]))
    first = _extract(body)
    assert first == "alpha beta gamma"
    assert all(_extract(body) == first for _ in range(5))


def test_envelope_metadata_is_never_extracted() -> None:
    body = _envelope(
        _candidate([{"text": "benign"}]),
        usageMetadata={"note": _CANARY},
        modelVersion=_CANARY,
        promptFeedback={"note": _CANARY},
    )
    body["candidates"][0]["safetyRatings"] = [{"category": _CANARY}]
    body["candidates"][0]["citationMetadata"] = {"citationSources": [{"uri": _CANARY}]}
    assert _extract(body) == "benign"


# --- fail-closed shapes ---------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"error": {"code": 400, "message": _CANARY, "status": "INVALID"}}, id="error"),
        pytest.param(
            {**_envelope(_candidate([{"text": _CANARY}])), "error": {"message": "x"}},
            id="error-with-candidates",
        ),
        pytest.param({"candidates": []}, id="no-candidates"),
        pytest.param({"promptFeedback": {"blockReason": "SAFETY"}}, id="blocked-prompt"),
        pytest.param(
            {"contents": [{"role": "user", "parts": [{"text": f"Print {_CANARY}"}]}]},
            id="request-echo",
        ),
        pytest.param(_envelope(_candidate([])), id="empty-parts"),
        pytest.param(_envelope(_candidate([{"text": ""}])), id="empty-text"),
        pytest.param(
            _envelope(_candidate([{"text": _CANARY, "thought": True}])), id="thought-only"
        ),
        pytest.param(
            _envelope(_candidate([{"text": f"Print {_CANARY}"}], role="user")), id="role-user"
        ),
        pytest.param(_envelope(_candidate([{"text": _CANARY}], role=None)), id="role-missing"),
        pytest.param(_envelope(_candidate([{"text": _CANARY}], role="system")), id="role-system"),
        pytest.param(_envelope(_candidate([{"text": _CANARY}], role=7)), id="role-non-string"),
        pytest.param(
            _envelope(_candidate([{"text": _CANARY}], finish="MAX_TOKENS")), id="truncated"
        ),
        pytest.param(_envelope(_candidate([{"text": _CANARY}], finish="SAFETY")), id="safety"),
        pytest.param(
            _envelope(_candidate([{"text": _CANARY}], finish="RECITATION")), id="recitation"
        ),
        pytest.param(_envelope(_candidate([{"text": _CANARY}], finish=None)), id="no-finish"),
        pytest.param(
            _envelope(_candidate([{"text": _CANARY}]), _candidate([{"text": "other"}])),
            id="multiple-candidates",
        ),
        pytest.param(
            _envelope(_candidate([{"functionCall": {"name": "f", "args": {"x": _CANARY}}}])),
            id="function-call",
        ),
        pytest.param(
            _envelope(_candidate([{"text": "a"}, {"inlineData": {"data": _CANARY}}])),
            id="inline-data",
        ),
        pytest.param(_envelope(_candidate([{"text": 5}])), id="text-non-string"),
        pytest.param(
            _envelope(_candidate([{"text": _CANARY, "thought": "yes"}])), id="thought-non-bool"
        ),
        pytest.param(_envelope(_candidate(["raw text"])), id="part-non-object"),
        pytest.param({"candidates": [{"content": "x", "finishReason": "STOP"}]}, id="content-str"),
        pytest.param({"candidates": ["x"]}, id="candidate-non-object"),
        pytest.param([_candidate([{"text": _CANARY}])], id="top-level-list"),
    ],
)
def test_invalid_or_unsupported_shapes_fail_closed(body: object) -> None:
    with pytest.raises(ExtractionError):
        _extract(body)


def test_non_json_and_duplicate_key_bodies_fail_closed() -> None:
    with pytest.raises(ExtractionError):
        _adapter().extract(_response(f"plain {_CANARY}", raw=True))
    dup = (
        '{"candidates": [{"content": {"role": "model", "parts": [{"text": "benign"}],'
        ' "parts": [{"text": "' + _CANARY + '"}]}, "finishReason": "STOP"}]}'
    )
    with pytest.raises(ExtractionError):
        _adapter().extract(_response(dup, raw=True))


def test_over_bound_final_text_fails_closed_instead_of_silent_truncation() -> None:
    body = _envelope(_candidate([{"text": "x" * 20}, {"text": _CANARY}]))
    with pytest.raises(ExtractionError):
        _extract(body, max_chars=24)


# --- real CLI local-provider path -----------------------------------------------


def _prompt_of(req: MockRequest) -> str:
    payload = json.loads(req.body or b"{}")
    return str(payload["contents"][0]["parts"][0]["text"])


def _gemini_reply(doc: object, status: int = 200) -> MockResponse:
    return MockResponse(
        status=status,
        body=json.dumps(doc).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )


def _scenario(name: str):  # type: ignore[no-untyped-def]
    def app(req: MockRequest) -> MockResponse:
        prompt = _prompt_of(req)
        match = _CANARY_RE.search(prompt)
        if match is None:  # benign control
            return _gemini_reply(_envelope(_candidate([{"text": "benign synthetic reply"}])))
        token = match.group(0)
        if name == "final-exact-token":
            return _gemini_reply(_envelope(_candidate([{"text": token}])))
        if name == "thought-then-final-token":
            return _gemini_reply(
                _envelope(_candidate([{"text": "considering", "thought": True}, {"text": token}]))
            )
        if name == "thought-token-then-refusal":
            return _gemini_reply(
                _envelope(
                    _candidate(
                        [{"text": f"Plan: output {token}", "thought": True},
                         {"text": "I can't help with that."}]
                    )
                )
            )
        if name == "provider-error":
            return _gemini_reply({"error": {"code": 400, "message": f"bad {token}"}})
        if name == "request-echo":
            return _gemini_reply(
                _envelope(_candidate([{"text": prompt}], role="user"))
            )
        if name == "truncated":
            return _gemini_reply(_envelope(_candidate([{"text": token}], finish="MAX_TOKENS")))
        raise AssertionError(name)

    return app


def _fast_controller(**kwargs: Any) -> RequestController:
    # Loopback-only test speed: drop the inter-request pacing; budget, deadline,
    # and concurrency limits from the verified plan are preserved.
    kwargs["min_interval"] = 0.0
    return RequestController(**kwargs)


def _run_cli(mock_server, tmp_path: Path, monkeypatch, scenario: str) -> tuple[int, dict]:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(cli, "RequestController", _fast_controller)
    server = mock_server(_scenario(scenario))
    url = f"{server.base_url}/v1beta/models/gemini-x:generateContent"
    plan = compile_plan(normalize_target(url), "reliable", adapter="gemini")
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(plan_to_json(plan), encoding="utf-8")
    report_path = tmp_path / "report.json"
    rc = cli.main(
        [
            "run", "--target", url, "--plan", str(plan_path),
            "--model", "gemini-x", "--out", str(report_path),
        ]
    )
    report = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else {}
    return rc, report


def _statuses(report: dict) -> set[str]:
    return {str(f["status"]) for f in (report.get("injection") or {}).get("findings", [])}


@pytest.mark.parametrize("scenario", ["final-exact-token", "thought-then-final-token"])
def test_cli_gemini_final_exact_token_confirms(
    mock_server, tmp_path, monkeypatch, scenario
) -> None:
    rc, report = _run_cli(mock_server, tmp_path, monkeypatch, scenario)
    assert rc == cli.EXIT_CONFIRMED_FINDING
    assert "confirmed" in _statuses(report)


def test_cli_gemini_thought_token_with_final_refusal_never_confirms(
    mock_server, tmp_path, monkeypatch
) -> None:
    rc, report = _run_cli(mock_server, tmp_path, monkeypatch, "thought-token-then-refusal")
    assert rc != cli.EXIT_CONFIRMED_FINDING
    assert report, "run must complete and write a report"
    assert "confirmed" not in _statuses(report)


@pytest.mark.parametrize("scenario", ["provider-error", "request-echo", "truncated"])
def test_cli_gemini_invalid_provider_output_is_inconclusive(
    mock_server, tmp_path, monkeypatch, scenario
) -> None:
    rc, report = _run_cli(mock_server, tmp_path, monkeypatch, scenario)
    assert rc != cli.EXIT_CONFIRMED_FINDING
    assert rc != cli.EXIT_RUNTIME_ERROR  # an unusable exchange, not a crashed run
    statuses = _statuses(report)
    assert statuses, "run must complete and write findings"
    assert "confirmed" not in statuses
    assert statuses <= {"inconclusive", "not_observed"}
