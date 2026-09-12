"""Generic HTTP adapter request shaping and extraction tests."""

from __future__ import annotations

import json
from typing import Any

import pytest

from ai_scan.adapters import AdapterConfigError, ExtractionError, ExtractionSpec, GenericHttpAdapter
from ai_scan.adapters.generic_http import CAPABILITIES
from ai_scan.targets import normalize_target
from ai_scan.transport import MARKER, HttpResponse, Transport, TransportConfig


def _response(body: str, headers: dict[str, str] | None = None) -> HttpResponse:
    return HttpResponse(
        status=200,
        body=body,
        headers=headers or {},
        redirected=False,
        redirect_location=None,
        truncated=False,
        request_line={"method": "POST", "url": "http://mock.local/chat"},
    )


def test_capability_discovery_is_static_and_offline() -> None:
    assert CAPABILITIES.name == "generic_http"
    assert CAPABILITIES.methods == frozenset({"GET", "POST"})
    assert CAPABILITIES.extraction_modes >= frozenset({"text", "json_pointer", "header"})


def test_post_json_marker_insertion_matches_legacy_transport(echo_server: Any) -> None:
    target = normalize_target(f"{echo_server.base_url}/chat")
    prompt = 'first\nsecond "quoted" \\ done'
    template = '{"input": "*"}'

    adapter = GenericHttpAdapter(target=target, method="POST", body_template=template)
    prepared = adapter.build_request(prompt)
    legacy = Transport(TransportConfig()).send(
        target, method="POST", prompt=prompt, body_template=template
    )
    echoed = json.loads(legacy.body)

    assert prepared.method == "POST"
    assert prepared.url == target.url
    assert prepared.body is not None
    prepared_body = prepared.body.decode("utf-8")
    assert json.loads(prepared_body)["input"] == prompt
    assert prepared_body == echoed["body"]
    assert prepared.headers["Content-Type"] == "application/json"
    assert MARKER not in prepared_body


def test_get_url_encoding_marker_insertion_matches_legacy_transport(echo_server: Any) -> None:
    target = normalize_target(f"{echo_server.base_url}/chat?q=*")
    prompt = "hello world&x=1"

    adapter = GenericHttpAdapter(target=target, method="GET")
    prepared = adapter.build_request(prompt)
    legacy = Transport(TransportConfig()).send(target, method="GET", prompt=prompt)
    echoed = json.loads(legacy.body)

    assert prepared.method == "GET"
    assert prepared.body is None
    assert prepared.url.endswith("/chat?q=hello%20world%26x%3D1")
    assert echoed["path"].endswith("/chat?q=hello%20world%26x%3D1")


def test_raw_prompt_mode_is_explicit_and_verbatim() -> None:
    target = normalize_target("http://mock.local/chat")
    adapter = GenericHttpAdapter(
        target=target,
        method="POST",
        body_template="prefix:*:suffix",
        prompt_encoding="raw",
    )
    prepared = adapter.build_request('line\n"quote"\\slash')
    assert prepared.body == b'prefix:line\n"quote"\\slash:suffix'


@pytest.mark.parametrize(
    "kwargs",
    [
        {"method": "DELETE"},
        {"method": "GET"},
        {"method": "POST", "body_template": "no marker"},
        {"method": "POST", "prompt_encoding": "pickle"},
    ],
)
def test_malformed_config_fails_before_request_creation(kwargs: dict[str, object]) -> None:
    target_url = "http://mock.local/chat"
    if kwargs.get("method") == "GET":
        target_url = "http://mock.local/chat?q=no-marker"
    with pytest.raises(AdapterConfigError):
        GenericHttpAdapter(target=normalize_target(target_url), **kwargs)  # type: ignore[arg-type]


def test_extract_text_json_pointer_header_and_bounds() -> None:
    body = json.dumps({"choices": [{"message": {"content": "abcdef"}}]})
    assert GenericHttpAdapter(
        target=normalize_target("http://mock.local/chat"),
        extraction=ExtractionSpec(
            mode="json_pointer", path="/choices/0/message/content", max_chars=3
        ),
    ).extract(_response(body)) == "abc"
    assert GenericHttpAdapter(
        target=normalize_target("http://mock.local/chat"),
        extraction=ExtractionSpec(mode="header", path="X-Reply"),
    ).extract(_response("ignored", {"x-reply": "from-header"})) == "from-header"


@pytest.mark.parametrize(
    "spec,response",
    [
        (ExtractionSpec(mode="json_pointer", path="/missing"), _response("{}")),
        (ExtractionSpec(mode="json_pointer", path="/obj"), _response('{"obj": {}}')),
        (ExtractionSpec(mode="header", path="X-Missing"), _response("body")),
    ],
)
def test_incompatible_extraction_fails_closed(spec: ExtractionSpec, response: HttpResponse) -> None:
    adapter = GenericHttpAdapter(target=normalize_target("http://mock.local/chat"), extraction=spec)
    with pytest.raises(ExtractionError):
        adapter.extract(response)
