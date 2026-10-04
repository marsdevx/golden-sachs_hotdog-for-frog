import json

import httpx
import pytest
from conftest import AGENT_KEY, BASE_POLICY
from fastapi.testclient import TestClient

ANTHROPIC_POLICY = BASE_POLICY.replace(
    'base_url: "http://upstream.test/v1"',
    'base_url: "https://anthropic.test/v1"\n    provider: anthropic'
    '\n    api_key_env: TEST_ANTHROPIC_KEY',
)
HEADERS = {"X-Agent-Key": AGENT_KEY}


class AnthropicUpstream:
    """Records Messages API requests and answers with queued response bodies."""

    def __init__(self, *bodies: dict) -> None:
        self.bodies = list(bodies)
        self.requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append({"url": str(request.url), "headers": dict(request.headers),
                              "body": json.loads(request.content)})
        return httpx.Response(200, json=self.bodies.pop(0))


def message(*content: dict, stop_reason: str = "end_turn") -> dict:
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": "remote-model",
            "content": list(content), "stop_reason": stop_reason,
            "usage": {"input_tokens": 10, "cache_read_input_tokens": 5, "output_tokens": 3}}


def post(make_firewall_app, upstream, **body):
    app = make_firewall_app(ANTHROPIC_POLICY, upstream_transport=httpx.MockTransport(upstream))
    return TestClient(app).post("/v1/chat/completions", headers=HEADERS,
                                json={"model": "remote-model", **body})


@pytest.fixture(autouse=True)
def anthropic_key(monkeypatch):
    monkeypatch.setenv("TEST_ANTHROPIC_KEY", "sk-test")


def test_text_request_is_translated_and_usage_reported(make_firewall_app):
    upstream = AnthropicUpstream(message({"type": "thinking", "thinking": ""},
                                         {"type": "text", "text": "Hello there"}))
    response = post(make_firewall_app, upstream, max_tokens=50, temperature=0.2, messages=[
        {"role": "system", "content": "Be brief."},
        {"role": "user", "content": "Hi"},
    ])

    assert response.status_code == 200
    sent = upstream.requests[0]
    assert sent["url"] == "https://anthropic.test/v1/messages"
    assert sent["headers"]["x-api-key"] == "sk-test"
    assert sent["headers"]["anthropic-version"] == "2023-06-01"
    assert "authorization" not in sent["headers"] and "x-agent-key" not in sent["headers"]
    assert sent["body"] == {"model": "remote-model", "max_tokens": 50, "system": "Be brief.",
                            "messages": [{"role": "user", "content": "Hi"}]}
    body = response.json()
    assert body["choices"][0]["message"]["content"] == "Hello there"
    assert body["choices"][0]["finish_reason"] == "stop"
    assert body["usage"] == {"prompt_tokens": 15, "completion_tokens": 3, "total_tokens": 18}


def test_default_max_tokens_is_set(make_firewall_app):
    upstream = AnthropicUpstream(message({"type": "text", "text": "ok"}))
    post(make_firewall_app, upstream, messages=[{"role": "user", "content": "Hi"}])
    assert upstream.requests[0]["body"]["max_tokens"] == 4096


def test_tool_round_trip(make_firewall_app):
    upstream = AnthropicUpstream(
        message({"type": "text", "text": "Checking."},
                {"type": "tool_use", "id": "toolu_1", "name": "read_file",
                 "input": {"path": "/demo/notes.txt"}}, stop_reason="tool_use"),
        message({"type": "text", "text": "Done"}),
    )
    first = post(make_firewall_app, upstream, enable_tools=True,
                 messages=[{"role": "user", "content": "Read my notes"}])
    assert first.status_code == 200
    tools = upstream.requests[0]["body"]["tools"]
    assert {"list_files", "read_file"} <= {tool["name"] for tool in tools}
    assert all("input_schema" in tool for tool in tools)
    reply = first.json()["choices"][0]
    assert reply["finish_reason"] == "tool_calls"
    call = reply["message"]["tool_calls"][0]
    assert call["id"] == "toolu_1"
    assert json.loads(call["function"]["arguments"]) == {"path": "/demo/notes.txt"}

    second = post(make_firewall_app, upstream, enable_tools=True, messages=[
        {"role": "user", "content": "Read my notes"},
        reply["message"],
        {"role": "tool", "tool_call_id": "toolu_1", "content": "buy milk"},
    ])
    assert second.status_code == 200
    assert upstream.requests[1]["body"]["messages"][1:] == [
        {"role": "assistant", "content": [
            {"type": "text", "text": "Checking."},
            {"type": "tool_use", "id": "toolu_1", "name": "read_file",
             "input": {"path": "/demo/notes.txt"}},
        ]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_1", "content": "buy milk"},
        ]},
    ]


def test_refusal_maps_to_content_filter(make_firewall_app):
    upstream = AnthropicUpstream(message(stop_reason="refusal"))
    response = post(make_firewall_app, upstream, messages=[{"role": "user", "content": "Hi"}])
    assert response.json()["choices"][0]["finish_reason"] == "content_filter"


def test_input_block_never_reaches_claude(make_firewall_app):
    upstream = AnthropicUpstream()
    response = post(make_firewall_app, upstream,
                    messages=[{"role": "user", "content": "Any news on Project Falcon?"}])
    assert response.json()["choices"][0]["finish_reason"] == "content_filter"
    assert upstream.requests == []


def test_output_is_checked(make_firewall_app):
    upstream = AnthropicUpstream(message({"type": "text", "text": "Project Falcon closes Friday"}))
    response = post(make_firewall_app, upstream, messages=[{"role": "user", "content": "Hi"}])
    body = response.json()
    assert body["choices"][0]["finish_reason"] == "content_filter"
    assert "closes Friday" not in response.text


def test_missing_key_fails_closed(make_firewall_app, monkeypatch):
    monkeypatch.delenv("TEST_ANTHROPIC_KEY")
    upstream = AnthropicUpstream()
    response = post(make_firewall_app, upstream, messages=[{"role": "user", "content": "Hi"}])
    assert response.status_code == 502
    assert upstream.requests == []


def test_upstream_error_fails_closed(make_firewall_app):
    def handler(request):
        return httpx.Response(401, json={"type": "error", "error": {"message": "bad key"}})

    app = make_firewall_app(ANTHROPIC_POLICY, upstream_transport=httpx.MockTransport(handler))
    response = TestClient(app).post("/v1/chat/completions", headers=HEADERS, json={
        "model": "remote-model", "messages": [{"role": "user", "content": "Hi"}]})
    assert response.status_code == 502
    assert "bad key" not in response.text
