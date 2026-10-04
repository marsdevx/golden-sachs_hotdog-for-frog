import httpx
import pytest
from conftest import AGENT_KEY, BASE_POLICY
from fastapi.testclient import TestClient
from firewall_app.controls import REGISTRY
from firewall_app.domain import Message
from firewall_app.policy import PolicyError, PolicyStore, parse_policy
from firewall_app.providers import registry
from firewall_app.providers.base import ModelResponse
from firewall_app.providers.registry import ProviderRegistry
from test_proxy import RecordingUpstream


def test_unknown_provider_rejected_and_reload_keeps_last_good(tmp_policy):
    store = PolicyStore(tmp_policy(), REGISTRY)
    previous = store.get()
    invalid = BASE_POLICY.replace('base_url: "mock://"',
                                  'base_url: "mock://"\n    provider: typo')
    with pytest.raises(PolicyError, match="unknown provider"):
        parse_policy(invalid, REGISTRY)
    tmp_policy(invalid)
    assert store.get() is previous
    assert "unknown provider" in store.last_error


def test_duplicate_model_route_rejected():
    with pytest.raises(PolicyError, match="duplicate model route"):
        parse_policy(BASE_POLICY.replace('models: ["remote-model"]', 'models: ["mock"]'), REGISTRY)


def test_registry_rejects_duplicate_names():
    local = ProviderRegistry()
    factory = lambda connection, client: None  # noqa: E731
    local.register("example", factory)
    with pytest.raises(ValueError, match="duplicate"):
        local.register("example", factory)


@pytest.mark.parametrize("prompt,reply,mode,expected_calls,action", [
    ("project falcon", "safe", "block", 0, "block"),
    ("hello", "project falcon", "block", 1, "block"),
    ("project falcon", "project falcon", "redact", 1, "redact"),
    ("hello", "safe", "block", 1, "allow"),
])
def test_new_adapter_uses_existing_firewall_pipeline(
    monkeypatch, make_firewall_app, prompt, reply, mode, expected_calls, action,
):
    calls = []

    class ExampleAdapter:
        def __init__(self, connection, client):
            self.connection = connection

        async def chat(self, request):
            calls.append(request)
            return ModelResponse(model=request.model,
                                 message=Message(role="assistant", content=reply))

    monkeypatch.setattr(registry, "_factories", dict(registry._factories))
    registry.register("example", ExampleAdapter)
    policy = BASE_POLICY.replace(
        'base_url: "http://upstream.test/v1"',
        'base_url: "http://upstream.test/v1"\n    provider: example',
    ).replace("mode: block", f"mode: {mode}")
    client = TestClient(make_firewall_app(policy))
    body = client.post("/v1/chat/completions", headers={"X-Agent-Key": AGENT_KEY}, json={
        "model": "remote-model", "messages": [{"role": "user", "content": prompt}],
    }).json()
    assert len(calls) == expected_calls
    assert body["firewall"]["action"] == action
    if mode == "redact":
        assert calls[0].messages[0].content == "[REDACTED]"
        assert body["choices"][0]["message"]["content"] == "[REDACTED]"
    if prompt == "hello" and action == "block":
        assert body["choices"][0]["finish_reason"] == "content_filter"


def test_ollama_adapter_receives_options_and_provider_key(make_firewall_app, monkeypatch):
    upstream = RecordingUpstream()
    monkeypatch.setenv("TEST_MODEL_KEY", "upstream-secret")
    policy = BASE_POLICY.replace(
        'base_url: "http://upstream.test/v1"',
        'base_url: "http://upstream.test/v1"\n    provider: ollama'
        '\n    api_key_env: TEST_MODEL_KEY',
    )
    response = TestClient(make_firewall_app(policy, upstream)).post(
        "/v1/chat/completions", headers={"X-Agent-Key": AGENT_KEY}, json={
            "model": "remote-model", "messages": [{"role": "user", "content": "Hello"}],
            "temperature": 0.3,
        },
    )
    assert response.status_code == 200
    sent = upstream.requests[0]
    assert sent["body"]["temperature"] == 0.3
    assert sent["body"]["stream"] is False
    assert sent["headers"]["authorization"] == "Bearer upstream-secret"
    assert "x-agent-key" not in sent["headers"]


@pytest.mark.parametrize("bad_usage", [{"prompt_tokens": -1}, "invalid"])
def test_invalid_adapter_response_fails_closed(make_firewall_app, bad_usage):
    def handler(request):
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "Unverified"}}], "usage": bad_usage,
        })

    app = make_firewall_app(upstream_transport=httpx.MockTransport(handler))
    response = TestClient(app).post(
        "/v1/chat/completions", headers={"X-Agent-Key": AGENT_KEY}, json={
            "model": "remote-model", "messages": [{"role": "user", "content": "Hi"}],
        },
    )
    assert response.status_code == 502
    assert "Unverified" not in response.text


@pytest.mark.parametrize("configured,extra,expected", [
    ("none", {}, "none"),
    ("default", {}, None),
    ("none", {"reasoning_effort": "low"}, "low"),
    ("none", {"reasoning": {"effort": "low"}}, None),
])
def test_ollama_tool_thinking_setting(
    make_firewall_app, monkeypatch, configured, extra, expected,
):
    monkeypatch.setenv("OLLAMA_TOOL_REASONING_EFFORT", configured)
    upstream = RecordingUpstream()
    policy = BASE_POLICY.replace('base_url: "http://upstream.test/v1"',
                                 'base_url: "http://upstream.test/v1"\n    provider: ollama')
    response = TestClient(make_firewall_app(policy, upstream)).post(
        "/v1/chat/completions", headers={"X-Agent-Key": AGENT_KEY}, json={
            "model": "remote-model", "messages": [{"role": "user", "content": "List files"}],
            "enable_tools": True, **extra,
        },
    )
    assert response.status_code == 200
    assert upstream.requests[0]["body"].get("reasoning_effort") == expected
    if "reasoning" in extra:
        assert upstream.requests[0]["body"]["reasoning"] == extra["reasoning"]


def test_timeout_diagnostics_do_not_log_provider_content(make_firewall_app, caplog):
    def fail(request):
        raise httpx.ReadTimeout("private prompt and secret-key", request=request)
    app = make_firewall_app(upstream_transport=httpx.MockTransport(fail))
    response = TestClient(app).post(
        "/v1/chat/completions", headers={"X-Agent-Key": AGENT_KEY}, json={
            "model": "remote-model", "messages": [{"role": "user", "content": "Hi"}],
        },
    )
    assert response.status_code == 502
    assert "ReadTimeout" in caplog.text
    assert "configured timeout 60s" in caplog.text
    assert "check_id=" in caplog.text
    assert "secret-key" not in caplog.text + response.text
    assert "private prompt" not in caplog.text + response.text
