import httpx
import pytest
from app.config import Settings
from app.firewall_client import FirewallClient
from app.main import create_app
from app.models import Message, ToolCall
from fastapi.testclient import TestClient

REQUEST = {"messages": [{"role": "user", "content": "Hello"}]}


@pytest.mark.parametrize("failure", [
    "connection", "timeout", "status", "json", "schema", "missing_action",
    "missing_content", "missing_output",
])
def test_firewall_failure_stops_chat(failure, monkeypatch):
    monkeypatch.setenv("FIREWALL_ENABLED", "false")  # obsolete bypass must have no effect
    def handler(request):
        assert request.url.path == "/v1/chat/completions"
        if failure == "connection":
            raise httpx.ConnectError("offline", request=request)
        if failure == "timeout":
            raise httpx.ReadTimeout("timeout", request=request)
        if failure == "status":
            return httpx.Response(503)
        if failure == "json":
            return httpx.Response(200, text="not json")
        body = {
            "model": "mock",
            "choices": [{"message": {"role": "assistant", "content": "Unverified"}}],
            "firewall": {
                "input": {"check_id": "i", "decision": {"action": "allow"}},
                "output": {"check_id": "o", "decision": {"action": "allow"}},
            },
        }
        if failure == "missing_action":
            body["firewall"]["output"]["decision"] = {}
        elif failure == "missing_content":
            body["choices"][0]["message"].pop("content")
        elif failure == "missing_output":
            body["firewall"]["output"] = None
        else:
            body = {}
        return httpx.Response(200, json=body)

    firewall = FirewallClient(Settings.from_env(), httpx.MockTransport(handler))
    response = TestClient(create_app(firewall)).post("/v1/chat", json=REQUEST)
    assert response.status_code == 503
    assert "Unverified" not in response.text


def test_firewall_runs_standalone_and_rejects_invalid_requests(firewall_app, agent_headers):
    client = TestClient(firewall_app)
    assert client.get("/health").status_code == 200
    response = client.post("/v1/check/output", headers=agent_headers, json={
        "message": {"role": "assistant", "content": "Contact me@example.com"},
    })
    assert response.json()["decision"]["action"] == "allow"
    assert response.json()["message"]["content"] == "Contact me@example.com"
    assert client.post(
        "/v1/check/input", json={"messages": []}, headers=agent_headers
    ).status_code == 422


async def test_client_tool_stage_helpers_use_the_firewall(firewall_app, agent_headers):
    from conftest import AGENT_KEY

    client = FirewallClient(
        Settings(agent_key=AGENT_KEY), transport=httpx.ASGITransport(app=firewall_app)
    )
    tool = ToolCall(resource="crm", action="read", args={"id": 1})
    decision, checked_tool = await client.check_tool_call(tool, user="bob")
    assert decision.action == "allow" and checked_tool == tool
    decision, result = await client.check_tool_result(tool, "client 1: ACME")
    assert decision.action == "allow" and result == "client 1: ACME"
    decision, message = await client.check_output(Message(role="assistant", content="hi"))
    assert decision.action == "allow" and message.content == "hi"


async def test_client_sends_agent_key():
    seen = {}

    def handler(request):
        seen.update(request.headers)
        return httpx.Response(200, json={
            "check_id": "c1", "policy_version": "v1", "decision": {"action": "allow"},
            "tool": {"resource": "crm", "action": "read", "args": {}},
        })

    client = FirewallClient(Settings(agent_key="k-123"), httpx.MockTransport(handler))
    await client.check_tool_call(ToolCall(resource="crm", action="read"))
    assert seen["x-agent-key"] == "k-123"
