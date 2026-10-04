import pytest
from conftest import BASE_POLICY
from fastapi.testclient import TestClient

TOOL = {"resource": "crm", "action": "read", "args": {"client_id": 7}}
VALID_BODIES = {
    "input": {"messages": [{"role": "user", "content": "Hello"}], "user": "bob"},
    "output": {
        "message": {"role": "assistant", "content": "Hi"},
        "usage": {"model": "mock", "prompt_tokens": 1, "completion_tokens": 1},
    },
    "tool_call": {"tool": TOOL},
    "tool_result": {"tool": TOOL, "tool_result": "client 7: ACME Corp"},
}
CONTENT_FIELDS = {
    "input": {"messages"},
    "output": {"message"},
    "tool_call": {"tool"},
    "tool_result": {"tool", "tool_result"},
}


@pytest.fixture
def client(firewall_app):
    return TestClient(firewall_app)


@pytest.mark.parametrize("stage", list(VALID_BODIES))
def test_each_stage_allows_and_echoes_content(client, agent_headers, stage):
    response = client.post(f"/v1/check/{stage}", json=VALID_BODIES[stage], headers=agent_headers)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"check_id", "policy_version", "decision"} | CONTENT_FIELDS[stage]
    assert body["decision"]["action"] == "allow"
    assert body["decision"]["findings"] == []
    assert body["policy_version"] == body["decision"]["policy_version"]
    for field in CONTENT_FIELDS[stage]:
        assert body[field] == VALID_BODIES[stage][field]


@pytest.mark.parametrize(
    "stage, body",
    [
        ("input", {}),
        ("input", {"messages": []}),
        ("input", {"messages": [{"role": "user", "content": "x"}], "tool": TOOL}),
        ("input", {"messages": [{"role": "user", "content": "x"}], "usage": {}}),
        ("output", {"messages": [{"role": "user", "content": "x"}]}),
        ("tool_call", {}),
        ("tool_call", {"tool": TOOL, "message": {"role": "assistant", "content": "x"}}),
        ("tool_result", {"tool": TOOL}),
        ("tool_result", {"tool_result": "x"}),
        ("input", {"messages": [{"role": "robot", "content": "x"}]}),
        ("input", {"messages": [{"role": "user", "content": "x"}], "violations": []}),
        ("nonsense", {"messages": [{"role": "user", "content": "x"}]}),
    ],
)
def test_invalid_bodies_are_rejected(client, agent_headers, stage, body):
    response = client.post(f"/v1/check/{stage}", json=body, headers=agent_headers)
    assert response.status_code == 422


def test_blocked_input_is_explained_with_structured_findings(client, agent_headers):
    body = {"messages": [{"role": "user", "content": "What about Project Falcon?"}]}
    response = client.post("/v1/check/input", json=body, headers=agent_headers)
    assert response.status_code == 200
    decision = response.json()["decision"]
    assert decision["action"] == "block"
    assert decision["reason"].startswith("Blocked by keyword_blocklist")
    finding = decision["findings"][0]
    assert finding == {
        "control": "keyword_blocklist",
        "type": "forbidden_phrase",
        "detail": "message 0 contains 'Project Falcon'",
        "span": [11, 25],
    }
    assert decision["verdicts"][0]["effective_action"] == "block"
    assert "violations" not in decision and "modified_content" not in decision


def test_redacted_output_returns_redacted_content(make_firewall_app, agent_headers):
    client = TestClient(make_firewall_app(BASE_POLICY.replace("mode: block", "mode: redact")))
    body = {"message": {"role": "assistant", "content": "project falcon is a go"}}
    response = client.post("/v1/check/output", json=body, headers=agent_headers).json()
    assert response["decision"]["action"] == "redact"
    assert response["message"]["content"] == "[REDACTED] is a go"


@pytest.mark.parametrize("headers", [{}, {"X-Agent-Key": "wrong"}])
def test_unknown_agent_is_a_normal_block_decision(client, headers):
    response = client.post("/v1/check/input", json=VALID_BODIES["input"], headers=headers)
    assert response.status_code == 200
    decision = response.json()["decision"]
    assert decision["action"] == "block"
    assert decision["reason"] == "unknown agent"


async def test_unknown_agent_creates_audit_event(firewall_app):
    client = TestClient(firewall_app)
    client.post("/v1/check/input", json=VALID_BODIES["input"])
    (event,) = await firewall_app.state.audit.query()
    assert event.reason == "unknown agent"
    assert event.agent_id == "unknown"


def test_unknown_agent_allowed_by_policy(make_firewall_app):
    app = make_firewall_app(BASE_POLICY.replace("unknown_agent: block", "unknown_agent: allow"))
    response = TestClient(app).post("/v1/check/input", json=VALID_BODIES["input"])
    assert response.json()["decision"]["action"] == "allow"


def test_hot_reload_through_http(client, agent_headers, tmp_policy):
    body = {"messages": [{"role": "user", "content": "project falcon"}]}
    first = client.post("/v1/check/input", json=body, headers=agent_headers).json()
    assert first["decision"]["action"] == "block"

    tmp_policy(BASE_POLICY.replace("mode: block", "mode: monitor"))
    second = client.post("/v1/check/input", json=body, headers=agent_headers).json()
    assert second["decision"]["action"] == "allow"
    assert second["policy_version"] != first["policy_version"]


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_tool_result_iban_is_redacted(make_firewall_app, agent_headers):
    policy = BASE_POLICY + """  sensitive_data:
    mode: redact
    params:
      categories:
        - name: iban
          patterns: ['\\b[A-Z]{2}\\d{2}(?: ?[A-Z0-9]){11,30}\\b']
          validator: iban
"""
    client = TestClient(make_firewall_app(policy))
    body = {"tool": TOOL, "tool_result": "client 7 pays to DE89 3704 0044 0532 0130 00"}
    response = client.post("/v1/check/tool_result", json=body, headers=agent_headers).json()
    assert response["decision"]["action"] == "redact"
    assert response["tool_result"] == "client 7 pays to [IBAN]"
    assert response["decision"]["findings"][0]["type"] == "iban"
