"""End-to-end execution, enforcement and audit evidence for the tool gateway."""
import json
import shutil
from pathlib import Path

import httpx
import pytest
import yaml
from app.config import Settings
from app.firewall_client import FirewallClient
from app.main import create_app
from fastapi.testclient import TestClient
from firewall_app.domain import ToolCall
from firewall_app.tools import files
from firewall_app.tools.files import execute

POLICY = (Path(__file__).resolve().parent.parent / "policy.yaml").read_text()
HEADERS = {"X-Agent-Key": "demo-agent-key"}


def policy_with(**controls) -> str:
    """policy.yaml with some Control sections replaced (the Policy is a file)."""
    data = yaml.safe_load(POLICY)
    for control_id, section in controls.items():
        data["controls"][control_id] = {**data["controls"][control_id], **section}
    return yaml.safe_dump(data, sort_keys=False)


@pytest.fixture
def gateway(make_firewall_app):
    app = make_firewall_app(POLICY)
    chat = create_app(FirewallClient(
        Settings(agent_key="demo-agent-key", llm_model="mock"),
        httpx.ASGITransport(app=app),
    ))
    return TestClient(app), TestClient(chat)


def call(client, action="read_file", path="/demo/contacts.txt", **extra):
    return client.post("/v1/tools/execute", headers=HEADERS, json={
        "tool": {"resource": "files", "action": action, "args": {"path": path}},
        "tool_call_id": "call-test", "metadata": {"session_id": "test-run"}, **extra,
    })


def test_chat_lists_files_and_links_all_six_checks(gateway):
    firewall, chat = gateway
    response = chat.post("/v1/chat", json={
        "messages": [{"role": "user", "content": "/list_files /demo"}],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert "contacts.txt" in body["message"]["content"]
    assert len(body["steps"]) == 3
    events = firewall.get("/v1/settings/events", params={"session_id": body["run_id"]}).json()
    assert [event["stage"] for event in reversed(events)] == [
        "input", "output", "tool_call", "tool_result", "input", "output",
    ]
    results = [e for e in events if e["stage"] == "tool_result"]
    assert results[0]["metadata"]["execution"] == "succeeded"
    assert results[0]["metadata"]["operation_id"] == body["steps"][1]["operation_id"]
    assert firewall.get("/v1/settings/events", params={"session_id": "other"}).json() == []


def test_chat_receives_only_redacted_tool_content(gateway):
    firewall, chat = gateway
    body = chat.post("/v1/chat", json={
        "messages": [{"role": "user", "content": "/read_file /demo/contacts.txt"}],
    }).json()
    assert "alice@example.com" not in json.dumps(body)
    assert "[EMAIL]" in body["message"]["content"]
    events = firewall.get("/v1/settings/events", params={"session_id": body["run_id"]}).json()
    assert "alice@example.com" not in json.dumps(events)
    assert next(e for e in events if e["stage"] == "tool_result")["action"] == "redact"


def test_forbidden_folder_never_executes(gateway, monkeypatch):
    firewall, chat = gateway
    def forbidden(*args):
        pytest.fail("executor must not run")
    monkeypatch.setattr("firewall_app.tools.files.execute", forbidden)
    body = chat.post("/v1/chat", json={
        "messages": [{"role": "user", "content": "/read_file /demo/private/internal.txt"}],
    }).json()
    assert body["output_decision"]["action"] == "block"
    assert body["steps"][1]["executed"] is False
    assert body["steps"][1]["result_check_id"] is None


def test_blocked_result_is_not_released(make_firewall_app):
    firewall = TestClient(make_firewall_app(policy_with(sensitive_data={
        "mode": "block", "params": {"categories": [{
            "name": "email", "patterns": [r"[\w.+-]+@[\w.-]+"], "on_match": "block",
        }]},
    })))
    body = call(firewall).json()
    assert body["executed"] is True
    assert body["decision"]["action"] == "block"
    assert body["tool_result"] is None
    assert "alice@example.com" not in json.dumps(body)


@pytest.mark.parametrize("action,path", [
    ("read_file", "/etc/passwd"), ("read_file", "/demo/../etc/passwd"),
    ("shell", "/demo"), ("write_file", "/demo/contacts.txt"),
])
def test_gateway_contract_cannot_be_disabled_by_policy(make_firewall_app, action, path):
    firewall = TestClient(make_firewall_app(policy_with(resource_access={"mode": "off"})))
    body = call(firewall, action, path).json()
    assert body["decision"]["action"] == "block"
    assert body["executed"] is False
    assert body["tool_result"] is None


def test_missing_agent_cannot_execute(gateway, monkeypatch):
    firewall, _ = gateway
    monkeypatch.setattr("firewall_app.tools.files.execute", lambda *_: pytest.fail("executed"))
    response = firewall.post("/v1/tools/execute", json={
        "tool": {"resource": "files", "action": "list_files", "args": {"path": "/demo"}},
        "tool_call_id": "x",
    })
    assert response.json()["decision"]["action"] == "block"


def test_executor_rejects_symlinks_and_large_files(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    secret = tmp_path / "secret"
    secret.write_text("must not read")
    (root / "link").symlink_to(secret)
    (root / "large").write_bytes(b"x" * 32769)
    for name in ("link", "large"):
        with pytest.raises((OSError, ValueError)):
            execute(ToolCall(resource="files", action="read_file",
                             args={"path": f"/demo/{name}"}), root)


def test_real_adapter_tool_round_trip(make_firewall_app):
    seen = []
    def provider(request):
        body = json.loads(request.content)
        seen.append(body)
        if len(seen) == 1:
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": "call-1", "type": "function", "function": {
                    "name": "read_file", "arguments": '{"path":"/demo/contacts.txt"}',
                },
            }]}
        else:
            assert body["messages"][-1]["tool_call_id"] == "call-1"
            assert "alice@example.com" not in body["messages"][-1]["content"]
            assert body["messages"][-2]["tool_calls"][0]["id"] == "call-1"
            message = {"role": "assistant", "content": "Read the checked file."}
        return httpx.Response(200, json={"model": "qwen3:4b", "choices": [{
            "message": message, "finish_reason": "tool_calls" if len(seen) == 1 else "stop",
        }], "usage": {"prompt_tokens": 10, "completion_tokens": 5}})
    app = make_firewall_app(POLICY, upstream_transport=httpx.MockTransport(provider))
    chat = TestClient(create_app(FirewallClient(
        Settings(agent_key="demo-agent-key", llm_model="qwen3:4b"), httpx.ASGITransport(app=app),
    )))
    response = chat.post("/v1/chat", json={"messages": [{"role": "user", "content": "Read it"}]})
    assert response.status_code == 200, response.text
    assert len(seen) == 2
    assert response.json()["usage"]["prompt_tokens"] == 20


def test_data_plane_has_no_settings_routes(make_firewall_app, monkeypatch):
    monkeypatch.setenv("FIREWALL_SETTINGS_ENABLED", "false")
    client = TestClient(make_firewall_app())
    assert client.get("/v1/settings/policy").status_code == 404
    assert client.get("/console").status_code == 404
    assert client.get("/health").status_code == 200


def test_audit_failure_prevents_execution(gateway, monkeypatch):
    firewall, _ = gateway
    async def unavailable(*args):
        raise RuntimeError("audit unavailable")
    monkeypatch.setattr(firewall.app.state.audit, "append", unavailable)
    monkeypatch.setattr("firewall_app.tools.files.execute", lambda *_: pytest.fail("executed"))
    with pytest.raises(RuntimeError, match="audit unavailable"):
        call(firewall)


def test_missing_file_is_audited_without_releasing_details(gateway):
    firewall, _ = gateway
    body = call(firewall, path="/demo/missing.txt").json()
    assert body["decision"]["action"] == "block"
    assert body["tool_result"] is None
    events = firewall.get("/v1/settings/events", params={"session_id": "test-run"}).json()
    assert events[0]["metadata"]["execution"] == "failed"
    assert "missing.txt" not in body["decision"]["reason"]


def test_model_loop_is_bounded(make_firewall_app):
    seen = []
    def provider(request):
        seen.append(request)
        return httpx.Response(200, json={"model": "qwen3:4b", "choices": [{
            "message": {"role": "assistant", "content": None, "tool_calls": [{
                "id": f"call-{len(seen)}", "type": "function", "function": {
                    "name": "list_files", "arguments": '{"path":"/demo"}',
                },
            }]}, "finish_reason": "tool_calls",
        }]})
    policy = policy_with(loop_detector={"mode": "off"}, token_budget={"mode": "off"})
    app = make_firewall_app(policy, upstream_transport=httpx.MockTransport(provider))
    chat = TestClient(create_app(FirewallClient(
        Settings(agent_key="demo-agent-key", llm_model="qwen3:4b"), httpx.ASGITransport(app=app),
    )))
    response = chat.post("/v1/chat", json={"messages": [{"role": "user", "content": "Loop"}]})
    assert response.status_code == 503
    assert len(seen) == 8
    assert "model-call limit" in response.json()["detail"]


@pytest.fixture
def demo_copy(tmp_path, monkeypatch):
    """The gateway works on a temp copy of demo_data, so tests never delete the real files."""
    root = tmp_path / "demo_data"
    shutil.copytree(files.ROOT, root)
    original = files.execute
    monkeypatch.setattr("firewall_app.tools.files.execute", lambda tool: original(tool, root))
    return root


def test_chat_deletes_a_sandbox_file(gateway, demo_copy):
    firewall, chat = gateway
    body = chat.post("/v1/chat", json={
        "messages": [{"role": "user", "content": "/delete_file /demo/sandbox/scratch.txt"}],
    }).json()
    assert body["message"]["content"] == "Deleted /demo/sandbox/scratch.txt"
    assert body["steps"][1]["executed"] is True
    assert not (demo_copy / "sandbox" / "scratch.txt").exists()
    events = firewall.get("/v1/settings/events", params={"session_id": body["run_id"]}).json()
    assert next(e for e in events if e["stage"] == "tool_result")["metadata"]["execution"] == (
        "succeeded")


@pytest.mark.parametrize("path", [
    "/demo/contacts.txt", "/demo/README.txt", "/demo/private/internal.txt",
])
def test_delete_outside_sandbox_is_blocked_before_execution(gateway, demo_copy, path):
    firewall, _ = gateway
    body = call(firewall, "delete_file", path).json()
    assert body["decision"]["action"] == "block"
    assert body["executed"] is False
    assert (demo_copy / path.removeprefix("/demo/")).exists()


@pytest.mark.parametrize("path", [
    "/demo/contacts.txt", "/demo/sandbox", "/demo/sandbox/../contacts.txt",
    "/demo/SANDBOX/scratch.txt", "/etc/passwd",
])
def test_delete_contract_holds_with_resource_access_off(make_firewall_app, demo_copy, path):
    firewall = TestClient(make_firewall_app(policy_with(resource_access={"mode": "off"})))
    body = call(firewall, "delete_file", path).json()
    assert body["decision"]["action"] == "block"
    assert body["executed"] is False
    assert (demo_copy / "contacts.txt").exists()
    assert (demo_copy / "sandbox" / "scratch.txt").exists()


def test_delete_blocked_without_a_writable_sandbox_rule(make_firewall_app, demo_copy):
    data = yaml.safe_load(POLICY)
    folders = data["controls"]["resource_access"]["params"]["folders"]
    data["controls"]["resource_access"]["params"]["folders"] = [
        folder for folder in folders if folder["path"] != "/demo/sandbox"
    ]
    firewall = TestClient(make_firewall_app(yaml.safe_dump(data, sort_keys=False)))
    body = call(firewall, "delete_file", "/demo/sandbox/scratch.txt").json()
    assert body["decision"]["action"] == "block"
    assert body["executed"] is False
    assert (demo_copy / "sandbox" / "scratch.txt").exists()


def test_delete_of_missing_file_is_audited_as_failed(gateway, demo_copy):
    firewall, _ = gateway
    body = call(firewall, "delete_file", "/demo/sandbox/missing.txt").json()
    assert body["decision"]["action"] == "block"
    assert body["tool_result"] is None
    events = firewall.get("/v1/settings/events", params={"session_id": "test-run"}).json()
    assert events[0]["metadata"]["execution"] == "failed"


def test_executor_deletes_only_regular_files(tmp_path):
    root = tmp_path / "root"
    (root / "sandbox" / "dir").mkdir(parents=True)
    secret = tmp_path / "secret"
    secret.write_text("must survive")
    (root / "sandbox" / "link").symlink_to(secret)
    (root / "sandbox" / "file").write_text("x")
    with pytest.raises((OSError, ValueError)):
        execute(ToolCall(resource="files", action="delete_file",
                         args={"path": "/demo/sandbox/dir"}), root)
    with pytest.raises((OSError, ValueError)):
        execute(ToolCall(resource="files", action="delete_file",
                         args={"path": "/demo/sandbox/link"}), root)
    assert secret.exists() and (root / "sandbox" / "dir").exists()
    execute(ToolCall(resource="files", action="delete_file",
                     args={"path": "/demo/sandbox/file"}), root)
    assert not (root / "sandbox" / "file").exists()
