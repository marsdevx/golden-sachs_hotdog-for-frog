import csv
import io
import json

import pytest
from conftest import BASE_POLICY
from fastapi.testclient import TestClient

FALCON = {"messages": [{"role": "user", "content": "project falcon"}]}
HELLO = {"messages": [{"role": "user", "content": "hello"}]}


@pytest.fixture
def client(firewall_app):
    return TestClient(firewall_app)


def check(client, agent_headers, body=FALCON):
    return client.post("/v1/check/input", json=body, headers=agent_headers).json()


def test_get_policy(client):
    body = client.get("/v1/admin/policy").json()
    assert body["yaml"] == BASE_POLICY
    assert body["parsed"]["controls"]["keyword_blocklist"]["mode"] == "block"
    assert len(body["version"]) == 12
    assert body["loaded_at"]
    assert body["last_error"] is None


def test_get_policy_reports_last_error(client, tmp_policy):
    tmp_policy("controls: [broken")
    body = client.get("/v1/admin/policy").json()
    assert "invalid YAML" in body["last_error"]
    assert body["yaml"] == BASE_POLICY


def test_put_policy_round_trip(client, agent_headers):
    old_version = client.get("/v1/admin/policy").json()["version"]
    new_yaml = BASE_POLICY.replace("mode: block", "mode: monitor")
    response = client.put(
        "/v1/admin/policy", content=new_yaml, headers={"Content-Type": "application/yaml"}
    )
    assert response.status_code == 200
    assert response.json()["version"] != old_version
    assert client.get("/v1/admin/policy").json()["yaml"] == new_yaml
    assert check(client, agent_headers)["decision"]["action"] == "allow"


def test_put_invalid_policy_is_422_and_file_unchanged(client, firewall_app):
    response = client.put("/v1/admin/policy", content="controls:\n  bogus: {}\n")
    assert response.status_code == 422
    assert "unknown Control id" in response.json()["detail"]["errors"][0]
    assert firewall_app.state.policy_store.path.read_text() == BASE_POLICY


def test_list_controls(client):
    (control,) = client.get("/v1/admin/controls").json()
    assert control["id"] == "keyword_blocklist"
    assert control["description"]
    assert control["mode"] == "block"
    assert control["supported_stages"] == ["input", "output"]
    assert control["stages"] == ["input", "output"]
    assert control["params"] == {"keywords": ["project falcon"]}
    assert "keywords" in control["params_schema"]["properties"]


def test_patch_mode_changes_next_check(client, agent_headers):
    assert check(client, agent_headers)["decision"]["action"] == "block"
    response = client.patch("/v1/admin/controls/keyword_blocklist", json={"mode": "monitor"})
    assert response.status_code == 200
    assert response.json()["parsed"]["controls"]["keyword_blocklist"]["mode"] == "monitor"
    assert check(client, agent_headers)["decision"]["action"] == "allow"


def test_patch_params(client, agent_headers):
    client.patch("/v1/admin/controls/keyword_blocklist", json={"params": {"keywords": ["hello"]}})
    assert check(client, agent_headers, HELLO)["decision"]["action"] == "block"
    assert check(client, agent_headers)["decision"]["action"] == "allow"


def test_patch_invalid_is_422(client, firewall_app):
    before = firewall_app.state.policy_store.path.read_text()
    bad = client.patch("/v1/admin/controls/keyword_blocklist", json={"params": {"keywords": 3}})
    assert bad.status_code == 422
    assert client.patch("/v1/admin/controls/nope", json={"mode": "block"}).status_code == 404
    assert client.patch(
        "/v1/admin/controls/keyword_blocklist", json={"mode": "loud"}
    ).status_code == 422
    assert firewall_app.state.policy_store.path.read_text() == before


def test_events_and_filters(client, agent_headers):
    check(client, agent_headers, HELLO)
    check(client, agent_headers)
    client.post("/v1/check/input", json=HELLO)  # unknown agent
    events = client.get("/v1/admin/events").json()
    assert [e["action"] for e in events] == ["block", "block", "allow"]
    assert len(client.get("/v1/admin/events", params={"action": "allow"}).json()) == 1
    assert len(client.get("/v1/admin/events", params={"agent_id": "test-agent"}).json()) == 2
    assert len(client.get("/v1/admin/events", params={"stage": "output"}).json()) == 0
    assert len(client.get("/v1/admin/events", params={"limit": 1}).json()) == 1
    since = client.get("/v1/admin/events", params={"since": "2999-01-01T00:00:00Z"})
    assert since.json() == []
    assert client.get("/v1/admin/events", params={"action": "explode"}).status_code == 422


def test_export_download(client, agent_headers):
    check(client, agent_headers, HELLO)
    check(client, agent_headers)
    jsonl = client.get("/v1/admin/events/export", params={"format": "jsonl"})
    assert jsonl.headers["content-disposition"].endswith('audit-events.jsonl"')
    assert [json.loads(line)["action"] for line in jsonl.text.splitlines()] == ["allow", "block"]
    csv_response = client.get("/v1/admin/events/export", params={"format": "csv"})
    assert csv_response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert [row["action"] for row in rows] == ["allow", "block"]
    blocked = client.get("/v1/admin/events/export", params={"action": "block"})
    assert len(blocked.text.splitlines()) == 1


def test_metrics(client, agent_headers):
    check(client, agent_headers, HELLO)
    check(client, agent_headers)
    metrics = client.get("/v1/admin/metrics").json()
    assert metrics["total_checks"] == 2
    assert metrics["by_action"]["block"] == 1
    assert metrics["by_control"]["keyword_blocklist"]["blocked"] == 1
    assert metrics["by_agent"]["test-agent"]["checks"] == 2
    assert "p95" in metrics["latency_ms"]["total"]


def test_admin_key_enforced_when_set(make_firewall_app, monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    client = TestClient(make_firewall_app())
    assert client.get("/v1/admin/policy").status_code == 401
    assert client.get("/v1/admin/policy", headers={"X-Admin-Key": "wrong"}).status_code == 401
    assert client.get("/v1/admin/policy", headers={"X-Admin-Key": "s3cret"}).status_code == 200
    assert client.get("/health").status_code == 200


def test_admin_open_without_key(make_firewall_app, monkeypatch):
    monkeypatch.delenv("ADMIN_KEY", raising=False)
    assert TestClient(make_firewall_app()).get("/v1/admin/metrics").status_code == 200
