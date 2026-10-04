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
    body = client.get("/v1/settings/policy").json()
    assert body["yaml"] == BASE_POLICY
    assert body["parsed"]["controls"]["keyword_blocklist"]["mode"] == "block"
    assert len(body["version"]) == 12
    assert body["loaded_at"]
    assert body["last_error"] is None


def test_get_policy_reports_last_error(client, tmp_policy):
    tmp_policy("controls: [broken")
    body = client.get("/v1/settings/policy").json()
    assert "invalid YAML" in body["last_error"]
    assert body["yaml"] == BASE_POLICY


def test_list_controls(client):
    control, *others = client.get("/v1/settings/controls").json()
    assert control["id"] == "keyword_blocklist"
    # Registered Controls that are not in the Policy are listed after it, as off.
    assert all(not other["in_policy"] and other["mode"] == "off" for other in others)
    assert control["description"]
    assert control["mode"] == "block"
    assert control["supported_stages"] == ["input", "output"]
    assert control["stages"] == ["input", "output"]
    assert control["params"] == {"keywords": ["project falcon"]}
    assert "keywords" in control["params_schema"]["properties"]


def test_policy_cannot_be_changed_through_the_api(client, firewall_app, agent_headers):
    """The Policy file is changed only by editing it: no route writes it."""
    path = firewall_app.state.policy_store.path
    attempts = [
        client.put("/v1/settings/policy", content="controls: {}\n"),
        client.post("/v1/settings/policy", content="controls: {}\n"),
        client.patch("/v1/settings/controls/keyword_blocklist", json={"mode": "off"}),
        client.put("/v1/settings/controls/keyword_blocklist", json={"mode": "off"}),
    ]
    # GET /policy exists (405 for other methods); /controls/{id} does not exist at all.
    assert [response.status_code for response in attempts] == [405, 405, 404, 404]
    assert path.read_text() == BASE_POLICY
    assert check(client, agent_headers)["decision"]["action"] == "block"


def test_edited_policy_file_changes_the_next_check(client, tmp_policy, agent_headers):
    assert check(client, agent_headers)["decision"]["action"] == "block"
    tmp_policy(BASE_POLICY.replace("mode: block", "mode: monitor"))
    assert client.get("/v1/settings/controls").json()[0]["mode"] == "monitor"
    assert check(client, agent_headers)["decision"]["action"] == "allow"

    tmp_policy(BASE_POLICY.replace('["project falcon"]', '["hello"]'))
    assert check(client, agent_headers, HELLO)["decision"]["action"] == "block"
    assert check(client, agent_headers)["decision"]["action"] == "allow"


SENSITIVE_POLICY = BASE_POLICY + """  sensitive_data:
    mode: redact
    params:
      categories:
        - name: email
          patterns: ['[\\w.+-]+@[\\w-]+(?:\\.[\\w-]+)+']
        - name: card
          patterns: ['\\b(?:\\d[ -]?){12,18}\\d\\b']
          validator: luhn
"""


def check_output(client, agent_headers, text):
    body = {"message": {"role": "assistant", "content": text}}
    return client.post("/v1/check/output", json=body, headers=agent_headers).json()


def test_one_category_can_be_switched_off_in_the_file(make_firewall_app, agent_headers):
    policy = SENSITIVE_POLICY.replace(
        "        - name: email\n", "        - name: email\n          enabled: false\n"
    )
    client = TestClient(make_firewall_app(policy))
    controls = {c["id"]: c for c in client.get("/v1/settings/controls").json()}
    shown = {c["name"]: c for c in controls["sensitive_data"]["params"]["categories"]}
    assert shown["email"]["enabled"] is False
    assert "enabled" not in shown["card"]

    email = check_output(client, agent_headers, "mail jan@bank.example")
    assert email["decision"]["action"] == "allow"
    card = check_output(client, agent_headers, "card 4111 1111 1111 1111")
    assert card["decision"]["action"] == "redact"
    assert card["message"]["content"] == "card [CARD]"


def test_events_and_filters(client, agent_headers):
    check(client, agent_headers, HELLO)
    check(client, agent_headers)
    client.post("/v1/check/input", json=HELLO)  # unknown agent
    events = client.get("/v1/settings/events").json()
    assert [e["action"] for e in events] == ["block", "block", "allow"]
    assert len(client.get("/v1/settings/events", params={"action": "allow"}).json()) == 1
    assert len(client.get("/v1/settings/events", params={"agent_id": "test-agent"}).json()) == 2
    assert len(client.get("/v1/settings/events", params={"stage": "output"}).json()) == 0
    assert len(client.get("/v1/settings/events", params={"limit": 1}).json()) == 1
    since = client.get("/v1/settings/events", params={"since": "2999-01-01T00:00:00Z"})
    assert since.json() == []
    assert client.get("/v1/settings/events", params={"action": "explode"}).status_code == 422


def test_export_download(client, agent_headers):
    check(client, agent_headers, HELLO)
    check(client, agent_headers)
    jsonl = client.get("/v1/settings/events/export", params={"format": "jsonl"})
    assert jsonl.headers["content-disposition"].endswith('audit-events.jsonl"')
    assert [json.loads(line)["action"] for line in jsonl.text.splitlines()] == ["allow", "block"]
    csv_response = client.get("/v1/settings/events/export", params={"format": "csv"})
    assert csv_response.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert [row["action"] for row in rows] == ["allow", "block"]
    blocked = client.get("/v1/settings/events/export", params={"action": "block"})
    assert len(blocked.text.splitlines()) == 1


def test_metrics(client, agent_headers):
    check(client, agent_headers, HELLO)
    check(client, agent_headers)
    metrics = client.get("/v1/settings/metrics").json()
    assert metrics["total_checks"] == 2
    assert metrics["by_action"]["block"] == 1
    assert metrics["by_control"]["keyword_blocklist"]["blocked"] == 1
    assert metrics["by_agent"]["test-agent"]["checks"] == 2
    assert "p95" in metrics["latency_ms"]["total"]


def test_settings_need_no_key(make_firewall_app, monkeypatch):
    # The user owns the firewall on their own PC: there is no administrator key.
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    assert TestClient(make_firewall_app()).get("/v1/settings/metrics").status_code == 200
    assert TestClient(make_firewall_app()).get("/v1/admin/metrics").status_code == 404

