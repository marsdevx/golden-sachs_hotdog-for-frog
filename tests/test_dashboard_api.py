"""The dashboard's admin API client against the real firewall app (no Streamlit needed)."""

import pytest
from dashboard_app.api import AdminAPIError, AdminClient
from fastapi.testclient import TestClient

FALCON = {"messages": [{"role": "user", "content": "project falcon"}]}


@pytest.fixture
def api(firewall_app):
    return AdminClient(client=TestClient(firewall_app), admin_key="")


def run_check(firewall_app, agent_headers, body=FALCON):
    return TestClient(firewall_app).post("/v1/check/input", json=body, headers=agent_headers)


def test_toggle_mode_changes_the_policy_file(api, firewall_app, agent_headers):
    assert run_check(firewall_app, agent_headers).json()["decision"]["action"] == "block"
    (control,) = api.controls()
    assert control["id"] == "keyword_blocklist" and control["mode"] == "block"

    result = api.patch_control("keyword_blocklist", mode="monitor")
    assert result["parsed"]["controls"]["keyword_blocklist"]["mode"] == "monitor"
    assert "mode: monitor" in firewall_app.state.policy_store.path.read_text()
    assert run_check(firewall_app, agent_headers).json()["decision"]["action"] == "allow"


def test_events_export_and_metrics(api, firewall_app, agent_headers):
    run_check(firewall_app, agent_headers)
    run_check(firewall_app, agent_headers, {"messages": [{"role": "user", "content": "hi"}]})
    assert [e["action"] for e in api.events()] == ["allow", "block"]
    assert len(api.events(action="block", stage="any", agent_id="")) == 1
    assert len(api.export("jsonl").splitlines()) == 2
    assert api.export("csv").startswith(b"check_id,")
    metrics = api.metrics()
    assert metrics["total_checks"] == 2 and metrics["by_action"]["block"] == 1
    assert api.policy()["last_error"] is None


def test_errors_are_raised_readably(api):
    with pytest.raises(AdminAPIError, match="unknown Control id"):
        api.put_policy("controls:\n  bogus: {}\n")
    with pytest.raises(AdminAPIError, match="404"):
        api.patch_control("bogus", mode="block")


def test_admin_key_is_sent(make_firewall_app, monkeypatch):
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    app = make_firewall_app()
    with pytest.raises(AdminAPIError, match="401"):
        AdminClient(client=TestClient(app), admin_key="").metrics()
    assert AdminClient(client=TestClient(app), admin_key="s3cret").metrics()["total_checks"] == 0
