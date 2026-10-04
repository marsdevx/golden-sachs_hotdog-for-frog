"""The web console: its summary endpoint and the static page."""

from fastapi.testclient import TestClient

FALCON = {"messages": [{"role": "user", "content": "project falcon"}]}
HELLO = {"messages": [{"role": "user", "content": "hi"}]}


def test_summary_is_derived_from_audit_events(firewall_app, agent_headers):
    client = TestClient(firewall_app)
    for body in (FALCON, FALCON, HELLO):
        client.post("/v1/check/input", json=body, headers=agent_headers)
    client.post("/v1/check/input", json=HELLO, headers={"X-Agent-Key": "nope"})

    data = client.get("/v1/settings/summary").json()
    totals = data["totals_24h"]
    assert totals["requests"] == 4 and totals["blocked"] == 3 and totals["allowed"] == 1
    assert data["threats"]["by_control"] == [["keyword_blocklist", 2]]
    assert sum(m["requests"] for m in data["realtime"]["minutes"]) == 4
    assert len(data["realtime"]["minutes"]) == 60 and len(data["usage"]["hourly"]) == 24
    assert [e["decision"] for e in data["realtime"]["feed"]] == ["block"] * 3
    (control,) = data["controls"]
    assert control["id"] == "keyword_blocklist" and control["fired_24h"] == 2
    assert "unknown" in data["posture"]["components"][1]["gaps"]
    assert data["policy"]["last_error"] is None


def test_summary_on_empty_store(firewall_app):
    data = TestClient(firewall_app).get("/v1/settings/summary").json()
    assert data["totals_24h"]["requests"] == 0 and data["totals_24h"]["latency_p95_ms"] is None
    assert data["realtime"]["anomalies"] == []


def test_console_and_its_data_need_no_key(make_firewall_app, monkeypatch):
    # The user owns the firewall on their own PC: an ADMIN_KEY in the environment changes nothing.
    monkeypatch.setenv("ADMIN_KEY", "s3cret")
    client = TestClient(make_firewall_app())
    page = client.get("/console")
    assert page.status_code == 200 and "AI Control Layer" in page.text
    assert "X-Admin-Key" not in page.text
    assert client.get("/v1/settings/summary").status_code == 200
