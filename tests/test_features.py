"""Tests for the `features:` master switches: each Control group, audit and the web console,
switched off and back on in the real `standard` Preset, live, without a restart."""

import pytest
import yaml
from conftest import POLICY_FILE
from fastapi.testclient import TestClient
from firewall_app.controls import REGISTRY
from firewall_app.controls.base import CONTROL_FEATURES, Control, Registry
from firewall_app.domain import Action, Agent, Check, Message, Stage, Verdict
from firewall_app.pipeline import run_check
from firewall_app.policy import PolicyError, parse_policy
from firewall_app.policy.schema import Features

STANDARD = POLICY_FILE.read_text()
HEADERS = {"X-Agent-Key": "demo-agent-key"}
FALCON = {"messages": [{"role": "user", "content": "Any news on Project Falcon?"}]}
EMAIL = {"message": {"role": "assistant", "content": "Write to jan.kowalski@bank.example"}}
SECRET_FILE = {"tool": {"resource": "files", "action": "read_file",
                        "args": {"path": "/demo/private/internal.txt"}}}
GROUPS = {
    "input_validation": {"keyword_blocklist", "injection_heuristics", "injection_classifier"},
    "data_protection": {"sensitive_data", "output_sanitizer"},
    "resource_access": {"resource_access"},
    "usage_limits": {"loop_detector", "request_limits", "token_budget"},
    "attack_mitigation": {"attack_signatures"},
}


def standard_with(**features) -> str:
    data = yaml.safe_load(STANDARD)
    data["features"] = {**data["features"], **features}
    return yaml.safe_dump(data, sort_keys=False)


def decision(client, stage, body):
    return client.post(f"/v1/check/{stage}", json=body, headers=HEADERS).json()["decision"]


# --- the schema and the groups ----------------------------------------------------------


def test_everything_is_on_by_default():
    assert all(Features().model_dump().values())
    policy = parse_policy("controls: {}\n", REGISTRY)
    assert policy.features == Features()


def test_switches_match_the_control_groups():
    assert set(Features.model_fields) == {*CONTROL_FEATURES, "audit", "console"}


def test_every_control_belongs_to_a_group():
    groups = {cid: cls.feature for cid, cls in REGISTRY.all().items()}
    assert {cid for cid, g in groups.items() if g not in CONTROL_FEATURES} == set()
    for group, controls in GROUPS.items():
        assert {cid for cid, g in groups.items() if g == group} == controls


def test_a_control_without_a_group_is_refused():
    registry = Registry()
    with pytest.raises(ValueError, match="must declare its feature"):
        @registry.control("orphan")
        class Orphan(Control):
            stages = {Stage.input}

            async def evaluate(self, check, params):
                return Verdict()


@pytest.mark.parametrize("text", ["features: {audti: false}\n", "features: {audit: maybe}\n"])
def test_typos_and_non_booleans_are_refused(text):
    with pytest.raises(PolicyError):
        parse_policy(text, REGISTRY)


# --- Control groups ---------------------------------------------------------------------


@pytest.mark.parametrize("group", GROUPS)
def test_a_group_switched_off_skips_its_controls_and_keeps_their_modes(group):
    policy = parse_policy(standard_with(**{group: False}), REGISTRY)
    for control_id, settings in policy.controls.items():
        assert settings.active is (control_id not in GROUPS[group])
        assert settings.mode == parse_policy(STANDARD, REGISTRY).controls[control_id].mode


async def test_pipeline_skips_a_group_that_is_off():
    check = Check(stage=Stage.input, agent=Agent(id="a", owner="o"),
                  messages=[Message(role="user", content="project falcon?")])
    on = parse_policy("controls:\n  keyword_blocklist: {mode: block, params: "
                      "{keywords: [project falcon]}}\n", REGISTRY)
    off = parse_policy("features: {input_validation: false}\ncontrols:\n  keyword_blocklist: "
                       "{mode: block, params: {keywords: [project falcon]}}\n", REGISTRY)
    assert (await run_check(check, on)).decision.action == Action.block
    result = await run_check(check, off)
    assert result.decision.action == Action.allow
    assert result.decision.verdicts == []


def test_input_validation_off_and_on_again_live(make_firewall_app, tmp_policy):
    client = TestClient(make_firewall_app(STANDARD))
    assert decision(client, "input", FALCON)["action"] == "block"
    tmp_policy(standard_with(input_validation=False))
    assert decision(client, "input", FALCON)["action"] == "allow"
    tmp_policy(STANDARD)
    assert decision(client, "input", FALCON)["action"] == "block"


def test_data_protection_off(make_firewall_app):
    client = TestClient(make_firewall_app(standard_with(data_protection=False)))
    response = client.post("/v1/check/output", json=EMAIL, headers=HEADERS).json()
    assert response["decision"]["action"] == "allow"
    assert response["message"]["content"] == EMAIL["message"]["content"]


def test_resource_access_off(make_firewall_app):
    on = TestClient(make_firewall_app(STANDARD))
    assert decision(on, "tool_call", SECRET_FILE)["action"] == "block"
    off = TestClient(make_firewall_app(standard_with(resource_access=False)))
    assert decision(off, "tool_call", SECRET_FILE)["action"] == "allow"


def test_usage_limits_off(make_firewall_app):
    client = TestClient(make_firewall_app(standard_with(usage_limits=False)))
    hello = {"messages": [{"role": "user", "content": "status?"}]}
    actions = [decision(client, "input", hello)["action"] for _ in range(10)]
    assert set(actions) == {"allow"}  # standard blocks the 6th identical call when on
    budgets = client.get("/v1/settings/budgets").json()
    assert budgets["mode"] == "block" and budgets["active"] is False


# --- audit and console ------------------------------------------------------------------


def test_audit_off_writes_no_events_but_still_enforces(make_firewall_app):
    client = TestClient(make_firewall_app(standard_with(audit=False)))
    assert decision(client, "input", FALCON)["action"] == "block"
    assert decision(client, "input", {"messages": [{"role": "user", "content": "hi"}]})[
        "action"] == "allow"
    assert client.get("/v1/settings/events").json() == []
    summary = client.get("/v1/settings/summary").json()
    assert summary["features"]["audit"] is False
    assert summary["totals_24h"]["requests"] == 0


def test_audit_off_and_on_again_live(make_firewall_app, tmp_policy):
    client = TestClient(make_firewall_app(standard_with(audit=False)))
    decision(client, "input", FALCON)
    tmp_policy(STANDARD)
    decision(client, "input", FALCON)
    assert len(client.get("/v1/settings/events").json()) == 1


def test_usage_limits_keep_working_without_audit(make_firewall_app):
    client = TestClient(make_firewall_app(standard_with(audit=False)))
    hello = {"messages": [{"role": "user", "content": "status?"}]}
    allowed = yaml.safe_load(STANDARD)["controls"]["loop_detector"]["params"]["max_similar"]
    actions = [decision(client, "input", hello)["action"] for _ in range(allowed + 1)]
    assert actions == ["allow"] * allowed + ["block"]


def test_console_off_and_on_again_live(make_firewall_app, tmp_policy):
    client = TestClient(make_firewall_app(standard_with(console=False)))
    assert client.get("/console").status_code == 404
    assert client.get("/v1/settings/summary").status_code == 200
    tmp_policy(STANDARD)
    assert client.get("/console").status_code == 200


def test_console_data_shows_what_is_off(make_firewall_app):
    client = TestClient(make_firewall_app(standard_with(data_protection=False)))
    summary = client.get("/v1/settings/summary").json()
    shown = {c["id"]: c for c in summary["controls"]}
    assert shown["sensitive_data"]["feature_on"] is False
    assert shown["sensitive_data"]["mode"] == "redact"  # kept for when it is switched back on
    assert shown["keyword_blocklist"]["feature_on"] is True
    coverage = summary["posture"]["components"][0]
    assert {"sensitive_data", "output_sanitizer"} <= set(coverage["gaps"])
    controls = {c["id"]: c for c in client.get("/v1/settings/controls").json()}
    assert controls["output_sanitizer"]["feature"] == "data_protection"
    assert controls["output_sanitizer"]["feature_on"] is False


# --- everything off: close to plain Ollama ----------------------------------------------


def test_everything_off_forwards_untouched_and_records_nothing(make_firewall_app):
    from test_proxy import RecordingUpstream

    upstream = RecordingUpstream(content="Mail jan.kowalski@bank.example ![x](https://evil.test/a)")
    off = {group: False for group in GROUPS} | {"audit": False, "console": False}
    client = TestClient(make_firewall_app(standard_with(**off), upstream_transport=upstream))

    prompt = "Project Falcon: " + "x" * 50000  # forbidden phrase and far over request_limits
    body = {"model": "qwen3:4b", "max_tokens": 99999,
            "messages": [{"role": "user", "content": prompt}]}
    response = client.post("/v1/chat/completions", json=body, headers=HEADERS).json()

    sent = upstream.requests[0]["body"]
    assert sent["messages"][0]["content"] == prompt
    assert sent["max_tokens"] == 99999
    assert response["choices"][0]["message"]["content"] == upstream.content
    assert response["firewall"]["input"]["decision"]["verdicts"] == []
    assert response["firewall"]["output"]["decision"]["verdicts"] == []
    assert client.get("/v1/settings/events").json() == []
    assert client.get("/console").status_code == 404
