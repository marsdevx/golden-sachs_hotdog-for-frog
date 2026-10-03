import pytest
from conftest import AGENT_KEY, BASE_POLICY
from firewall_app.controls import REGISTRY
from firewall_app.identity import resolve_agent
from firewall_app.policy import parse_policy

POLICY_BLOCK = parse_policy(BASE_POLICY, REGISTRY)
POLICY_ALLOW = parse_policy(
    BASE_POLICY.replace("unknown_agent: block", "unknown_agent: allow"), REGISTRY
)


@pytest.mark.parametrize(
    "headers",
    [{"x-agent-key": AGENT_KEY}, {"authorization": f"Bearer {AGENT_KEY}"}],
    ids=["x-agent-key", "bearer"],
)
def test_known_key(headers):
    identity = resolve_agent(headers, POLICY_BLOCK)
    assert identity.known and identity.allowed
    assert identity.agent.id == "test-agent"
    assert identity.agent.owner == "owner@bank.example"
    assert identity.agent.team == "test-team"


@pytest.mark.parametrize(
    "headers",
    [{}, {"x-agent-key": "wrong"}, {"authorization": "Bearer wrong"}, {"authorization": "Basic x"}],
    ids=["missing", "unknown", "unknown-bearer", "not-bearer"],
)
def test_missing_or_unknown_key_under_block(headers):
    identity = resolve_agent(headers, POLICY_BLOCK)
    assert not identity.known
    assert not identity.allowed
    assert identity.agent.id == "unknown"


@pytest.mark.parametrize("headers", [{}, {"x-agent-key": "wrong"}], ids=["missing", "unknown"])
def test_missing_or_unknown_key_under_allow_is_anonymous(headers):
    identity = resolve_agent(headers, POLICY_ALLOW)
    assert not identity.known
    assert identity.allowed
    assert identity.agent.id == "unknown"
    assert identity.agent.owner == "unknown"
