import pytest
from firewall_app.domain import (
    Action,
    Agent,
    Check,
    Content,
    Message,
    Stage,
    ToolCall,
    Verdict,
    most_severe,
)
from pydantic import ValidationError

AGENT = Agent(id="research-assistant", owner="alice@bank.example", team="markets-research")


def test_severity_order():
    assert Action.block.severity > Action.review.severity > Action.redact.severity
    assert Action.redact.severity > Action.allow.severity
    assert most_severe([Action.allow, Action.block, Action.redact]) == Action.block
    assert most_severe([Action.redact, Action.review]) == Action.review
    assert most_severe([]) == Action.allow


def test_check_defaults_and_unique_ids():
    first = Check(stage=Stage.input, agent=AGENT)
    second = Check(stage=Stage.input, agent=AGENT)
    assert first.check_id != second.check_id
    assert first.messages == [] and first.labels == [] and first.metadata == {}
    assert first.transport == "check_api"


def test_message_role_is_validated():
    with pytest.raises(ValidationError):
        Message(role="robot", content="hi")


def test_risk_score_bounds():
    with pytest.raises(ValidationError):
        Verdict(action=Action.block, risk_score=1.5)


def test_with_content_replaces_only_given_fields():
    check = Check(
        stage=Stage.tool_result,
        agent=AGENT,
        tool=ToolCall(resource="crm", action="read"),
        tool_result="secret",
    )
    rewritten = check.with_content(Content(tool_result="[REDACTED]"))
    assert rewritten.tool_result == "[REDACTED]"
    assert rewritten.tool == check.tool
    assert check.tool_result == "secret"


def test_content_of_input_check():
    check = Check(stage=Stage.input, agent=AGENT, messages=[Message(role="user", content="hi")])
    assert check.content().messages[0].content == "hi"
    assert check.content().message is None
