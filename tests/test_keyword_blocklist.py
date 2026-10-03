"""Tests for the reference Control. Copy this file as the template for a new Control's tests:
for every supported Stage, at least one allowed case and one blocked/redacted case."""

from firewall_app.controls import REGISTRY
from firewall_app.controls.keyword_blocklist import KeywordBlocklist
from firewall_app.domain import Action, Agent, Check, Message, Stage
from firewall_app.pipeline import run_check
from firewall_app.policy import parse_policy

AGENT = Agent(id="research-assistant", owner="alice@bank.example")
PARAMS = KeywordBlocklist.Params(keywords=["project falcon"])


def input_check(text: str) -> Check:
    return Check(stage=Stage.input, agent=AGENT, messages=[Message(role="user", content=text)])


def output_check(text: str) -> Check:
    return Check(stage=Stage.output, agent=AGENT, message=Message(role="assistant", content=text))


async def evaluate(check: Check, params=PARAMS):
    return await KeywordBlocklist().evaluate(check, params)


def test_registered():
    assert REGISTRY.get("keyword_blocklist") is KeywordBlocklist
    assert KeywordBlocklist.stages == {Stage.input, Stage.output}


async def test_input_allowed():
    verdict = await evaluate(input_check("What is the weather?"))
    assert verdict.action == Action.allow
    assert verdict.findings == []


async def test_input_blocked_case_insensitive_with_findings_and_redaction():
    verdict = await evaluate(input_check("Tell me about Project Falcon please"))
    assert verdict.action == Action.block
    assert "project falcon" in verdict.reason
    assert verdict.findings[0].control == "keyword_blocklist"
    assert verdict.findings[0].span == (14, 28)
    assert verdict.rewritten.messages[0].content == "Tell me about [REDACTED] please"


async def test_output_allowed():
    verdict = await evaluate(output_check("The weather is fine."))
    assert verdict.action == Action.allow


async def test_output_blocked():
    verdict = await evaluate(output_check("Sure, project falcon closes on Friday."))
    assert verdict.action == Action.block
    assert verdict.rewritten.message.content == "Sure, [REDACTED] closes on Friday."


async def test_empty_keyword_list_allows_everything():
    verdict = await evaluate(input_check("project falcon"), KeywordBlocklist.Params())
    assert verdict.action == Action.allow


def policy_with_mode(mode: str):
    return parse_policy(
        f"controls:\n  keyword_blocklist:\n    mode: {mode}\n"
        "    params:\n      keywords: ['project falcon']\n",
        REGISTRY,
    )


async def test_monitor_mode_records_but_allows():
    result = await run_check(input_check("project falcon status?"), policy_with_mode("monitor"))
    assert result.decision.action == Action.allow
    assert result.decision.verdicts[0].action == Action.block
    assert result.decision.findings
    assert result.after.messages[0].content == "project falcon status?"


async def test_redact_mode_rewrites_and_lets_through():
    result = await run_check(output_check("project falcon is on"), policy_with_mode("redact"))
    assert result.decision.action == Action.redact
    assert result.after.message.content == "[REDACTED] is on"


async def test_block_mode_blocks_with_explanation():
    result = await run_check(input_check("project falcon status?"), policy_with_mode("block"))
    assert result.decision.action == Action.block
    assert result.decision.reason.startswith("Blocked by keyword_blocklist")
