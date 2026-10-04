"""Tests for the `request_limits` Control: every Stage allowed and limited, the Mode table,
and the `max_tokens` ceiling end to end through the check API and the proxy."""

import pytest
from conftest import BASE_POLICY
from fastapi.testclient import TestClient
from firewall_app.controls import REGISTRY
from firewall_app.controls.request_limits import RequestLimits
from firewall_app.domain import Action, Agent, Check, Message, Stage, ToolCall, Usage
from firewall_app.pipeline import run_check
from firewall_app.policy import PolicyError, parse_policy

AGENT = Agent(id="research-assistant", owner="alice@bank.example")
PARAMS = RequestLimits.Params(
    max_messages=3,
    max_prompt_tokens=50,  # 200 characters
    max_completion_tokens=20,  # 80 characters
    max_tool_args_tokens=10,
    max_tool_result_tokens=25,  # 100 characters
)
MARKER = " [truncated by AI Control Layer]"
TOOL = ToolCall(resource="crm", action="read_client", args={"client_id": 7})


def input_check(*texts: str, max_tokens: int | None = None) -> Check:
    return Check(
        stage=Stage.input,
        agent=AGENT,
        messages=[Message(role="user", content=text) for text in texts],
        max_tokens=max_tokens,
    )


def output_check(text: str, completion_tokens: int | None = None) -> Check:
    usage = Usage(model="mock", completion_tokens=completion_tokens)
    return Check(stage=Stage.output, agent=AGENT, usage=usage,
                 message=Message(role="assistant", content=text))


def tool_call_check(args: dict) -> Check:
    return Check(stage=Stage.tool_call, agent=AGENT, tool=TOOL.model_copy(update={"args": args}))


def tool_result_check(text: str) -> Check:
    return Check(stage=Stage.tool_result, agent=AGENT, tool=TOOL, tool_result=text)


async def evaluate(check: Check, params=PARAMS):
    return await RequestLimits().evaluate(check, params)


def test_registered():
    assert REGISTRY.get("request_limits") is RequestLimits
    assert RequestLimits.stages == {Stage.input, Stage.output, Stage.tool_call, Stage.tool_result}


def test_no_limits_by_default_allows_everything():
    assert all(
        value is None
        for name, value in RequestLimits.Params().model_dump().items()
        if name.startswith("max_")
    )


@pytest.mark.parametrize(
    "params_yaml, expected",
    [
        ("max_prompt_tokens: 0", "max_prompt_tokens"),
        ("chars_per_token: 0", "chars_per_token"),
        ("max_prompt_tokns: 10", "unknown keys"),
    ],
)
def test_invalid_params_are_refused_at_load(params_yaml, expected):
    text = f"controls:\n  request_limits:\n    mode: block\n    params:\n      {params_yaml}\n"
    with pytest.raises(PolicyError) as error:
        parse_policy(text, REGISTRY)
    assert expected in str(error.value)


# --- input ------------------------------------------------------------------------------


async def test_input_within_limits_is_allowed():
    verdict = await evaluate(input_check("What is the weather?", max_tokens=10))
    assert verdict.action == Action.allow
    assert verdict.findings == []


async def test_too_many_messages_is_blocked():
    verdict = await evaluate(input_check("a", "b", "c", "d"))
    assert verdict.action == Action.block
    assert [f.type for f in verdict.findings] == ["too_many_messages"]
    assert "4 messages > limit 3" in verdict.reason


async def test_oversized_prompt_is_blocked_without_quoting_it():
    secret = "client list: " + "x" * 300
    verdict = await evaluate(input_check(secret))
    assert verdict.action == Action.block
    assert verdict.findings[0].type == "prompt_too_large"
    assert "~79 tokens > limit 50" in verdict.reason
    assert "client list" not in verdict.reason


async def test_prompt_size_counts_every_message():
    verdict = await evaluate(input_check("x" * 120, "y" * 120))
    assert verdict.findings[0].type == "prompt_too_large"


async def test_max_tokens_above_ceiling_is_lowered():
    verdict = await evaluate(input_check("hello", max_tokens=5000))
    assert verdict.action == Action.redact
    assert verdict.findings[0].type == "max_tokens_too_high"
    assert verdict.rewritten.max_tokens == 20
    assert verdict.rewritten.messages == input_check("hello").messages


async def test_missing_max_tokens_is_allowed_unless_required():
    assert (await evaluate(input_check("hello"))).action == Action.allow
    required = PARAMS.model_copy(update={"require_max_tokens": True})
    verdict = await evaluate(input_check("hello"), required)
    assert verdict.action == Action.redact
    assert verdict.findings[0].type == "max_tokens_missing"
    assert verdict.rewritten.max_tokens == 20


async def test_unfixable_and_fixable_together_block_but_still_rewrite():
    verdict = await evaluate(input_check("x" * 400, max_tokens=5000))
    assert verdict.action == Action.block
    assert {f.type for f in verdict.findings} == {"prompt_too_large", "max_tokens_too_high"}
    assert verdict.rewritten.max_tokens == 20


# --- output -----------------------------------------------------------------------------


async def test_short_reply_is_allowed():
    assert (await evaluate(output_check("Fine.", completion_tokens=2))).action == Action.allow


async def test_long_reply_by_reported_tokens_is_truncated():
    verdict = await evaluate(output_check("y" * 100, completion_tokens=500))
    assert verdict.action == Action.redact
    assert verdict.findings[0].type == "reply_too_long"
    assert "reply 500 tokens > limit 20" in verdict.reason
    assert verdict.rewritten.message.content == "y" * 80 + MARKER


async def test_long_reply_is_estimated_when_usage_is_unknown():
    verdict = await evaluate(output_check("z" * 400))
    assert "reply ~100 tokens" in verdict.reason
    assert verdict.rewritten.message.content == "z" * 80 + MARKER


async def test_reported_tokens_win_over_the_estimate():
    # A long text the provider counted as few tokens (e.g. one repeated word) passes.
    assert (await evaluate(output_check("z" * 400, completion_tokens=10))).action == Action.allow


# --- tool_call --------------------------------------------------------------------------


async def test_small_tool_args_are_allowed():
    assert (await evaluate(tool_call_check({"client_id": 7}))).action == Action.allow


async def test_oversized_tool_args_are_blocked():
    verdict = await evaluate(tool_call_check({"query": "q" * 200}))
    assert verdict.action == Action.block
    assert verdict.findings[0].type == "tool_args_too_large"
    assert "crm.read_client arguments" in verdict.reason


# --- tool_result ------------------------------------------------------------------------


async def test_small_tool_result_is_allowed():
    assert (await evaluate(tool_result_check("client 7: ACME Corp"))).action == Action.allow


async def test_oversized_tool_result_is_truncated():
    verdict = await evaluate(tool_result_check("r" * 1000))
    assert verdict.action == Action.redact
    assert verdict.findings[0].type == "tool_result_too_large"
    assert verdict.rewritten.tool_result == "r" * 100 + MARKER


# --- Modes through the pipeline ---------------------------------------------------------


def policy_with_mode(mode: str):
    return parse_policy(
        f"controls:\n  request_limits:\n    mode: {mode}\n    params:\n"
        "      max_prompt_tokens: 50\n      max_completion_tokens: 20\n",
        REGISTRY,
    )


async def test_monitor_mode_records_but_changes_nothing():
    result = await run_check(input_check("x" * 400, max_tokens=5000), policy_with_mode("monitor"))
    assert result.decision.action == Action.allow
    assert result.decision.verdicts[0].action == Action.block
    assert result.after.max_tokens == 5000


async def test_block_mode_blocks_what_cannot_be_fixed():
    result = await run_check(input_check("x" * 400), policy_with_mode("block"))
    assert result.decision.action == Action.block
    assert result.decision.reason.startswith("Blocked by request_limits: prompt ~100 tokens")


async def test_block_mode_still_fixes_what_can_be_fixed():
    result = await run_check(input_check("hello", max_tokens=5000), policy_with_mode("block"))
    assert result.decision.action == Action.redact
    assert result.after.max_tokens == 20


async def test_redact_mode_fixes_and_never_rejects():
    result = await run_check(input_check("x" * 400, max_tokens=5000), policy_with_mode("redact"))
    assert result.decision.action == Action.redact
    assert result.after.max_tokens == 20
    assert result.after.messages[0].content == "x" * 400


# --- end to end -------------------------------------------------------------------------

LIMITS_POLICY = BASE_POLICY + """  request_limits:
    mode: block
    params:
      max_prompt_tokens: 50
      max_completion_tokens: 20
"""


@pytest.fixture
def limited_client(make_firewall_app):
    return TestClient(make_firewall_app(LIMITS_POLICY))


def test_check_api_returns_the_lowered_max_tokens(limited_client, agent_headers):
    body = {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 5000}
    response = limited_client.post("/v1/check/input", json=body, headers=agent_headers).json()
    assert response["decision"]["action"] == "redact"
    assert response["max_tokens"] == 20


def test_check_api_rejects_max_tokens_outside_input(limited_client, agent_headers):
    body = {"message": {"role": "assistant", "content": "hi"}, "max_tokens": 5}
    response = limited_client.post("/v1/check/output", json=body, headers=agent_headers)
    assert response.status_code == 422


def test_proxy_forwards_the_lowered_max_tokens(make_firewall_app):
    from test_proxy import HEADERS, RecordingUpstream, completion

    upstream = RecordingUpstream()
    client = TestClient(make_firewall_app(LIMITS_POLICY, upstream_transport=upstream))
    response = client.post(
        "/v1/chat/completions",
        json=completion(model="remote-model", max_completion_tokens=5000),
        headers=HEADERS,
    )
    assert response.status_code == 200
    sent = upstream.requests[0]["body"]
    assert sent["max_completion_tokens"] == 20
    assert "max_tokens" not in sent
    assert response.json()["firewall"]["input"]["decision"]["action"] == "redact"


def test_proxy_blocks_an_oversized_prompt_before_the_model(make_firewall_app):
    from test_proxy import HEADERS, RecordingUpstream, completion

    upstream = RecordingUpstream()
    client = TestClient(make_firewall_app(LIMITS_POLICY, upstream_transport=upstream))
    messages = [{"role": "user", "content": "x" * 400}]
    body = client.post(
        "/v1/chat/completions",
        json=completion(model="remote-model", messages=messages),
        headers=HEADERS,
    ).json()
    assert body["choices"][0]["finish_reason"] == "content_filter"
    assert "prompt_too_large" in str(body["firewall"]["input"]["decision"]["findings"])
    assert upstream.requests == []


@pytest.mark.parametrize("value", [0, -1, "100", True])
def test_proxy_rejects_an_invalid_max_tokens(limited_client, value):
    from test_proxy import HEADERS, completion

    response = limited_client.post(
        "/v1/chat/completions", json=completion(max_tokens=value), headers=HEADERS
    )
    assert response.status_code == 400
