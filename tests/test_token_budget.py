"""Tests for the `token_budget` Control and the shared run definition: daily Agent and user
budgets, per-run limits, warnings, the UTC day boundary, Modes, and the budget end to end
through the proxy, the check API and the settings API."""

from datetime import datetime, timedelta

import pytest
from conftest import BASE_POLICY
from fastapi.testclient import TestClient
from firewall_app.controls import REGISTRY
from firewall_app.controls.base import ControlContext
from firewall_app.controls.token_budget import TokenBudget
from firewall_app.domain import Action, Agent, Check, Message, Stage, ToolCall, Usage
from firewall_app.pipeline import run_check
from firewall_app.policy import PolicyError, parse_policy
from firewall_app.runs import run_id_of
from firewall_app.storage.db import create_all, create_engine, create_sessionmaker

AGENT = Agent(id="research-assistant", owner="alice@bank.example")
RUN = "conversation:run-1"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 10, 4, 12, 0, 0)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
async def ctx(tmp_path, clock):
    engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'budget.db'}")
    await create_all(engine)
    yield ControlContext(db=create_sessionmaker(engine), clock=clock)
    await engine.dispose()


def params(**sections) -> TokenBudget.Params:
    return TokenBudget.Params.model_validate(sections)


def ask(user: str | None = None, run_id: str | None = None) -> Check:
    return Check(stage=Stage.input, agent=AGENT, user=user, run_id=run_id,
                 messages=[Message(role="user", content="hello")])


def reply(prompt: int | None, completion: int | None, user=None, run_id=None) -> Check:
    return Check(stage=Stage.output, agent=AGENT, user=user, run_id=run_id,
                 message=Message(role="assistant", content="hi"),
                 usage=Usage(model="mock", prompt_tokens=prompt, completion_tokens=completion))


def tool(run_id: str | None = RUN) -> Check:
    return Check(stage=Stage.tool_call, agent=AGENT, run_id=run_id,
                 tool=ToolCall(resource="crm", action="read_client"))


async def run(ctx, check: Check, budget: TokenBudget.Params):
    return await TokenBudget(ctx).evaluate(check, budget)


def types(verdict) -> list[str]:
    return [finding.type for finding in verdict.findings]


def test_registered():
    assert REGISTRY.get("token_budget") is TokenBudget
    assert TokenBudget.stages == {Stage.input, Stage.tool_call, Stage.output}


@pytest.mark.parametrize(
    "params_yaml, expected",
    [
        ("default: {tokens_per_day: 0}", "tokens_per_day"),
        ("default: {warn_at: 1.5}", "warn_at"),
        ("default: {cost_per_day_usd: 20}", "cost_per_day_usd"),  # money is not a budget
        ("per_team: {tokens_per_day: 5}", "unknown keys"),
        ("per_run: {requets: 5}", "requets"),
    ],
)
def test_invalid_params_are_refused_at_load(params_yaml, expected):
    text = f"controls:\n  token_budget:\n    mode: block\n    params:\n      {params_yaml}\n"
    with pytest.raises(PolicyError) as error:
        parse_policy(text, REGISTRY)
    assert expected in str(error.value)


# --- the shared run definition ----------------------------------------------------------


def test_run_is_the_session_id_or_the_conversation_start():
    def conversation(*turns):
        return [Message(role="system", content="You watch the market.")] + [
            Message(role="user" if i % 2 == 0 else "assistant", content=t)
            for i, t in enumerate(turns)
        ]

    assert run_id_of(conversation("hi"), {}) == run_id_of(conversation("hi", "yo", "more"), {})
    assert run_id_of(conversation("hi"), {}) != run_id_of(conversation("other"), {})
    assert run_id_of(None, {"session_id": "task-7"}) == run_id_of(
        conversation("x"), {"session_id": "task-7"}
    )
    assert run_id_of(None, {}) is None
    assert run_id_of(None, {"session_id": True}) is None


# --- daily budget of the Agent ----------------------------------------------------------

DAILY = params(default={"tokens_per_day": 100})


async def test_under_budget_is_allowed(ctx):
    assert (await run(ctx, ask(), DAILY)).action == Action.allow
    assert (await run(ctx, reply(30, 20), DAILY)).action == Action.allow
    assert (await run(ctx, ask(), DAILY)).action == Action.allow


async def test_used_up_budget_blocks_the_next_request_with_the_owner(ctx):
    verdict = await run(ctx, reply(70, 40), DAILY)
    assert verdict.action == Action.allow  # the reply is never cut
    assert types(verdict) == ["daily_tokens_exhausted"]

    blocked = await run(ctx, ask(), DAILY)
    assert blocked.action == Action.block
    assert types(blocked) == ["daily_tokens_exhausted"]
    assert blocked.reason == (
        "Agent research-assistant used 110 of 100 tokens today (owner alice@bank.example)"
    )


async def test_prompt_and_completion_tokens_both_count(ctx):
    await run(ctx, reply(60, None), DAILY)
    await run(ctx, reply(None, 40), DAILY)
    assert (await run(ctx, ask(), DAILY)).action == Action.block


async def test_unknown_usage_counts_nothing(ctx):
    await run(ctx, reply(None, None), DAILY)
    assert (await run(ctx, ask(), DAILY)).action == Action.allow


async def test_budget_resets_at_utc_midnight(ctx, clock):
    clock.now = datetime(2026, 10, 4, 23, 59, 0)
    await run(ctx, reply(100, 0), DAILY)
    assert (await run(ctx, ask(), DAILY)).action == Action.block
    clock.advance(120)
    assert (await run(ctx, ask(), DAILY)).action == Action.allow


async def test_agents_are_counted_apart(ctx):
    await run(ctx, reply(100, 0), DAILY)
    other = ask().model_copy(update={"agent": Agent(id="trading-assistant", owner="bob")})
    assert (await run(ctx, other, DAILY)).action == Action.allow


# --- daily budget per user --------------------------------------------------------------

PER_USER = params(per_user={"tokens_per_day": 50})


async def test_each_user_has_their_own_budget(ctx):
    await run(ctx, reply(40, 20, user="bob"), PER_USER)
    blocked = await run(ctx, ask(user="bob"), PER_USER)
    assert blocked.action == Action.block
    assert "user bob used 60 of 50 tokens today" in blocked.reason
    assert (await run(ctx, ask(user="carol"), PER_USER)).action == Action.allow
    assert (await run(ctx, ask(), PER_USER)).action == Action.allow  # no user, no user budget


# --- per run ----------------------------------------------------------------------------


async def test_run_request_limit(ctx):
    budget = params(per_run={"requests": 2})
    verdicts = [await run(ctx, ask(run_id=RUN), budget) for _ in range(3)]
    assert [v.action for v in verdicts] == [Action.allow, Action.allow, Action.block]
    assert "this run made 3 requests > limit 2" in verdicts[2].reason
    assert (await run(ctx, ask(run_id="conversation:other"), budget)).action == Action.allow


async def test_run_tool_call_limit(ctx):
    budget = params(per_run={"tool_calls": 2})
    verdicts = [await run(ctx, tool(), budget) for _ in range(3)]
    assert [v.action for v in verdicts] == [Action.allow, Action.allow, Action.block]
    assert types(verdicts[2]) == ["run_tool_calls_exceeded"]


async def test_run_token_limit_blocks_the_next_call_of_that_run_only(ctx):
    budget = params(per_run={"tokens": 100})
    await run(ctx, ask(run_id=RUN), budget)
    await run(ctx, reply(80, 30, run_id=RUN), budget)
    assert types(await run(ctx, ask(run_id=RUN), budget)) == ["run_tokens_exhausted"]
    assert types(await run(ctx, tool(), budget)) == ["run_tokens_exhausted"]
    assert (await run(ctx, ask(run_id="conversation:other"), budget)).action == Action.allow


async def test_run_wall_clock_limit(ctx, clock):
    budget = params(per_run={"wall_clock_seconds": 300})
    await run(ctx, ask(run_id=RUN), budget)
    clock.advance(200)
    assert (await run(ctx, ask(run_id=RUN), budget)).action == Action.allow
    clock.advance(200)
    blocked = await run(ctx, ask(run_id=RUN), budget)
    assert "this run has been going for 400s > limit 300s" in blocked.reason


async def test_idle_run_is_over_and_starts_again(ctx, clock):
    budget = params(per_run={"requests": 1, "idle_seconds": 60})
    await run(ctx, ask(run_id=RUN), budget)
    assert (await run(ctx, ask(run_id=RUN), budget)).action == Action.block
    clock.advance(61)
    assert (await run(ctx, ask(run_id=RUN), budget)).action == Action.allow


async def test_no_run_id_means_no_run_limits(ctx):
    budget = params(per_run={"requests": 1})
    assert all([(await run(ctx, ask(), budget)).action == Action.allow for _ in range(3)])


# --- warnings ---------------------------------------------------------------------------


async def test_warning_before_the_budget_is_used_up(ctx):
    budget = params(default={"tokens_per_day": 100, "warn_at": 0.8})
    assert types(await run(ctx, reply(50, 0), budget)) == []
    warned = await run(ctx, reply(30, 0), budget)
    assert warned.action == Action.allow
    assert types(warned) == ["budget_warning"]
    assert "used 80 of 100 tokens today (80%, warning at 80%)" in warned.reason
    assert types(await run(ctx, ask(), budget)) == ["budget_warning"]


async def test_run_warnings(ctx):
    budget = params(per_run={"requests": 4, "warn_at": 0.5})
    verdicts = [await run(ctx, ask(run_id=RUN), budget) for _ in range(2)]
    assert types(verdicts[0]) == []
    assert "this run made 2 of 4 requests (50%" in verdicts[1].reason


async def test_no_warn_at_means_no_warning(ctx):
    await run(ctx, reply(99, 0), DAILY)
    assert types(await run(ctx, ask(), DAILY)) == []


# --- Modes through the pipeline ---------------------------------------------------------


def policy_with_mode(mode: str):
    return parse_policy(
        f"controls:\n  token_budget:\n    mode: {mode}\n    params:\n"
        "      default: {tokens_per_day: 100, warn_at: 0.5}\n",
        REGISTRY,
    )


async def test_monitor_mode_counts_and_reports_but_allows(ctx):
    policy = policy_with_mode("monitor")
    await run_check(reply(150, 0), policy, ctx=ctx)
    result = await run_check(ask(), policy, ctx=ctx)
    assert result.decision.action == Action.allow
    assert result.decision.verdicts[0].action == Action.block


async def test_block_mode_blocks_with_explanation(ctx):
    policy = policy_with_mode("block")
    await run_check(reply(150, 0), policy, ctx=ctx)
    result = await run_check(ask(), policy, ctx=ctx)
    assert result.decision.action == Action.block
    assert result.decision.reason.startswith("Blocked by token_budget: Agent research-assistant")


async def test_warning_shows_in_the_decision_reason(ctx):
    policy = policy_with_mode("block")
    result = await run_check(reply(60, 0), policy, ctx=ctx)
    assert result.decision.action == Action.allow
    assert result.decision.reason.startswith("Allowed; warnings: token_budget: Agent")
    assert result.decision.findings[0].type == "budget_warning"


async def test_missing_storage_is_a_control_error():
    result = await run_check(ask(), policy_with_mode("block"))
    assert result.decision.action == Action.block
    assert result.decision.verdicts[0].error


# --- end to end -------------------------------------------------------------------------

BUDGET_POLICY = BASE_POLICY.replace("controls:\n", """controls:
  token_budget:
    mode: block
    params:
      default: {tokens_per_day: 30, warn_at: 0.5}
      per_run: {requests: 3}
""")


@pytest.fixture
def budget_client(make_firewall_app):
    from test_proxy import RecordingUpstream

    upstream = RecordingUpstream()  # reports 11 prompt + 7 completion tokens per call
    return TestClient(make_firewall_app(BUDGET_POLICY, upstream_transport=upstream)), upstream


def test_proxy_counts_provider_tokens_and_stops_the_agent(budget_client):
    from test_proxy import HEADERS, completion

    client, upstream = budget_client

    def call(text: str):
        body = completion(model="remote-model", messages=[{"role": "user", "content": text}])
        return client.post("/v1/chat/completions", json=body, headers=HEADERS).json()

    first = call("first question")
    assert first["choices"][0]["finish_reason"] == "stop"
    assert "warnings: token_budget" in first["firewall"]["output"]["decision"]["reason"]
    assert call("second question")["choices"][0]["finish_reason"] == "stop"  # 36 of 30 now
    third = call("third question")
    assert third["choices"][0]["finish_reason"] == "content_filter"
    assert "used 36 of 30 tokens today" in third["firewall"]["reason"]
    assert "owner owner@bank.example" in third["firewall"]["reason"]
    assert len(upstream.requests) == 2  # the over-budget request never reached the model

    usage = client.get("/v1/settings/budgets").json()
    assert usage["agents"] == [
        {"id": "test-agent", "used": 36, "limit": 30, "percent": 120.0, "state": "exhausted"}
    ]


def test_proxy_input_and_output_share_the_run(budget_client):
    from test_proxy import HEADERS, completion

    client, _ = budget_client
    messages = [{"role": "user", "content": "start"}]
    for _ in range(2):
        client.post("/v1/chat/completions", headers=HEADERS,
                    json=completion(model="remote-model", messages=messages))
        messages += [{"role": "assistant", "content": "ok"}, {"role": "user", "content": "go"}]
    runs = client.get("/v1/settings/budgets").json()["runs"]
    assert len(runs) == 1
    assert runs[0]["requests"]["used"] == 2
    assert runs[0]["tokens"]["used"] == 36  # both replies counted towards the run


def test_check_api_run_limit_by_session_id(budget_client, agent_headers):
    client, _ = budget_client
    body = {"messages": [{"role": "user", "content": "step"}],
            "metadata": {"session_id": "task-1"}}
    actions = [
        client.post("/v1/check/input", json=body, headers=agent_headers).json()["decision"]
        for _ in range(4)
    ]
    assert [d["action"] for d in actions] == ["allow", "allow", "allow", "block"]
    assert actions[3]["findings"][0]["type"] == "run_requests_exceeded"


def test_check_api_counts_reported_usage(budget_client, agent_headers):
    client, _ = budget_client
    body = {"message": {"role": "assistant", "content": "hi"},
            "usage": {"model": "mock", "prompt_tokens": 25, "completion_tokens": 10}}
    client.post("/v1/check/output", json=body, headers=agent_headers)
    blocked = client.post("/v1/check/input", headers=agent_headers,
                          json={"messages": [{"role": "user", "content": "hi"}]}).json()
    assert blocked["decision"]["action"] == "block"


def test_raising_the_limit_applies_on_the_next_request(make_firewall_app, tmp_policy,
                                                       agent_headers):
    client = TestClient(make_firewall_app(BUDGET_POLICY))
    body = {"message": {"role": "assistant", "content": "hi"},
            "usage": {"model": "mock", "prompt_tokens": 40, "completion_tokens": 0}}
    client.post("/v1/check/output", json=body, headers=agent_headers)
    ask_body = {"messages": [{"role": "user", "content": "hi"}]}
    assert client.post("/v1/check/input", json=ask_body,
                       headers=agent_headers).json()["decision"]["action"] == "block"
    tmp_policy(BUDGET_POLICY.replace("tokens_per_day: 30", "tokens_per_day: 1000"))
    assert client.post("/v1/check/input", json=ask_body,
                       headers=agent_headers).json()["decision"]["action"] == "allow"
