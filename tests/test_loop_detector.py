"""Tests for the `loop_detector` Control: call rate, repeats, the circuit
breaker and its settings endpoints, with a real SQLite store and a fake clock."""

from datetime import datetime, timedelta

import pytest
from conftest import BASE_POLICY
from fastapi.testclient import TestClient
from firewall_app.controls import REGISTRY
from firewall_app.controls.base import ControlContext
from firewall_app.controls.loop_detector import LoopDetector, fingerprint
from firewall_app.domain import Action, Agent, Check, Message, Stage, ToolCall
from firewall_app.pipeline import run_check
from firewall_app.policy import parse_policy
from firewall_app.storage.db import create_all, create_engine, create_sessionmaker

AGENT = Agent(id="market-watcher", owner="carol@bank.example", team="trading-desk")
OTHER = Agent(id="research-assistant", owner="alice@bank.example")
PARAMS = LoopDetector.Params(
    window_seconds=60, max_calls=10, max_similar=3, breaker_cooldown_seconds=0
)


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
    engine = create_engine(f"sqlite+aiosqlite:///{tmp_path / 'loop.db'}")
    await create_all(engine)
    yield ControlContext(db=create_sessionmaker(engine), clock=clock)
    await engine.dispose()


def ask(text: str, agent: Agent = AGENT, **metadata) -> Check:
    return Check(stage=Stage.input, agent=agent, metadata=metadata,
                 messages=[Message(role="user", content=text)])


def tool(action: str = "book_trade", **args) -> Check:
    return Check(stage=Stage.tool_call, agent=AGENT,
                 tool=ToolCall(resource="trading", action=action, args=args))


async def run(ctx, check: Check, params=PARAMS):
    return await LoopDetector(ctx).evaluate(check, params)


async def run_many(ctx, checks, params=PARAMS):
    return [await run(ctx, check, params) for check in checks]


def test_registered():
    assert REGISTRY.get("loop_detector") is LoopDetector
    assert LoopDetector.stages == {Stage.input, Stage.tool_call}


# --- fingerprints ------------------------------------------------------------------------


def test_fingerprint_ignores_numbers_case_and_spacing():
    a = fingerprint(ask("BTC moved to 101.5, buy?"), ignore_numbers=True)
    b = fingerprint(ask("btc  moved to 101,7,   BUY?"), ignore_numbers=True)
    assert a == b
    assert a != fingerprint(ask("ETH moved to 101.5, buy?"), ignore_numbers=True)
    assert fingerprint(ask("price 1"), ignore_numbers=False) != fingerprint(
        ask("price 2"), ignore_numbers=False
    )


def test_fingerprint_does_not_contain_the_content():
    assert "secret" not in fingerprint(ask("secret deal"), ignore_numbers=True)


def test_tool_fingerprint_uses_resource_action_and_args():
    assert fingerprint(tool(qty=100), True) == fingerprint(tool(qty=250), True)
    assert fingerprint(tool(qty=100), True) != fingerprint(tool("cancel", qty=100), True)
    assert fingerprint(tool(qty=100), False) != fingerprint(tool(qty=250), False)


# --- allowed and blocked ----------------------------------------------------------------


async def test_normal_traffic_is_allowed(ctx):
    verdicts = await run_many(ctx, [ask(f"question about topic {name}") for name in "abcde"])
    assert all(v.action == Action.allow and not v.findings for v in verdicts)


async def test_repeated_request_is_blocked_after_max_similar(ctx):
    *first, fourth = await run_many(ctx, [ask(f"BTC at {100 + i}.5, buy?") for i in range(4)])
    assert all(v.action == Action.allow for v in first)
    assert fourth.action == Action.block
    assert fourth.findings[0].type == "repeated_request"
    assert "4 identical requests in 60s > limit 3" in fourth.reason


async def test_numbers_count_when_ignore_numbers_is_off(ctx):
    params = PARAMS.model_copy(update={"ignore_numbers": False})
    verdicts = await run_many(ctx, [ask(f"BTC at {100 + i}") for i in range(5)], params)
    assert all(v.action == Action.allow for v in verdicts)


async def test_repeats_spread_over_time_are_allowed(ctx, clock):
    for _ in range(6):
        assert (await run(ctx, ask("status?"))).action == Action.allow
        clock.advance(30)  # two per window, under max_similar


async def test_call_rate_is_limited_per_window(ctx, clock):
    verdicts = await run_many(ctx, [ask(f"question {chr(97 + i)}") for i in range(11)])
    assert all(v.action == Action.allow for v in verdicts[:10])
    assert verdicts[10].findings[0].type == "call_rate"
    clock.advance(61)
    assert (await run(ctx, ask("a fresh question"))).action == Action.allow


async def test_agents_do_not_share_counters(ctx):
    await run_many(ctx, [ask("status?")] * 3)
    assert (await run(ctx, ask("status?", agent=OTHER))).action == Action.allow
    assert (await run(ctx, ask("status?"))).action == Action.block


async def test_repeated_tool_call_loop_is_blocked(ctx):
    verdicts = await run_many(ctx, [tool(symbol="BTC", qty=100 + i) for i in range(4)])
    assert [v.action for v in verdicts] == [Action.allow] * 3 + [Action.block]


# --- circuit breaker --------------------------------------------------------------------

BREAKER = PARAMS.model_copy(update={"breaker_cooldown_seconds": 300})


async def test_breaker_stops_every_call_until_cooldown_ends(ctx, clock):
    await run_many(ctx, [ask("BTC at 101, buy?")] * 3, BREAKER)
    tripped = await run(ctx, ask("BTC at 102, buy?"), BREAKER)
    assert tripped.action == Action.block
    assert "circuit breaker open for 300s, owner carol@bank.example" in tripped.reason

    clock.advance(10)
    unrelated = await run(ctx, ask("Something completely different"), BREAKER)
    assert unrelated.action == Action.block
    assert unrelated.findings[0].type == "circuit_breaker_open"
    assert "until 12:05:00 UTC" in unrelated.reason
    assert (await run(ctx, tool(qty=1), BREAKER)).action == Action.block
    assert (await run(ctx, ask("hi", agent=OTHER), BREAKER)).action == Action.allow

    clock.advance(300)
    assert (await run(ctx, ask("Something completely different"), BREAKER)).action == (
        Action.allow
    )


async def test_without_breaker_only_offending_calls_are_blocked(ctx):
    await run_many(ctx, [ask("status?")] * 4)
    assert (await run(ctx, ask("a different question"))).action == Action.allow


async def test_missing_storage_is_a_control_error():
    policy = parse_policy("controls:\n  loop_detector:\n    mode: block\n", REGISTRY)
    result = await run_check(ask("hi"), policy)  # default ControlContext: no db
    assert result.decision.action == Action.block
    assert result.decision.verdicts[0].error


# --- Modes through the pipeline ---------------------------------------------------------


def policy_with_mode(mode: str):
    return parse_policy(
        f"controls:\n  loop_detector:\n    mode: {mode}\n    params:\n"
        "      max_similar: 2\n      breaker_cooldown_seconds: 0\n",
        REGISTRY,
    )


async def test_monitor_mode_records_but_allows(ctx):
    policy = policy_with_mode("monitor")
    results = [await run_check(ask("status?"), policy, ctx=ctx) for _ in range(3)]
    assert results[2].decision.action == Action.allow
    assert results[2].decision.verdicts[0].action == Action.block
    assert results[2].decision.findings[0].type == "repeated_request"


async def test_block_mode_blocks_with_explanation(ctx):
    policy = policy_with_mode("block")
    results = [await run_check(ask("status?"), policy, ctx=ctx) for _ in range(3)]
    assert results[2].decision.action == Action.block
    assert results[2].decision.reason.startswith("Blocked by loop_detector: 3 identical")


# --- end to end: proxy and settings API ----------------------------------------------------

LOOP_POLICY = BASE_POLICY.replace("controls:\n", """controls:
  loop_detector:
    mode: block
    params:
      max_similar: 3
      breaker_cooldown_seconds: 300
""")


def test_runaway_agent_is_stopped_before_the_model_and_can_be_reset(make_firewall_app):
    from test_proxy import HEADERS, RecordingUpstream, completion

    upstream = RecordingUpstream()
    client = TestClient(make_firewall_app(LOOP_POLICY, upstream_transport=upstream))

    def call(text: str):
        messages = [{"role": "user", "content": text}]
        return client.post(
            "/v1/chat/completions",
            json=completion(model="remote-model", messages=messages),
            headers=HEADERS,
        ).json()

    replies = [call(f"BTC moved to {100 + i}.5, what now?") for i in range(6)]
    finish = [reply["choices"][0]["finish_reason"] for reply in replies]
    assert finish == ["stop"] * 3 + ["content_filter"] * 3
    assert len(upstream.requests) == 3  # the loop never reached the model again
    assert "circuit breaker open" in replies[5]["firewall"]["reason"]

    breakers = client.get("/v1/settings/breakers").json()
    assert [b["agent_id"] for b in breakers] == ["test-agent"]
    assert "identical requests" in breakers[0]["reason"]

    assert client.delete("/v1/settings/breakers/test-agent").json() == {
        "agent_id": "test-agent", "reset": True
    }
    assert client.get("/v1/settings/breakers").json() == []
    assert call("A new question")["choices"][0]["finish_reason"] == "stop"
    assert client.delete("/v1/settings/breakers/test-agent").status_code == 404


def test_blocked_loop_calls_are_audited(make_firewall_app, agent_headers):
    client = TestClient(make_firewall_app(LOOP_POLICY))
    body = {"messages": [{"role": "user", "content": "status?"}]}
    for _ in range(4):
        client.post("/v1/check/input", json=body, headers=agent_headers)
    events = client.get("/v1/settings/events", params={"action": "block"}).json()
    assert len(events) == 1
    assert events[0]["findings"][0]["type"] == "repeated_request"
