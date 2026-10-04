"""UC-06 (part 1): a runaway Agent is stopped (R3).

The story behind it is incident 3 of the stakeholder summary: a market-monitoring Agent goes
from a few calls a day to tens of thousands and the owner learns it from the bill. The
`loop_detector` Control sees the same request over and over (numbers do not count, so "BTC at
101.5" and "BTC at 101.7" are one request), stops the Agent before the model is called and
keeps it stopped (circuit breaker) until the cooldown ends or an operator resets it.

Numbers below come from the `standard` Preset: 5 identical requests per minute, 30 calls per
minute, 5 minutes cooldown. Time is a fake clock, so nothing here waits.
"""

from __future__ import annotations

import pytest

from test_suites.harness import TRADER_KEY

pytestmark = [pytest.mark.uc("UC-06"), pytest.mark.req("R3")]


def watch(gateway, price: float, **kwargs):
    """The Agent asks the same thing again and again; only the number changes."""
    return gateway.chat(f"Market update: BTC at {price}. Anything to report?", **kwargs)


def similar_limit(gateway) -> int:
    """How many identical requests a minute the policy allows."""
    return gateway.policy.load()["controls"]["loop_detector"]["params"]["max_similar"]


def trip(gateway, **kwargs):
    """Make the Agent loop until it is stopped; returns the reply that was blocked."""
    for i in range(10):
        reply = watch(gateway, 100 + i / 10, **kwargs)
        if reply.blocked:
            return reply
    raise AssertionError("the Agent was never stopped")


# ---- 1. the loop is stopped, normal work is not ---------------------------------------------


def test_an_agent_repeating_itself_is_stopped_before_the_model(gateway):
    limit = similar_limit(gateway)
    for i in range(limit):
        assert not watch(gateway, 101.0 + i / 10).blocked, f"the first {limit} are allowed"

    over = watch(gateway, 101.9)

    assert over.blocked
    assert over.firewall["action"] == "block"
    assert "identical requests" in over.reason
    assert not over.reached_the_model, "a stopped request must never cost model tokens"
    assert "alice@bank.example" in over.reason, "the owner is named, so someone can be called"


def test_the_stopped_agent_stays_stopped_for_any_request(gateway):
    trip(gateway)

    other = gateway.chat("What is the weather in Krakow?")

    assert other.blocked
    assert "circuit breaker open" in other.reason
    assert [b["agent_id"] for b in gateway.breakers()] == ["research-assistant"]


def test_one_looping_agent_does_not_stop_the_others(gateway):
    trip(gateway)

    assert gateway.chat("What is the weather in Krakow?").blocked
    assert not gateway.chat("What is the weather in Krakow?", key=TRADER_KEY).blocked


def test_normal_traffic_is_not_stopped(gateway):
    for i in range(12):
        reply = gateway.chat(f"Question number {i} about a different topic: {'abc' * i}")
        assert not reply.blocked


def test_the_same_question_asked_slowly_is_fine(gateway):
    """Two a minute is under the limit. (Eight asks, 4 minutes: a longer conversation would be
    stopped by the 5-minute run limit of `token_budget`, which is a different Control.)"""
    for _ in range(8):
        assert not gateway.chat("Is the build green?").blocked
        gateway.clock.advance(30)


def test_a_fast_burst_of_different_requests_hits_the_call_rate_limit(gateway):
    gateway.policy.set_params("loop_detector", max_calls=4, max_similar=100)

    replies = [gateway.chat(f"Topic {i}: {'x' * i}") for i in range(5)]

    assert [r.blocked for r in replies] == [False, False, False, False, True]
    assert "calls in 60s" in replies[-1].reason


# ---- 2. getting the Agent running again -----------------------------------------------------


def test_an_operator_can_let_the_agent_run_again(gateway):
    trip(gateway)
    assert gateway.reset_breaker("research-assistant") == 200

    assert gateway.breakers() == []
    assert not gateway.chat("What is the weather in Krakow?").blocked


def test_resetting_an_agent_that_is_not_stopped_is_a_404(gateway):
    assert gateway.reset_breaker("research-assistant") == 404


def test_the_agent_runs_again_by_itself_after_the_cooldown(gateway):
    trip(gateway)
    gateway.clock.advance(120)
    assert gateway.chat("What is the weather in Krakow?").blocked, "still inside 5 minutes"

    gateway.clock.advance(300)

    assert not gateway.chat("What is the weather in Krakow?").blocked


# ---- 3. the operator tunes it in the Policy -------------------------------------------------


def test_lowering_the_limit_in_the_policy_applies_to_the_next_request(gateway):
    assert not watch(gateway, 1.0).blocked and not watch(gateway, 1.1).blocked

    gateway.policy.set_params("loop_detector", max_similar=2)

    assert watch(gateway, 1.2).blocked, "the third identical request is now over the limit"


def test_numbers_can_be_made_to_count_as_different_requests(gateway):
    gateway.policy.set_params("loop_detector", ignore_numbers=False)

    assert not any(watch(gateway, 100 + i / 10).blocked for i in range(8))


def test_monitor_only_records_the_loop(gateway):
    gateway.policy.set_mode("loop_detector", "monitor")
    gateway.policy.set_params("loop_detector", breaker_cooldown_seconds=0)

    replies = [watch(gateway, 100 + i / 10) for i in range(12)]

    assert not any(r.blocked for r in replies), "the Agent keeps working"
    verdicts = replies[-1].firewall["input"]["decision"]["verdicts"]
    seen = next(v for v in verdicts if v["control"] == "loop_detector")
    assert seen["action"] == "block" and seen["effective_action"] == "allow"
    assert seen["findings"], "but the loop is on record"
    assert gateway.breakers() == []


def test_off_mode_does_not_run_the_control(gateway):
    gateway.policy.set_mode("loop_detector", "off")

    assert not any(watch(gateway, 100 + i / 10).blocked for i in range(12))


# ---- 4. a Resource call loop, and the audit trail -------------------------------------------


def test_an_agent_looping_on_a_resource_call_is_stopped(gateway):
    call = {"tool": {"resource": "trading", "action": "get_quote", "args": {"symbol": "BTC"}}}

    limit = similar_limit(gateway)

    actions = [gateway.check("tool_call", call)["decision"]["action"] for _ in range(limit + 1)]

    assert actions == ["allow"] * limit + ["block"]


def test_the_stop_is_in_the_audit_log_with_the_owner(gateway):
    trip(gateway)

    (event,) = gateway.events(stage="input", action="block")
    assert event["agent_id"] == "research-assistant"
    assert event["owner"] == "alice@bank.example"
    assert "repeated_request" in {f["type"] for f in event["findings"]}
    assert "loop_detector" in {v["control"] for v in event["verdicts"]}
