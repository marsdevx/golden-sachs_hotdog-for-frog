"""UC-06 (part 2): a cost spike is stopped by a token budget (R3).

`token_budget` counts the tokens the model reports and blocks the NEXT request once a budget is
used up, before the model is called. A reply that is already produced is never thrown away:
the request that crosses the line is delivered, the one after it is stopped.

Budgets exist per Agent per UTC day, per user per UTC day and per run (one conversation or
task, named with `metadata.session_id`). Counts are raw tokens, so a local model is counted like
a paid one.

The built-in `mock` model reports words as tokens: a request of four words costs 4 prompt +
6 completion (the answer is "Mock response: " plus the echo) = 10 tokens. Limits are lowered in
the Policy so a test needs a handful of calls, not thousands.
"""

from __future__ import annotations

import pytest

from test_suites.harness import TRADER_KEY

pytestmark = [pytest.mark.uc("UC-06"), pytest.mark.req("R3")]

TOKENS_PER_CALL = 10
WORDS = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "kilo"]


def ask(gateway, n: int, **kwargs):
    """A four-word request, different every time so the loop detector stays out of the way."""
    word = WORDS[n % len(WORDS)]
    return gateway.chat(f"{word} {word} {word} {word}", **kwargs)


@pytest.fixture
def small_budget(gateway):
    """Agent budget of 25 tokens a day: three calls fit (the third crosses it), the fourth stops."""
    gateway.policy.set_params("token_budget", default={"tokens_per_day": 25, "warn_at": 0.5})
    return gateway


# ---- 1. the Agent's daily budget ------------------------------------------------------------


def test_a_used_up_budget_stops_the_next_request_before_the_model(small_budget):
    replies = [ask(small_budget, i) for i in range(4)]

    assert [r.blocked for r in replies] == [False, False, False, True]
    assert all(r.finish_reason == "stop" for r in replies[:3]), "earlier replies are delivered"
    stopped = replies[3]
    assert "of 25 tokens today" in stopped.reason
    assert "alice@bank.example" in stopped.reason, "the owner is named"
    assert not stopped.reached_the_model


def test_a_warning_comes_before_the_stop(small_budget):
    ask(small_budget, 0)
    second = ask(small_budget, 1)  # 20 of 25 tokens: past 50 percent

    assert not second.blocked
    assert "budget_warning" in second.dump()


def test_the_dashboard_view_shows_the_usage_and_the_state(small_budget):
    for i in range(3):
        ask(small_budget, i)

    view = small_budget.budgets()

    assert view["mode"] == "block"
    (agent,) = view["agents"]
    assert agent["id"] == "research-assistant"
    assert agent["used"] == 3 * TOKENS_PER_CALL and agent["limit"] == 25
    assert agent["state"] == "exhausted"


def test_other_agents_have_their_own_budget(small_budget):
    for i in range(4):
        ask(small_budget, i)

    assert ask(small_budget, 5).blocked
    assert not ask(small_budget, 5, key=TRADER_KEY).blocked


# ---- 2. per user and per run ----------------------------------------------------------------


def test_each_user_has_their_own_budget(gateway):
    gateway.policy.set_params("token_budget", per_user={"tokens_per_day": 15})

    ivan = [ask(gateway, i, user="ivan") for i in range(3)]
    olga = ask(gateway, 5, user="olga")

    assert [r.blocked for r in ivan] == [False, False, True]
    assert "user ivan" in ivan[2].reason
    assert not olga.blocked


def test_one_run_cannot_make_more_requests_than_its_limit(gateway):
    gateway.policy.set_params("token_budget", per_run={"requests": 3})

    task = [ask(gateway, i, session_id="task-1") for i in range(4)]
    another = ask(gateway, 5, session_id="task-2")

    assert [r.blocked for r in task] == [False, False, False, True]
    assert "this run made 4 requests > limit 3" in task[3].reason
    assert not another.blocked, "a new run starts with a clean count"


def test_one_run_cannot_make_more_resource_calls_than_its_limit(gateway):
    gateway.policy.set_params("token_budget", per_run={"tool_calls": 3})

    def call(i: int) -> dict:
        # Different words, not numbers: the loop detector ignores numbers and would stop it first.
        body = {
            "tool": {"resource": "crm", "action": "read_client", "args": {"client": WORDS[i]}},
            "metadata": {"session_id": "task-1"},
        }
        return gateway.check("tool_call", body)["decision"]

    decisions = [call(i) for i in range(4)]

    assert [d["action"] for d in decisions] == ["allow", "allow", "allow", "block"]
    assert "Resource calls > limit 3" in decisions[3]["reason"]


# ---- 3. the operator changes the picture in the Policy, or time passes ----------------------


def test_raising_the_budget_in_the_policy_lets_the_agent_continue(small_budget):
    for i in range(4):
        ask(small_budget, i)
    assert ask(small_budget, 4).blocked

    small_budget.policy.set_params("token_budget", default={"tokens_per_day": 1000})

    assert not ask(small_budget, 5).blocked


def test_the_budget_starts_again_at_the_next_utc_day(small_budget):
    for i in range(4):
        ask(small_budget, i)
    assert ask(small_budget, 4).blocked

    small_budget.clock.advance_to_next_utc_day()

    assert not ask(small_budget, 5).blocked


def test_monitor_mode_counts_and_reports_but_never_stops(small_budget):
    small_budget.policy.set_mode("token_budget", "monitor")

    replies = [ask(small_budget, i) for i in range(6)]

    assert not any(r.blocked for r in replies)
    verdicts = replies[-1].firewall["input"]["decision"]["verdicts"]
    seen = next(v for v in verdicts if v["control"] == "token_budget")
    assert seen["action"] == "block" and seen["effective_action"] == "allow"
    assert small_budget.budgets()["agents"][0]["state"] == "exhausted"


def test_off_mode_does_not_run_the_control(small_budget):
    small_budget.policy.set_mode("token_budget", "off")

    assert not any(ask(small_budget, i).blocked for i in range(6))


def test_monitor_has_the_same_limits_but_only_warns(gateway):
    gateway.policy.set_mode("token_budget", "monitor")
    gateway.policy.set_params("token_budget", default={"tokens_per_day": 25, "warn_at": 0.5})

    replies = [ask(gateway, i) for i in range(5)]

    assert not any(r.blocked for r in replies)
    assert "budget_warning" in replies[1].dump()


# ---- 4. the audit trail ---------------------------------------------------------------------


def test_the_stop_is_in_the_audit_log_with_the_owner(small_budget):
    for i in range(4):
        ask(small_budget, i)

    (event,) = small_budget.events(stage="input", action="block")

    assert event["agent_id"] == "research-assistant"
    assert event["owner"] == "alice@bank.example"
    assert "daily_tokens_exhausted" in {f["type"] for f in event["findings"]}
    spent = small_budget.events(stage="output", action="allow")
    assert sum(e["prompt_tokens"] + e["completion_tokens"] for e in spent) >= 3 * TOKENS_PER_CALL
