"""UC-06 (part 3): no single request, reply or Resource call may be huge (R3).

A budget stops an Agent that spends too much over time. `request_limits` stops the one giant
interaction: a context bomb as the prompt, an unbounded reply, an oversized argument or a
Resource result that would flood the model. What can be fixed is fixed (the reply is
truncated, `max_tokens` is lowered) and the request goes on; what cannot (a prompt that is
simply too big) is blocked before it costs anything.

Sizes come from `policy.yaml`: prompt 8000 tokens, reply 2048, tool arguments 4000,
Resource result 8000, 100 messages. Tokens are estimated as characters / 4.
"""

from __future__ import annotations

import json
import time

import pytest

pytestmark = [pytest.mark.uc("UC-06"), pytest.mark.req("R3")]

MARKER = "[truncated by AI Control Layer]"
BIG_PROMPT = "lorem " * 6000  # about 9000 tokens, over the 8000 limit
FINE_PROMPT = "lorem " * 1000  # about 1500 tokens


# ---- 1. the prompt ---------------------------------------------------------------------------


def test_an_oversized_prompt_is_stopped_before_the_model(gateway):
    reply = gateway.chat(BIG_PROMPT)

    assert reply.blocked
    assert "prompt ~9000 tokens > limit 8000" in reply.reason
    assert not reply.reached_the_model


def test_the_explanation_does_not_quote_the_prompt(gateway):
    reply = gateway.chat(BIG_PROMPT)

    assert "lorem lorem" not in json.dumps(reply.firewall)


def test_a_normal_prompt_passes(gateway):
    reply = gateway.chat(FINE_PROMPT)

    assert not reply.blocked
    assert reply.firewall["action"] == "allow"


def test_a_very_long_conversation_is_stopped(gateway):
    messages = [
        {"role": "user" if i % 2 == 0 else "assistant", "content": f"turn {i}"}
        for i in range(101)
    ]

    reply = gateway.chat(messages=messages)

    assert reply.blocked
    assert "101 messages > limit 100" in reply.reason


def test_a_request_for_too_long_a_reply_is_lowered_not_refused(gateway):
    result = gateway.check(
        "input", {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 99999}
    )

    assert result["decision"]["action"] == "redact"
    assert result["max_tokens"] == 2048
    assert "max_tokens 99999 > limit 2048" in result["decision"]["reason"]


# ---- 2. the reply ----------------------------------------------------------------------------


def test_an_endless_reply_is_cut_and_still_delivered(gateway):
    text = "word " * 3000  # the mock model reports about 3000 completion tokens

    reply = gateway.chat(text)

    assert reply.finish_reason == "stop", "a truncated reply is delivered, not refused"
    assert reply.firewall["action"] == "redact"
    assert reply.answer.endswith(MARKER)
    assert len(reply.answer) < len(text)


def test_a_reply_within_the_ceiling_is_untouched(gateway):
    reply = gateway.chat("word " * 100)

    assert MARKER not in reply.answer
    assert reply.firewall["action"] == "allow"


# ---- 3. Resource calls and results -----------------------------------------------------------


def test_oversized_tool_arguments_are_blocked(gateway):
    call = {"tool": {"resource": "crm", "action": "search", "args": {"query": "a" * 20000}}}

    decision = gateway.check("tool_call", call)["decision"]

    assert decision["action"] == "block"
    assert "arguments" in decision["reason"] and "tokens > limit 4000" in decision["reason"]


def test_small_tool_arguments_are_allowed(gateway):
    call = {"tool": {"resource": "crm", "action": "search", "args": {"query": "Kowalska"}}}

    assert gateway.check("tool_call", call)["decision"]["action"] == "allow"


def test_an_oversized_resource_result_is_cut_before_it_floods_the_model(gateway):
    result = gateway.check(
        "tool_result",
        {
            "tool": {"resource": "crm", "action": "export", "args": {}},
            "tool_result": "lorem " * 7000,  # about 10500 tokens, over the 8000 limit
        },
    )

    assert result["decision"]["action"] == "redact"
    assert result["tool_result"].endswith(MARKER)
    assert len(result["tool_result"]) < 42000


# ---- 4. the operator tunes it in the Policy --------------------------------------------------


def test_lowering_the_limit_in_the_policy_applies_to_the_next_request(gateway):
    assert not gateway.chat(FINE_PROMPT).blocked

    gateway.policy.set_params("request_limits", max_prompt_tokens=100)

    assert gateway.chat(FINE_PROMPT).blocked


def test_monitor_mode_records_but_lets_the_request_through(gateway):
    gateway.policy.set_mode("request_limits", "monitor")

    reply = gateway.chat(BIG_PROMPT)

    assert not reply.blocked
    verdicts = reply.firewall["input"]["decision"]["verdicts"]
    seen = next(v for v in verdicts if v["control"] == "request_limits")
    assert seen["action"] == "block" and seen["effective_action"] == "allow"


def test_off_mode_does_not_run_the_control(gateway):
    gateway.policy.set_mode("request_limits", "off")

    assert not gateway.chat(BIG_PROMPT).blocked


# ---- 5. robustness: size must not mean stalling ---------------------------------------------

# Text shaped to make a pattern search restart over and over. Each is ~30-40k characters.
HOSTILE = {
    "one long word": "x" * 40000,
    "dotted word": "a." * 15000,
    "digits": "1" * 30000,
    "digit groups": "1 " * 15000,
    "at signs": "x@" * 15000,
    "obfuscated at": "x[at]" * 6000,
    "brackets": "[a](" * 7500,
    "image openings": "![](" * 7500,
    "key headers": "-----BEGIN PRIVATE KEY-----" * 1100,
}


@pytest.mark.parametrize("shape", HOSTILE)
def test_text_shaped_to_slow_a_pattern_does_not_stall_the_firewall(gateway, shape):
    """One slow check holds up every Agent, because the firewall runs in a single thread. The
    email patterns once took ~1s for 10k characters of one word and ~18s for 40k; now the name
    before @ is capped. The same input must be quick as a Resource result and as an answer."""
    text = HOSTILE[shape]
    call = {"tool": {"resource": "crm", "action": "export", "args": {}}, "tool_result": text}

    started = time.perf_counter()
    gateway.check("tool_result", call)
    result_seconds = time.perf_counter() - started

    started = time.perf_counter()
    gateway.chat(text[:30000])
    answer_seconds = time.perf_counter() - started

    assert result_seconds < 1.0, f"a Resource result of this shape took {result_seconds:.1f}s"
    assert answer_seconds < 1.0, f"an answer of this shape took {answer_seconds:.1f}s"
