"""One test per pipeline rule (spec "Pipeline semantics"), with test-only Controls."""

import asyncio

from firewall_app.controls.base import Control, Registry
from firewall_app.domain import (
    Action,
    Agent,
    Check,
    Content,
    Finding,
    Message,
    Stage,
    Verdict,
)
from firewall_app.pipeline import run_check
from firewall_app.policy import parse_policy
from pydantic import BaseModel

registry = Registry()
SEEN: dict[str, list[str]] = {}


@registry.control("always_allow")
class AlwaysAllow(Control):
    stages = {Stage.input, Stage.output}
    feature = "input_validation"

    async def evaluate(self, check, params):
        return Verdict()


@registry.control("always_redact")
class AlwaysRedact(Control):
    """Replaces every input message's content with a marker."""

    stages = {Stage.input}
    feature = "input_validation"

    class Params(BaseModel):
        marker: str = "[R]"

    async def evaluate(self, check, params):
        messages = [m.model_copy(update={"content": params.marker}) for m in check.messages]
        return Verdict(
            action=Action.redact,
            reason="redacted everything",
            risk_score=0.4,
            findings=[Finding(control="", type="everything", detail="all of it")],
            rewritten=Content(messages=messages),
        )


@registry.control("always_block")
class AlwaysBlock(Control):
    stages = {Stage.input, Stage.output}
    feature = "input_validation"

    async def evaluate(self, check, params):
        return Verdict(action=Action.block, reason="always blocks", risk_score=0.9)


@registry.control("block_with_rewrite")
class BlockWithRewrite(Control):
    stages = {Stage.input}
    feature = "input_validation"

    async def evaluate(self, check, params):
        messages = [m.model_copy(update={"content": "safe"}) for m in check.messages]
        return Verdict(action=Action.block, reason="unsafe", rewritten=Content(messages=messages))


@registry.control("always_review")
class AlwaysReview(Control):
    stages = {Stage.input}
    feature = "input_validation"

    async def evaluate(self, check, params):
        return Verdict(action=Action.review, reason="needs a human", risk_score=0.6)


@registry.control("raises")
class Raises(Control):
    stages = {Stage.input}
    feature = "input_validation"

    async def evaluate(self, check, params):
        raise ZeroDivisionError("boom")


@registry.control("recorder")
class Recorder(Control):
    """Records the content it saw, keyed by the Check id."""

    stages = {Stage.input, Stage.output, Stage.tool_call}
    feature = "input_validation"

    async def evaluate(self, check, params):
        SEEN.setdefault(check.check_id, []).extend(m.content for m in check.messages)
        return Verdict()


@registry.control("slow")
class Slow(Control):
    stages = {Stage.input}
    feature = "input_validation"

    async def evaluate(self, check, params):
        await asyncio.sleep(0.02)
        return Verdict()


AGENT = Agent(id="a", owner="o")


def policy(controls: str, on_error: str = "block"):
    text = f"defaults:\n  on_error: {on_error}\ncontrols:\n{controls}"
    return parse_policy(text, registry)


def input_check(text="hello"):
    return Check(stage=Stage.input, agent=AGENT, messages=[Message(role="user", content=text)])


async def run(controls: str, check=None, **kwargs):
    return await run_check(check or input_check(), policy(controls, **kwargs), registry)


def ran(result):
    return [v.control for v in result.decision.verdicts]


async def test_rule1_policy_order_and_only_active_controls_at_this_stage():
    result = await run(
        "  recorder: {mode: monitor}\n"
        "  always_block: {mode: off}\n"
        "  always_allow: {mode: block, stages: [output]}\n"
        "  slow: {mode: block}\n"
    )
    assert ran(result) == ["recorder", "slow"]

    reordered = await run("  slow: {mode: block}\n  recorder: {mode: monitor}\n")
    assert ran(reordered) == ["slow", "recorder"]

    tool_check = Check(stage=Stage.tool_call, agent=AGENT)
    assert ran(await run("  recorder: {mode: block}\n  slow: {mode: block}\n", tool_check)) == [
        "recorder"
    ]


async def test_rule2_redactions_chain():
    check = input_check("secret")
    result = await run(
        "  always_redact: {mode: redact, params: {marker: '[X]'}}\n  recorder: {mode: block}\n",
        check,
    )
    assert SEEN[check.check_id] == ["[X]"]
    assert result.after.messages[0].content == "[X]"
    assert result.before.messages[0].content == "secret"
    assert result.decision.action == Action.redact


async def test_rule2_monitor_does_not_rewrite():
    check = input_check("secret")
    result = await run("  always_redact: {mode: monitor}\n  recorder: {mode: block}\n", check)
    assert SEEN[check.check_id] == ["secret"]
    assert result.after.messages[0].content == "secret"


async def test_rule3_short_circuit_on_first_effective_block():
    result = await run(
        "  always_allow: {mode: block}\n  always_block: {mode: block}\n  recorder: {mode: block}\n"
    )
    assert ran(result) == ["always_allow", "always_block"]
    assert result.decision.action == Action.block


async def test_rule3_monitored_block_does_not_short_circuit():
    result = await run("  always_block: {mode: monitor}\n  always_allow: {mode: block}\n")
    assert ran(result) == ["always_block", "always_allow"]


async def test_rule4_error_follows_on_error_block():
    result = await run("  raises: {mode: block}\n  always_allow: {mode: block}\n")
    verdict = result.decision.verdicts[0]
    assert verdict.action == Action.block and verdict.error
    assert verdict.reason == "control error: ZeroDivisionError"
    assert result.decision.action == Action.block
    assert ran(result) == ["raises"]


async def test_rule4_error_follows_on_error_allow_and_per_control_override():
    result = await run("  raises: {mode: block}\n", on_error="allow")
    assert result.decision.action == Action.allow
    assert result.decision.verdicts[0].reason == "control error: ZeroDivisionError"

    overridden = await run("  raises: {mode: block, on_error: block}\n", on_error="allow")
    assert overridden.decision.action == Action.block


async def test_rule5_monitor_never_changes_outcome():
    result = await run("  always_block: {mode: monitor}\n")
    verdict = result.decision.verdicts[0]
    assert verdict.action == Action.block
    assert verdict.effective_action == Action.allow
    assert result.decision.action == Action.allow
    assert "always_block" in result.decision.reason


async def test_rule5_redact_mode_downgrades_block_only_with_rewritten_content():
    with_rewrite = await run("  block_with_rewrite: {mode: redact}\n")
    assert with_rewrite.decision.verdicts[0].action == Action.block
    assert with_rewrite.decision.verdicts[0].effective_action == Action.redact
    assert with_rewrite.after.messages[0].content == "safe"

    without_rewrite = await run("  always_block: {mode: redact}\n")
    assert without_rewrite.decision.verdicts[0].effective_action == Action.allow
    assert without_rewrite.decision.action == Action.allow


async def test_rule5_block_mode_uses_the_verdict_as_is():
    result = await run("  always_review: {mode: block}\n")
    assert result.decision.verdicts[0].effective_action == Action.review
    assert result.decision.action == Action.review


async def test_rule6_most_severe_action_max_risk_all_findings_and_explained_reason():
    result = await run(
        "  always_redact: {mode: redact}\n  always_review: {mode: block}\n"
        "  always_block: {mode: monitor}\n"
    )
    decision = result.decision
    assert decision.action == Action.review
    assert decision.risk_score == 0.9
    assert [f.control for f in decision.findings] == ["always_redact"]
    assert decision.reason == "Held for review by always_review: needs a human"

    blocked = await run("  always_redact: {mode: redact}\n  always_block: {mode: block}\n")
    assert blocked.decision.reason == "Blocked by always_block: always blocks"

    clean = await run("  always_allow: {mode: block}\n")
    assert clean.decision.reason == "No Control objected"


async def test_rule6_policy_version_is_stamped():
    p = policy("  always_allow: {mode: block}\n")
    p._version = "abc123"
    result = await run_check(input_check(), p, registry)
    assert result.decision.policy_version == "abc123"


async def test_rule7_latency_per_control_and_total():
    result = await run("  slow: {mode: block}\n  always_allow: {mode: block}\n")
    slow, fast = result.decision.verdicts
    assert slow.latency_ms >= 15
    assert fast.latency_ms >= 0
    assert result.decision.latency_ms >= slow.latency_ms + fast.latency_ms


async def test_rule8_one_audit_event_per_check(tmp_path):
    from firewall_app.identity import Identity
    from firewall_app.service import CheckService
    from firewall_app.storage import AuditStore

    audit = AuditStore(f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}")
    service = CheckService(audit, registry)
    identity = Identity(agent=AGENT, known=True, allowed=True)
    p = policy("  always_allow: {mode: block}\n  always_block: {mode: monitor}\n")
    first = await service.run(input_check(), p, identity)
    second = await service.run(input_check(), p, identity)
    events = await audit.query()
    assert [e.check_id for e in events] == [second.before.check_id, first.before.check_id]
    assert all(e.action == "allow" for e in events)
    verdicts = events[0].verdicts
    assert [(v["control"], v["action"], v["effective_action"]) for v in verdicts] == [
        ("always_allow", "allow", "allow"),
        ("always_block", "block", "allow"),
    ]
    await audit.close()
