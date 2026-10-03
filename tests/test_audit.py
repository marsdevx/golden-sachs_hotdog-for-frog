import csv
import io
import json
from datetime import UTC, datetime, timedelta

import pytest
from conftest import AGENT_KEY, BASE_POLICY
from firewall_app.controls import REGISTRY
from firewall_app.domain import Check, Message, Stage, Usage
from firewall_app.identity import resolve_agent
from firewall_app.policy import parse_policy
from firewall_app.service import CheckService
from firewall_app.storage import AuditStore


@pytest.fixture
async def audit(tmp_path):
    store = AuditStore(f"sqlite+aiosqlite:///{tmp_path / 'audit.db'}")
    yield store
    await store.close()


def policy_with(store_content="redacted"):
    text = BASE_POLICY.replace("store_content: redacted", f"store_content: {store_content}")
    return parse_policy(text, REGISTRY)


async def run(audit, text, stage=Stage.input, key=AGENT_KEY, policy=None, usage=None):
    policy = policy or policy_with()
    identity = resolve_agent({"x-agent-key": key}, policy)
    message = Message(role="user" if stage == Stage.input else "assistant", content=text)
    check = Check(
        stage=stage,
        agent=identity.agent,
        user="bob",
        messages=[message] if stage == Stage.input else [],
        message=message if stage == Stage.output else None,
        usage=usage,
    )
    return await CheckService(audit).run(check, policy, identity)


async def test_one_event_per_check_including_allowed(audit):
    allowed = await run(audit, "hello")
    blocked = await run(audit, "project falcon")
    events = await audit.query()
    assert [e.check_id for e in events] == [blocked.before.check_id, allowed.before.check_id]
    newest, oldest = events
    assert oldest.action == "allow" and newest.action == "block"
    assert newest.agent_id == "test-agent"
    assert newest.owner == "owner@bank.example"
    assert newest.team == "test-team"
    assert newest.user == "bob"
    assert newest.transport == "check_api"
    assert newest.policy_version == blocked.decision.policy_version
    assert "keyword_blocklist" in newest.reason
    assert newest.findings[0]["control"] == "keyword_blocklist"
    verdict = newest.verdicts[0]
    assert verdict["action"] == "block" and verdict["effective_action"] == "block"
    assert verdict["latency_ms"] >= 0
    assert newest.total_latency_ms >= 0


async def test_unknown_agent_is_blocked_and_recorded(audit):
    result = await run(audit, "hello", key="nope")
    assert result.decision.action == "block"
    assert result.decision.reason == "unknown agent"
    (event,) = await audit.query()
    assert event.agent_id == "unknown"
    assert event.reason == "unknown agent"


async def test_tokens_and_model_are_recorded(audit):
    usage = Usage(model="mock", prompt_tokens=3, completion_tokens=5)
    await run(audit, "fine", stage=Stage.output, usage=usage)
    (event,) = await audit.query()
    assert (event.model, event.prompt_tokens, event.completion_tokens) == ("mock", 3, 5)


async def test_filters(audit):
    await run(audit, "hello")
    await run(audit, "project falcon")
    await run(audit, "fine", stage=Stage.output)
    await run(audit, "hello", key="nope")
    assert len(await audit.query(stage="output")) == 1
    assert len(await audit.query(action="block")) == 2
    assert len(await audit.query(agent_id="test-agent")) == 3
    assert len(await audit.query(limit=2)) == 2
    future = datetime.now(UTC) + timedelta(minutes=1)
    assert await audit.query(since=future) == []
    assert len(await audit.query(since=datetime.now(UTC) - timedelta(minutes=1))) == 4


async def test_store_content_modes(audit):
    await run(audit, "about project falcon", policy=policy_with("full"))
    await run(audit, "about project falcon", policy=policy_with("redacted"))
    await run(audit, "about project falcon", policy=policy_with("none"))
    none, redacted, full = await audit.query()
    assert full.content_before["messages"][0]["content"] == "about project falcon"
    assert full.content_after is not None
    assert redacted.content_before is None
    assert redacted.content_after["messages"][0]["content"] == "about project falcon"
    assert none.content_before is None and none.content_after is None


async def test_redacted_mode_stores_post_firewall_content(audit):
    policy = parse_policy(
        BASE_POLICY.replace("mode: block", "mode: redact"), REGISTRY
    )
    await run(audit, "about project falcon", policy=policy)
    (event,) = await audit.query()
    assert event.content_after["messages"][0]["content"] == "about [REDACTED]"


async def collect(stream):
    return "".join([chunk async for chunk in stream])


async def test_export_jsonl_and_csv(audit):
    await run(audit, "hello")
    await run(audit, "project falcon")
    lines = (await collect(audit.export("jsonl"))).splitlines()
    assert [json.loads(line)["action"] for line in lines] == ["allow", "block"]

    rows = list(csv.DictReader(io.StringIO(await collect(audit.export("csv")))))
    assert [row["action"] for row in rows] == ["allow", "block"]
    assert json.loads(rows[1]["findings"])[0]["control"] == "keyword_blocklist"

    blocked_only = await collect(audit.export("jsonl", action="block"))
    assert len(blocked_only.splitlines()) == 1


async def test_export_pages_through_many_events(audit):
    for index in range(7):
        await run(audit, f"hello {index}")
    events = [event async for event in audit.iter_events(batch_size=3)]
    assert len(events) == 7


async def test_metrics_shape(audit):
    await run(audit, "hello")
    await run(audit, "project falcon")
    await run(audit, "ok", stage=Stage.output, usage=Usage(prompt_tokens=2, completion_tokens=3))
    metrics = await audit.metrics()
    assert metrics["total_checks"] == 3
    assert metrics["by_action"] == {"allow": 2, "redact": 0, "review": 0, "block": 1}
    control = metrics["by_control"]["keyword_blocklist"]
    assert control == {"evaluated": 3, "fired": 1, "blocked": 1, "redacted": 0, "errors": 0}
    agent = metrics["by_agent"]["test-agent"]
    assert agent["checks"] == 3 and agent["blocked"] == 1 and agent["total_tokens"] == 5
    assert metrics["tokens"] == {"prompt": 2, "completion": 3, "total": 5}
    assert metrics["latency_ms"]["total"]["p95"] is not None
    assert set(metrics["latency_ms"]["controls"]["keyword_blocklist"]) == {"p50", "p95"}
