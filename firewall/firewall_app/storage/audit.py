"""AuditStore: one immutable Audit Event per Check, queries, export and metrics."""

from __future__ import annotations

import csv
import io
import json
import math
from collections import defaultdict
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import select

from firewall_app.domain import Action
from firewall_app.pipeline import PipelineResult
from firewall_app.policy.schema import Policy
from firewall_app.storage.db import (
    AuditEventRow,
    create_all,
    create_engine,
    create_sessionmaker,
)

ExportFormat = Literal["jsonl", "csv"]


class AuditEvent(BaseModel):
    check_id: str
    ts: datetime
    stage: str
    transport: str
    agent_id: str
    owner: str
    team: str | None = None
    user: str | None = None
    model: str | None = None
    action: Action
    reason: str
    risk_score: float
    findings: list[dict[str, Any]] = Field(default_factory=list)
    verdicts: list[dict[str, Any]] = Field(default_factory=list)
    policy_version: str
    total_latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    content_before: dict[str, Any] | None = None
    content_after: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_result(cls, result: PipelineResult, policy: Policy) -> AuditEvent:
        check, decision = result.before, result.decision
        store = policy.audit.store_content
        usage = check.usage or result.after.usage
        return cls(
            check_id=check.check_id,
            ts=datetime.now(UTC),
            stage=check.stage,
            transport=check.transport,
            agent_id=check.agent.id,
            owner=check.agent.owner,
            team=check.agent.team,
            user=check.user,
            model=usage.model if usage else None,
            action=decision.action,
            reason=decision.reason,
            risk_score=decision.risk_score,
            findings=[finding.model_dump(mode="json") for finding in decision.findings],
            verdicts=[
                verdict.model_dump(mode="json", exclude={"rewritten", "findings"})
                | {"findings": len(verdict.findings)}
                for verdict in decision.verdicts
            ],
            policy_version=decision.policy_version,
            total_latency_ms=decision.latency_ms,
            prompt_tokens=usage.prompt_tokens if usage else None,
            completion_tokens=usage.completion_tokens if usage else None,
            content_before=_content(result.before) if store == "full" else None,
            content_after=_content(result.after) if store in ("full", "redacted") else None,
            metadata=check.metadata,
        )


def _content(check) -> dict[str, Any]:
    return check.content().model_dump(mode="json", exclude_none=True)


def _to_naive_utc(value: datetime) -> datetime:
    if value.tzinfo is not None:
        value = value.astimezone(UTC).replace(tzinfo=None)
    return value


_FIELDS = list(AuditEvent.model_fields)


def _row_to_event(row: AuditEventRow) -> AuditEvent:
    data = {name: getattr(row, name) for name in _FIELDS if name != "metadata"}
    data["metadata"] = row.metadata_ or {}
    data["ts"] = row.ts.replace(tzinfo=UTC)
    return AuditEvent.model_validate(data)


def percentile(values: list[float], pct: float) -> float | None:
    """Nearest-rank percentile, computed in Python so the SQL stays portable."""
    if not values:
        return None
    ordered = sorted(values)
    rank = max(1, math.ceil(pct / 100 * len(ordered)))
    return round(ordered[rank - 1], 3)


class AuditStore:
    def __init__(self, database_url: str) -> None:
        self.engine = create_engine(database_url)
        self.sessions = create_sessionmaker(self.engine)
        self._ready = False

    async def init(self) -> None:
        # Idempotent; also called lazily because ASGI test transports skip the app lifespan.
        if not self._ready:
            await create_all(self.engine)
            self._ready = True

    async def close(self) -> None:
        await self.engine.dispose()

    async def append(self, event: AuditEvent) -> None:
        await self.init()
        data = event.model_dump(mode="python")
        data["metadata_"] = data.pop("metadata")
        data["ts"] = _to_naive_utc(event.ts)
        data["action"] = str(event.action)
        async with self.sessions.begin() as session:
            session.add(AuditEventRow(**data))

    def _select(self, stage, agent_id, action, since):
        statement = select(AuditEventRow)
        if stage:
            statement = statement.where(AuditEventRow.stage == str(stage))
        if agent_id:
            statement = statement.where(AuditEventRow.agent_id == agent_id)
        if action:
            statement = statement.where(AuditEventRow.action == str(action))
        if since:
            statement = statement.where(AuditEventRow.ts >= _to_naive_utc(since))
        return statement

    async def query(
        self,
        stage: str | None = None,
        agent_id: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
        session_id: str | None = None,
    ) -> list[AuditEvent]:
        """Audit Events, newest first."""
        await self.init()
        statement = self._select(stage, agent_id, action, since)
        if session_id is not None:
            statement = statement.where(
                AuditEventRow.metadata_["session_id"].as_string() == session_id
            )
        statement = statement.order_by(AuditEventRow.id.desc()).limit(limit)
        async with self.sessions() as session:
            rows = (await session.scalars(statement)).all()
        return [_row_to_event(row) for row in rows]

    async def iter_events(
        self,
        stage: str | None = None,
        agent_id: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        batch_size: int = 500,
    ) -> AsyncIterator[AuditEvent]:
        """All matching Audit Events, oldest first, fetched in batches."""
        await self.init()
        last_id = 0
        while True:
            statement = self._select(stage, agent_id, action, since)
            statement = (
                statement.where(AuditEventRow.id > last_id)
                .order_by(AuditEventRow.id)
                .limit(batch_size)
            )
            async with self.sessions() as session:
                rows = (await session.scalars(statement)).all()
            for row in rows:
                yield _row_to_event(row)
            if len(rows) < batch_size:
                return
            last_id = rows[-1].id

    async def export(self, export_format: ExportFormat, **filters: Any) -> AsyncIterator[str]:
        if export_format == "jsonl":
            async for event in self.iter_events(**filters):
                yield event.model_dump_json() + "\n"
            return
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=_FIELDS)
        writer.writeheader()
        async for event in self.iter_events(**filters):
            row = event.model_dump(mode="json")
            for name, value in row.items():
                if isinstance(value, dict | list):
                    row[name] = json.dumps(value, ensure_ascii=False)
            writer.writerow(row)
            yield buffer.getvalue()
            buffer.seek(0)
            buffer.truncate()
        if buffer.getvalue():
            yield buffer.getvalue()

    async def metrics(self) -> dict[str, Any]:
        by_action: dict[str, int] = defaultdict(int)
        by_stage: dict[str, int] = defaultdict(int)
        by_control: dict[str, dict[str, int]] = defaultdict(
            lambda: {"evaluated": 0, "fired": 0, "blocked": 0, "redacted": 0, "errors": 0}
        )
        by_agent: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "owner": None,
                "team": None,
                "checks": 0,
                "blocked": 0,
                "redacted": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            }
        )
        total_latency: list[float] = []
        control_latency: dict[str, list[float]] = defaultdict(list)
        total = 0

        async for event in self.iter_events():
            total += 1
            by_action[event.action] += 1
            by_stage[event.stage] += 1
            total_latency.append(event.total_latency_ms)
            agent = by_agent[event.agent_id]
            agent["owner"], agent["team"] = event.owner, event.team
            agent["checks"] += 1
            agent["blocked"] += event.action == Action.block
            agent["redacted"] += event.action == Action.redact
            prompt, completion = event.prompt_tokens or 0, event.completion_tokens or 0
            agent["prompt_tokens"] += prompt
            agent["completion_tokens"] += completion
            agent["total_tokens"] += prompt + completion
            for verdict in event.verdicts:
                stats = by_control[verdict["control"]]
                stats["evaluated"] += 1
                stats["fired"] += verdict["action"] != Action.allow
                stats["blocked"] += verdict.get("effective_action") == Action.block
                stats["redacted"] += verdict.get("effective_action") == Action.redact
                stats["errors"] += bool(verdict.get("error"))
                control_latency[verdict["control"]].append(verdict.get("latency_ms", 0.0))

        prompt_total = sum(agent["prompt_tokens"] for agent in by_agent.values())
        completion_total = sum(agent["completion_tokens"] for agent in by_agent.values())
        return {
            "total_checks": total,
            "by_action": {action.value: by_action.get(action.value, 0) for action in Action},
            "by_stage": dict(by_stage),
            "by_control": dict(by_control),
            "by_agent": dict(by_agent),
            "tokens": {
                "prompt": prompt_total,
                "completion": completion_total,
                "total": prompt_total + completion_total,
            },
            "latency_ms": {
                "total": {
                    "p50": percentile(total_latency, 50),
                    "p95": percentile(total_latency, 95),
                },
                "controls": {
                    control_id: {"p50": percentile(values, 50), "p95": percentile(values, 95)}
                    for control_id, values in control_latency.items()
                },
            },
        }
