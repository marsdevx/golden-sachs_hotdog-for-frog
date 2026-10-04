"""State of `token_budget`: tokens per UTC day (per Agent and per user) and per-run counters.

Shared by the Control (through `ctx.db`) and the settings API (budget usage). Counters are
incremented with `UPDATE ... SET n = n + :delta`, so concurrent Checks do not lose counts.
Portable SQL only (ADR 0002); timestamps are naive UTC."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from firewall_app.storage.db import BudgetDayRow, BudgetRunRow


@dataclass(frozen=True, slots=True)
class Run:
    agent_id: str
    run_id: str
    started_at: datetime
    last_seen: datetime
    requests: int
    tool_calls: int
    tokens: int

    @classmethod
    def from_row(cls, row: BudgetRunRow) -> Run:
        return cls(row.agent_id, row.run_id, row.started_at, row.last_seen,
                   row.requests, row.tool_calls, row.tokens)


@dataclass(frozen=True, slots=True)
class Day:
    scope: str
    subject: str
    tokens: int


class BudgetState:
    def __init__(self, sessions) -> None:
        self.sessions = sessions  # SQLAlchemy async_sessionmaker

    async def day_tokens(self, scope: str, subject: str, day: str) -> int:
        async with self.sessions() as session:
            row = await session.get(BudgetDayRow, (scope, subject, day))
        return row.tokens if row else 0

    async def add_day_tokens(self, scope: str, subject: str, day: str, tokens: int) -> int:
        """Add tokens to a day and return its new total."""
        rows = BudgetDayRow
        key = (rows.scope == scope, rows.subject == subject, rows.day == day)
        for _ in range(2):  # a concurrent first insert of the same day: retry as an update
            try:
                async with self.sessions.begin() as session:
                    result = await session.execute(
                        update(rows).where(*key).values(tokens=rows.tokens + tokens)
                    )
                    if result.rowcount == 0:
                        session.add(rows(scope=scope, subject=subject, day=day, tokens=tokens))
                break
            except IntegrityError:
                continue
        return await self.day_tokens(scope, subject, day)

    async def touch_run(
        self,
        agent_id: str,
        run_id: str,
        now: datetime,
        idle_seconds: int,
        requests: int = 0,
        tool_calls: int = 0,
        tokens: int = 0,
    ) -> Run:
        """Count activity in a run and return it. A run idle for longer than `idle_seconds`
        is over: the next activity starts a new run with the same id."""
        rows = BudgetRunRow
        key = (rows.agent_id == agent_id, rows.run_id == run_id)
        for _ in range(2):
            try:
                async with self.sessions.begin() as session:
                    row = await session.get(rows, (agent_id, run_id))
                    if row is None:
                        session.add(rows(agent_id=agent_id, run_id=run_id, started_at=now,
                                         last_seen=now, requests=requests,
                                         tool_calls=tool_calls, tokens=tokens))
                    elif (now - row.last_seen).total_seconds() > idle_seconds:
                        await session.execute(
                            update(rows).where(*key).values(
                                started_at=now, last_seen=now, requests=requests,
                                tool_calls=tool_calls, tokens=tokens,
                            )
                        )
                    else:
                        await session.execute(
                            update(rows).where(*key).values(
                                last_seen=now,
                                requests=rows.requests + requests,
                                tool_calls=rows.tool_calls + tool_calls,
                                tokens=rows.tokens + tokens,
                            )
                        )
                break
            except IntegrityError:
                continue
        async with self.sessions() as session:
            row = await session.get(rows, (agent_id, run_id), populate_existing=True)
        return Run.from_row(row)

    async def days(self, day: str) -> list[Day]:
        statement = select(BudgetDayRow).where(BudgetDayRow.day == day).order_by(
            BudgetDayRow.scope, BudgetDayRow.tokens.desc()
        )
        async with self.sessions() as session:
            rows = (await session.scalars(statement)).all()
        return [Day(row.scope, row.subject, row.tokens) for row in rows]

    async def runs(self, active_since: datetime) -> list[Run]:
        """Runs with activity since `active_since`, most recent first."""
        statement = (
            select(BudgetRunRow)
            .where(BudgetRunRow.last_seen >= active_since)
            .order_by(BudgetRunRow.last_seen.desc())
        )
        async with self.sessions() as session:
            rows = (await session.scalars(statement)).all()
        return [Run.from_row(row) for row in rows]
