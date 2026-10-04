"""State of `loop_detector`: recent call fingerprints and open circuit breakers.

Shared by the Control (through `ctx.db`) and the settings API (list and reset breakers).
Portable SQL only (ADR 0002); timestamps are naive UTC."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import delete, func, select

from firewall_app.storage.db import CircuitBreakerRow, LoopObservationRow


@dataclass(frozen=True, slots=True)
class Breaker:
    agent_id: str
    opened_at: datetime
    open_until: datetime
    reason: str

    @classmethod
    def from_row(cls, row: CircuitBreakerRow) -> Breaker:
        return cls(row.agent_id, row.opened_at, row.open_until, row.reason)


@dataclass(frozen=True, slots=True)
class Counts:
    calls: int  # by this Agent in the window
    repeats: int  # with the same fingerprint, by this Agent, in the window


class LoopState:
    def __init__(self, sessions) -> None:
        self.sessions = sessions  # SQLAlchemy async_sessionmaker

    async def open_breaker(self, agent_id: str, now: datetime) -> Breaker | None:
        async with self.sessions() as session:
            row = await session.get(CircuitBreakerRow, agent_id)
        if row is None or row.open_until <= now:
            return None
        return Breaker.from_row(row)

    async def trip(self, agent_id: str, now: datetime, until: datetime, reason: str) -> None:
        async with self.sessions.begin() as session:
            await session.merge(
                CircuitBreakerRow(agent_id=agent_id, opened_at=now, open_until=until,
                                  reason=reason)
            )

    async def reset(self, agent_id: str) -> bool:
        async with self.sessions.begin() as session:
            result = await session.execute(
                delete(CircuitBreakerRow).where(CircuitBreakerRow.agent_id == agent_id)
            )
        return result.rowcount > 0

    async def breakers(self, now: datetime) -> list[Breaker]:
        """Breakers open at `now`, the ones closing last first."""
        statement = (
            select(CircuitBreakerRow)
            .where(CircuitBreakerRow.open_until > now)
            .order_by(CircuitBreakerRow.open_until.desc())
        )
        async with self.sessions() as session:
            rows = (await session.scalars(statement)).all()
        return [Breaker.from_row(row) for row in rows]

    async def record_and_count(
        self,
        agent_id: str,
        fingerprint: str,
        now: datetime,
        since: datetime,
    ) -> Counts:
        """Record one call, forget this Agent's calls older than the window, and count
        (the new call included)."""
        rows = LoopObservationRow
        async with self.sessions.begin() as session:
            await session.execute(delete(rows).where(rows.agent_id == agent_id, rows.ts < since))
            session.add(rows(ts=now, agent_id=agent_id, fingerprint=fingerprint))
            await session.flush()
            recent = select(func.count()).where(rows.agent_id == agent_id, rows.ts >= since)
            calls = await session.scalar(recent)
            repeats = await session.scalar(recent.where(rows.fingerprint == fingerprint))
        return Counts(calls=calls or 0, repeats=repeats or 0)
