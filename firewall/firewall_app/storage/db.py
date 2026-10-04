"""SQLAlchemy async engine and tables. Portable SQL only: Postgres in Compose, SQLite in tests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Integer, String, Text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.pool import NullPool


class Base(DeclarativeBase):
    pass


class AuditEventRow(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    check_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)  # naive UTC
    stage: Mapped[str] = mapped_column(String(32), index=True)
    transport: Mapped[str] = mapped_column(String(32))
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    owner: Mapped[str] = mapped_column(String(255))
    team: Mapped[str | None] = mapped_column(String(255), nullable=True)
    user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    model: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(16), index=True)
    reason: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Float)
    findings: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    verdicts: Mapped[list[dict[str, Any]]] = mapped_column(JSON)
    policy_version: Mapped[str] = mapped_column(String(64))
    total_latency_ms: Mapped[float] = mapped_column(Float)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    completion_tokens: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_before: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    content_after: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON)


class LoopObservationRow(Base):
    """One call seen by `loop_detector`: a fingerprint, never the content itself."""

    __tablename__ = "loop_observations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)  # naive UTC
    agent_id: Mapped[str] = mapped_column(String(255), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)


class CircuitBreakerRow(Base):
    """An Agent stopped by `loop_detector` until `open_until`."""

    __tablename__ = "circuit_breakers"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    opened_at: Mapped[datetime] = mapped_column(DateTime)  # naive UTC
    open_until: Mapped[datetime] = mapped_column(DateTime)
    reason: Mapped[str] = mapped_column(Text)


class BudgetDayRow(Base):
    """Tokens used on one UTC day by one subject (`scope` is `agent` or `user`)."""

    __tablename__ = "budget_days"

    scope: Mapped[str] = mapped_column(String(16), primary_key=True)
    subject: Mapped[str] = mapped_column(String(255), primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)  # YYYY-MM-DD, UTC
    tokens: Mapped[int] = mapped_column(Integer, default=0)


class BudgetRunRow(Base):
    """One Agent run (see runs.py): what it has used since it started."""

    __tablename__ = "budget_runs"

    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime)  # naive UTC
    last_seen: Mapped[datetime] = mapped_column(DateTime, index=True)
    requests: Mapped[int] = mapped_column(Integer, default=0)
    tool_calls: Mapped[int] = mapped_column(Integer, default=0)
    tokens: Mapped[int] = mapped_column(Integer, default=0)


def create_engine(database_url: str) -> AsyncEngine:
    if database_url.startswith("sqlite"):
        # aiosqlite connections are bound to the event loop that opened them; tests use several.
        return create_async_engine(database_url, poolclass=NullPool)
    return create_async_engine(database_url, pool_pre_ping=True)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker:
    return async_sessionmaker(engine, expire_on_commit=False)


async def create_all(engine: AsyncEngine) -> None:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
