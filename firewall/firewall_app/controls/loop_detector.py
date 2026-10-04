"""Stops runaway Agents: too many calls, or the same request over and over. When a loop is
detected the Agent's circuit breaker opens and every call it makes is blocked until the
cooldown ends (or the user resets it from the settings API). Requests per run are counted by
`token_budget` (`per_run.requests`), not here.

Repeats are found with a fingerprint of the request with numbers removed, so a market-watching
Agent reacting to its own price moves ("BTC at 101.5", "BTC at 101.7") counts as repeating.
Only fingerprints are stored, never the content."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import timedelta

from pydantic import BaseModel, Field

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Finding, Stage, Verdict
from firewall_app.storage.loop_state import Counts, LoopState

_NUMBER = re.compile(r"\d+(?:[.,]\d+)*")
_SPACE = re.compile(r"\s+")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def _normalize(text: str, ignore_numbers: bool) -> str:
    text = text.casefold()
    if ignore_numbers:
        text = _NUMBER.sub("#", text)
    return _SPACE.sub(" ", text).strip()


def fingerprint(check: Check, ignore_numbers: bool) -> str:
    """The same request made again has the same fingerprint."""
    if check.stage == Stage.tool_call and check.tool is not None:
        args = json.dumps(check.tool.args, sort_keys=True, ensure_ascii=False, default=str)
        key = f"{check.tool.resource}.{check.tool.action}:{args}"
        return "tool:" + _digest(_normalize(key, ignore_numbers))
    users = [message for message in check.messages if message.role == "user"]
    latest = (users or check.messages)[-1].content if check.messages else ""
    return "input:" + _digest(_normalize(latest, ignore_numbers))


@control("loop_detector")
class LoopDetector(Control):
    stages = {Stage.input, Stage.tool_call}
    feature = "usage_limits"
    description = "Stops runaway Agents that repeat themselves or call too often."

    class Params(BaseModel):
        window_seconds: int = Field(60, ge=1)
        max_calls: int | None = Field(30, ge=1)  # per Agent in the window
        max_similar: int | None = Field(5, ge=1)  # same request per Agent in the window
        ignore_numbers: bool = True  # "price 101.5" and "price 101.7" are the same request
        breaker_cooldown_seconds: int = Field(300, ge=0)  # 0: block only the offending calls

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        if self.ctx.db is None:
            raise RuntimeError("loop_detector needs storage")
        state = LoopState(self.ctx.db)
        now = self.ctx.clock()
        agent_id = check.agent.id

        breaker = await state.open_breaker(agent_id, now)
        if breaker is not None:
            return Verdict(
                action=Action.block,
                reason=f"circuit breaker open until {breaker.open_until:%H:%M:%S} UTC "
                f"({breaker.reason})",
                risk_score=1.0,
                findings=[Finding(control=self.id, type="circuit_breaker_open",
                                  detail=f"Agent {agent_id} is stopped; owner "
                                  f"{check.agent.owner}")],
            )

        counts = await state.record_and_count(
            agent_id,
            fingerprint(check, params.ignore_numbers),
            now,
            since=now - timedelta(seconds=params.window_seconds),
        )
        findings = self._findings(counts, params)
        if not findings:
            return Verdict()
        reason = "; ".join(finding.detail for finding in findings)
        if params.breaker_cooldown_seconds:
            until = now + timedelta(seconds=params.breaker_cooldown_seconds)
            await state.trip(agent_id, now, until, reason)
            reason += (
                f"; circuit breaker open for {params.breaker_cooldown_seconds}s, "
                f"owner {check.agent.owner}"
            )
        return Verdict(action=Action.block, reason=reason, risk_score=0.9, findings=findings)

    def _findings(self, counts: Counts, params: Params) -> list[Finding]:
        window = f"{params.window_seconds}s"
        checks = [
            ("call_rate", counts.calls, params.max_calls, f"calls in {window}"),
            ("repeated_request", counts.repeats, params.max_similar,
             f"identical requests in {window}"),
        ]
        return [
            Finding(control=self.id, type=kind, detail=f"{count} {what} > limit {limit}")
            for kind, count, limit, what in checks
            if limit is not None and count > limit
        ]
