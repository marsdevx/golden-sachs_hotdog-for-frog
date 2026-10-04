"""Hard token budgets: how many tokens an Agent and each user may use per UTC day, and what one
Agent run (one conversation or task, see runs.py) may use in requests, Resource calls, tokens
and time. Raw token counts only, for paid and local models alike.

- `input`: blocks the request when a budget is already used up, before the model is called.
- `tool_call`: counts the call and enforces the run's limits.
- `output`: counts the tokens the reply used. It never blocks the reply (the tokens are already
  spent); the next request is blocked instead.

With `warn_at`, a budget past that share is reported as a `budget_warning` Finding on an
allowed Check, so the warning shows up in the Decision, the audit log and the dashboard."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Finding, Stage, Verdict
from firewall_app.storage.budget_state import BudgetState, Run

WarnAt = Field(None, gt=0, le=1)


class DailyBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tokens_per_day: int | None = Field(None, ge=1)
    warn_at: float | None = WarnAt  # e.g. 0.8: warn at 80% of the budget


class RunBudget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests: int | None = Field(None, ge=1)  # LLM calls in one run
    tool_calls: int | None = Field(None, ge=1)  # Resource calls in one run
    tokens: int | None = Field(None, ge=1)
    wall_clock_seconds: int | None = Field(None, ge=1)  # from the run's first call
    idle_seconds: int = Field(600, ge=1)  # a run with no call for this long is over
    warn_at: float | None = WarnAt


def _share(used: int, limit: int) -> str:
    return f"{used:,} of {limit:,}"


@control("token_budget")
class TokenBudget(Control):
    stages = {Stage.input, Stage.tool_call, Stage.output}
    feature = "usage_limits"
    description = "Stops an Agent, user or run that has used up its token budget."

    class Params(BaseModel):
        default: DailyBudget = Field(default_factory=DailyBudget)  # the Agent, per UTC day
        per_user: DailyBudget = Field(default_factory=DailyBudget)  # each `user`, per UTC day
        per_run: RunBudget = Field(default_factory=RunBudget)

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        if self.ctx.db is None:
            raise RuntimeError("token_budget needs storage")
        self.state = BudgetState(self.ctx.db)
        self.now = self.ctx.clock()
        self.day = self.now.date().isoformat()
        self.blocks: list[Finding] = []
        self.warnings: list[Finding] = []

        if check.stage == Stage.output:
            await self._account(check, params)
        else:
            await self._enforce(check, params)

        if self.blocks:
            return Verdict(
                action=Action.block,
                reason="; ".join(f.detail for f in self.blocks)
                + f" (owner {check.agent.owner})",
                risk_score=0.9,
                findings=self.blocks + self.warnings,
            )
        if self.warnings:
            return Verdict(
                reason="; ".join(f.detail for f in self.warnings),
                risk_score=0.3,
                findings=self.warnings,
            )
        return Verdict()

    async def _enforce(self, check: Check, params: Params) -> None:
        """Before a request or Resource call: is any budget already used up?"""
        if check.stage == Stage.input:
            used = await self.state.day_tokens("agent", check.agent.id, self.day)
            self._daily("daily_tokens", f"Agent {check.agent.id}", used, params.default)
            if check.user:
                used = await self.state.day_tokens("user", check.user, self.day)
                self._daily("user_daily_tokens", f"user {check.user}", used, params.per_user)
        if check.run_id is not None:
            calls = {"requests": 1} if check.stage == Stage.input else {"tool_calls": 1}
            run = await self.state.touch_run(
                check.agent.id, check.run_id, self.now, params.per_run.idle_seconds, **calls
            )
            self._run(run, params.per_run, check.stage)

    async def _account(self, check: Check, params: Params) -> None:
        """After a reply: count its tokens and report budgets that are now low or used up."""
        usage = check.usage
        if usage is None or (usage.prompt_tokens is None and usage.completion_tokens is None):
            return
        tokens = (usage.prompt_tokens or 0) + (usage.completion_tokens or 0)
        used = await self.state.add_day_tokens("agent", check.agent.id, self.day, tokens)
        self._daily("daily_tokens", f"Agent {check.agent.id}", used, params.default)
        if check.user:
            used = await self.state.add_day_tokens("user", check.user, self.day, tokens)
            self._daily("user_daily_tokens", f"user {check.user}", used, params.per_user)
        if check.run_id is not None:
            run = await self.state.touch_run(
                check.agent.id, check.run_id, self.now, params.per_run.idle_seconds,
                tokens=tokens,
            )
            self._run(run, params.per_run, check.stage)
        # The reply already exists: a used-up budget is reported, and the next request blocks.
        self.warnings = self.blocks + self.warnings
        self.blocks = []

    def _daily(self, kind: str, who: str, used: int, budget: DailyBudget) -> None:
        limit = budget.tokens_per_day
        if limit is None:
            return
        if used >= limit:
            self._block(f"{kind}_exhausted", f"{who} used {_share(used, limit)} tokens today")
        else:
            self._warn(used, limit, budget.warn_at, f"{who} used {_share(used, limit)} "
                       "tokens today")

    def _run(self, run: Run, budget: RunBudget, stage: Stage) -> None:
        elapsed = int((self.now - run.started_at).total_seconds())
        if budget.requests is not None:
            if run.requests > budget.requests:
                self._block("run_requests_exceeded",
                            f"this run made {run.requests} requests > limit {budget.requests}")
            elif stage == Stage.input:
                self._warn(run.requests, budget.requests, budget.warn_at,
                           f"this run made {_share(run.requests, budget.requests)} requests")
        if budget.tool_calls is not None:
            if run.tool_calls > budget.tool_calls:
                self._block("run_tool_calls_exceeded",
                            f"this run made {run.tool_calls} Resource calls "
                            f"> limit {budget.tool_calls}")
            elif stage == Stage.tool_call:
                self._warn(run.tool_calls, budget.tool_calls, budget.warn_at,
                           f"this run made {_share(run.tool_calls, budget.tool_calls)} "
                           "Resource calls")
        if budget.tokens is not None:
            if run.tokens >= budget.tokens:
                self._block("run_tokens_exhausted",
                            f"this run used {_share(run.tokens, budget.tokens)} tokens")
            else:
                self._warn(run.tokens, budget.tokens, budget.warn_at,
                           f"this run used {_share(run.tokens, budget.tokens)} tokens")
        limit = budget.wall_clock_seconds
        if limit is not None and stage != Stage.output and elapsed > limit:
            self._block("run_time_exceeded", f"this run has been going for {elapsed}s "
                        f"> limit {limit}s")

    def _block(self, kind: str, detail: str) -> None:
        self.blocks.append(Finding(control=self.id, type=kind, detail=detail))

    def _warn(self, used: int, limit: int, warn_at: float | None, detail: str) -> None:
        if warn_at is not None and used >= warn_at * limit:
            self.warnings.append(Finding(
                control=self.id, type="budget_warning",
                detail=f"{detail} ({used / limit:.0%}, warning at {warn_at:.0%})",
            ))
