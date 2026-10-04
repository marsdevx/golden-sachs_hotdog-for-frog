"""Domain model shared by every part of the firewall. Terms follow CONTEXT.md."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class Stage(StrEnum):
    input = "input"
    output = "output"
    tool_call = "tool_call"
    tool_result = "tool_result"


class Mode(StrEnum):
    off = "off"
    monitor = "monitor"
    redact = "redact"
    block = "block"


class Action(StrEnum):
    allow = "allow"
    redact = "redact"
    review = "review"
    block = "block"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {Action.allow: 0, Action.redact: 1, Action.review: 2, Action.block: 3}


def most_severe(actions: Iterable[Action]) -> Action:
    """`block` > `review` > `redact` > `allow`; `allow` when there is nothing to compare."""
    return max(actions, key=lambda action: action.severity, default=Action.allow)


class Transport(StrEnum):
    check_api = "check_api"
    proxy = "proxy"
    gemini = "gemini"  # Gemini CLI through /gemini/ (api/gemini.py)


class FunctionCall(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    arguments: str = Field(max_length=32768)


class ModelToolCall(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    type: Literal["function"] = "function"
    function: FunctionCall


class Message(BaseModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_calls: list[ModelToolCall] | None = Field(
        default=None, max_length=8, exclude_if=lambda v: v is None,
    )
    tool_call_id: str | None = Field(default=None, exclude_if=lambda v: v is None)


class ToolCall(BaseModel):
    resource: str
    action: str
    args: dict[str, Any] = Field(default_factory=dict)


class Usage(BaseModel):
    model: str | None = None
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)


class Agent(BaseModel):
    id: str
    owner: str
    team: str | None = None


UNKNOWN_AGENT = Agent(id="unknown", owner="unknown")


class Content(BaseModel):
    """The inspectable content of a Check. A Control rewrites content by returning one of these."""

    messages: list[Message] | None = None
    message: Message | None = None
    tool: ToolCall | None = None
    tool_result: str | None = None
    max_tokens: int | None = Field(default=None, ge=1)  # input Stage: the reply ceiling


class Check(BaseModel):
    """What every Control receives: one Stage of one interaction."""

    check_id: str = Field(default_factory=lambda: str(uuid4()))
    stage: Stage
    agent: Agent
    user: str | None = None
    messages: list[Message] = Field(default_factory=list)
    message: Message | None = None
    tool: ToolCall | None = None
    tool_result: str | None = None
    usage: Usage | None = None
    # The Agent run this Check belongs to (see runs.py); stamped by the transport.
    run_id: str | None = None
    # Input Stage: the most reply tokens the caller asked for (None: no limit was requested).
    max_tokens: int | None = Field(default=None, ge=1)
    labels: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Recorded in the Audit Event only. Controls must never branch on it.
    transport: Transport = Transport.check_api

    def content(self) -> Content:
        return Content(
            messages=self.messages if self.stage == Stage.input else None,
            message=self.message,
            tool=self.tool,
            tool_result=self.tool_result,
            max_tokens=self.max_tokens if self.stage == Stage.input else None,
        )

    def with_content(self, content: Content) -> Check:
        """A copy of this Check with every content field that `content` sets replaced."""
        updates = {name: getattr(content, name) for name in content.model_fields_set}
        updates = {name: value for name, value in updates.items() if value is not None}
        return self.model_copy(update=updates, deep=True)


class Finding(BaseModel):
    control: str
    type: str
    detail: str
    span: tuple[int, int] | None = None


class Verdict(BaseModel):
    """What one Control returns for a Check. The pipeline stamps `control`,
    `effective_action` and `latency_ms`."""

    model_config = ConfigDict(validate_assignment=True)

    control: str = ""
    action: Action = Action.allow
    reason: str = ""
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    rewritten: Content | None = None
    # Set by the pipeline after Mode capping. `action` stays the raw Control output.
    effective_action: Action | None = None
    mode: Mode | None = None
    error: bool = False
    latency_ms: float = 0.0


class Decision(BaseModel):
    """The combined outcome of all Verdicts of one Check. The caller must enforce it."""

    action: Action = Action.allow
    reason: str = "No Control objected"
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    verdicts: list[Verdict] = Field(default_factory=list)
    policy_version: str = ""
    latency_ms: float = 0.0
