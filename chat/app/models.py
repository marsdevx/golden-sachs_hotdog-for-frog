from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


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
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class ChatRequest(BaseModel):
    messages: list[Message] = Field(min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    control: str
    type: str
    detail: str
    span: tuple[int, int] | None = None


class ControlDecision(BaseModel):
    action: Literal["allow", "redact", "review", "block"] = "allow"
    reason: str = "No Control objected"
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)


class ChatResponse(BaseModel):
    run_id: str | None = None
    steps: list[dict[str, Any]] = Field(default_factory=list)
    request_id: str
    message: Message
    model: str
    input_decision: ControlDecision
    output_decision: ControlDecision | None
    usage: Usage
