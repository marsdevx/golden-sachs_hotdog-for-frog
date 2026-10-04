"""Check API: `POST /v1/check/{stage}`, the integration contract for Agents."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from firewall_app.domain import Check, Decision, Message, Stage, ToolCall, Transport, Usage
from firewall_app.identity import resolve_agent
from firewall_app.pipeline import PipelineResult
from firewall_app.runs import run_id_of

router = APIRouter(tags=["check"])

CONTENT_FIELDS = ("messages", "message", "tool", "tool_result")
REQUIRED: dict[Stage, set[str]] = {
    Stage.input: {"messages"},
    Stage.output: {"message"},
    Stage.tool_call: {"tool"},
    Stage.tool_result: {"tool", "tool_result"},
}
OPTIONAL: dict[Stage, set[str]] = {Stage.input: {"max_tokens"}, Stage.output: {"usage"}}
ALWAYS_ALLOWED = {"user", "metadata"}


class CheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[Message] | None = None
    message: Message | None = None
    tool: ToolCall | None = None
    tool_result: str | None = None
    max_tokens: int | None = Field(default=None, ge=1)
    user: str | None = None
    usage: Usage | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CheckResponse(BaseModel):
    """Only the content fields of the requested Stage are present."""

    check_id: str
    policy_version: str
    decision: Decision
    messages: list[Message] | None = None
    message: Message | None = None
    tool: ToolCall | None = None
    tool_result: str | None = None
    max_tokens: int | None = None  # input only, when sent or set by a Control


def validate_for_stage(stage: Stage, body: CheckRequest) -> None:
    present = {name for name in body.model_fields_set if getattr(body, name) is not None}
    errors = []
    for name in sorted(REQUIRED[stage] - present):
        errors.append(_error(name, f"field required for the {stage} stage", "missing"))
    allowed = REQUIRED[stage] | OPTIONAL.get(stage, set()) | ALWAYS_ALLOWED
    for name in sorted(present - allowed):
        errors.append(_error(name, f"field not allowed for the {stage} stage", "extra_forbidden"))
    if stage == Stage.input and body.messages == []:
        errors.append(_error("messages", "at least one message is required", "too_short"))
    if errors:
        raise RequestValidationError(errors)


def _error(field: str, message: str, kind: str) -> dict[str, Any]:
    return {"loc": ["body", field], "msg": message, "type": kind}


def check_response(result: PipelineResult) -> dict[str, Any]:
    fields = REQUIRED[result.after.stage] | {"max_tokens"}
    content = result.after.content().model_dump(mode="json", include=fields)
    if content.get("max_tokens") is None:
        content.pop("max_tokens", None)
    return {
        "check_id": result.before.check_id,
        "policy_version": result.decision.policy_version,
        "decision": dump_decision(result.decision),
        **content,
    }


def dump_decision(decision: Decision) -> dict[str, Any]:
    return decision.model_dump(mode="json", exclude={"verdicts": {"__all__": {"rewritten"}}})


@router.post(
    "/v1/check/{stage}",
    responses={200: {"model": CheckResponse}},
    summary="Run one Check at a Stage",
)
async def check(stage: Stage, body: CheckRequest, request: Request) -> JSONResponse:
    validate_for_stage(stage, body)
    state = request.app.state
    policy = state.policy_store.get()
    identity = resolve_agent(request.headers, policy)
    check_ = Check(
        stage=stage,
        agent=identity.agent,
        user=body.user,
        messages=body.messages or [],
        message=body.message,
        tool=body.tool,
        tool_result=body.tool_result,
        max_tokens=body.max_tokens,
        usage=body.usage,
        metadata=body.metadata,
        run_id=run_id_of(body.messages, body.metadata),
        transport=Transport.check_api,
    )
    result = await state.service.run(check_, policy, identity)
    return JSONResponse(check_response(result))
