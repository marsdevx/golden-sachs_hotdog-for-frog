"""The mandatory tool gateway: check -> execute -> check. No raw result on denial."""
from __future__ import annotations

import asyncio
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict, Field

from firewall_app.api.check import dump_decision
from firewall_app.domain import Check, Finding, Stage, ToolCall
from firewall_app.identity import resolve_agent
from firewall_app.pipeline import denied
from firewall_app.runs import run_id_of
from firewall_app.tools import files

router = APIRouter(tags=["tools"])
STOP = {"block", "review"}


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: ToolCall
    tool_call_id: str = Field(min_length=1, max_length=128)
    user: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@router.get("/v1/tools")
async def catalog() -> dict:
    return {"tools": files.definitions()}


@router.post("/v1/tools/execute")
async def execute(body: ExecuteRequest, request: Request) -> dict:
    state = request.app.state
    policy = state.policy_store.get()
    identity = resolve_agent(request.headers, policy)
    operation_id = str(uuid4())
    metadata = {**body.metadata, "operation_id": operation_id,
                "tool_call_id": body.tool_call_id, "tool_name": body.tool.action,
                "execution": "proposed"}
    check = Check(stage=Stage.tool_call, agent=identity.agent, user=body.user,
                  tool=body.tool, metadata=metadata,
                  run_id=run_id_of(None, body.metadata))
    before = await state.service.run(check, policy, identity)

    def response(result, output=None, executed=False):
        return {"operation_id": operation_id, "tool_call_id": body.tool_call_id,
                "executed": executed, "decision": dump_decision(result.decision),
                "tool_result": output,
                "call_check_id": before.before.check_id,
                "result_check_id": (result.before.check_id
                                    if result.before.stage == Stage.tool_result else None)}

    if before.decision.action in STOP:
        return response(before)
    try:
        tool = files.validate(before.after.tool)
    except ValueError:
        rejected = denied(check.model_copy(update={
            "check_id": str(uuid4()), "metadata": {**metadata, "execution": "rejected"},
        }), policy,
                          "Tool or path is outside the demo gateway contract",
                          Finding(control="tool_gateway", type="invalid_tool",
                                  detail="Not executed"))
        await state.service.record(rejected, policy)
        return response(rejected)

    result_check = Check(
        stage=Stage.tool_result, agent=identity.agent, user=body.user, tool=tool,
        run_id=check.run_id, metadata={**metadata, "execution": "succeeded"},
    )
    try:
        raw = await asyncio.wait_for(asyncio.to_thread(files.execute, tool), timeout=5)
    except (OSError, ValueError, TimeoutError):
        result_check.metadata["execution"] = "failed"
        failed = denied(result_check, policy, "Tool execution failed or exceeded its limits",
                        Finding(control="tool_gateway", type="execution_error",
                                detail="No result released"))
        await state.service.record(failed, policy)
        return response(failed)
    result_check.tool_result = raw
    after = await state.service.run(result_check, policy, identity)
    return response(after, None if after.decision.action in STOP else after.after.tool_result,
                    executed=True)
