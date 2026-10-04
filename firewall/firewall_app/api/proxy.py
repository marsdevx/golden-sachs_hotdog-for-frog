"""OpenAI-compatible proxy: `POST /v1/chat/completions` (non-streaming).

Agents integrate by setting `base_url` to the firewall and `api_key` to their agent key."""

from __future__ import annotations

import logging
import time
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from firewall_app.api.check import dump_decision
from firewall_app.domain import (
    Action,
    Check,
    Finding,
    Message,
    Stage,
    Transport,
    Usage,
    most_severe,
)
from firewall_app.identity import resolve_agent
from firewall_app.pipeline import PipelineResult, denied
from firewall_app.providers.base import ModelRequest, ProviderError
from firewall_app.providers.manager import ProviderManager
from firewall_app.runs import run_id_of
from firewall_app.tools.files import definitions

logger = logging.getLogger("firewall.proxy")
router = APIRouter(tags=["proxy"])

ENFORCED = {Action.block, Action.review}


def openai_error(status: int, message: str, kind: str, **extra: Any) -> JSONResponse:
    return JSONResponse({"error": {"message": message, "type": kind}, **extra}, status_code=status)


def _text(content: Any) -> str:
    """OpenAI content is a string or a list of parts; Controls see the text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    raise ValueError("unsupported message content")


def _parse_messages(raw: Any) -> list[Message]:
    if not isinstance(raw, list) or not raw:
        raise ValueError("messages must be a non-empty list")
    messages = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each message must be an object")
        role = "system" if item.get("role") == "developer" else item.get("role")
        messages.append(Message(
            role=role, content=_text(item.get("content")),
            tool_calls=item.get("tool_calls"), tool_call_id=item.get("tool_call_id"),
        ))
    return messages


MAX_TOKENS_KEYS = ("max_completion_tokens", "max_tokens")  # new OpenAI name first


def _requested_max_tokens(body: dict[str, Any]) -> tuple[str, int | None]:
    """The reply ceiling the caller asked for, and the key it used (default `max_tokens`)."""
    for key in MAX_TOKENS_KEYS:
        value = body.get(key)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{key} must be a positive integer")
        return key, value
    return "max_tokens", None


def _section(result: PipelineResult | None) -> dict[str, Any] | None:
    if result is None:
        return None
    return {"check_id": result.before.check_id, "decision": dump_decision(result.decision)}


def _firewall(input_result: PipelineResult, output_result: PipelineResult | None = None):
    """Summary of the whole completion: the most severe Decision of both Stages, so a
    redaction on input still shows when the reply itself was clean."""
    final = output_result or input_result
    stages = {"input": input_result, "output": output_result}
    results = {stage: result for stage, result in stages.items() if result is not None}
    action = most_severe(result.decision.action for result in results.values())
    deciding = {s: r for s, r in results.items() if r.decision.action == action}
    if action == Action.allow:
        reason = final.decision.reason
    elif len(deciding) == 1:
        reason = next(iter(deciding.values())).decision.reason
    else:
        reason = "; ".join(f"{stage}: {r.decision.reason}" for stage, r in deciding.items())
    return {
        "action": action,
        "reason": reason,
        "policy_version": final.decision.policy_version,
        "input": _section(input_result),
        "output": _section(output_result),
    }


def _blocked_completion(model: str, result: PipelineResult, firewall: dict[str, Any]):
    content = f"AI Control Layer: {result.decision.reason}"
    return {
        "id": f"chatcmpl-fw-{result.before.check_id}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "content_filter",
            }
        ],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "firewall": firewall,
    }


@router.post("/v1/chat/completions", summary="OpenAI-compatible chat completions")
async def chat_completions(request: Request) -> JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return openai_error(400, "request body must be JSON", "invalid_request_error")
    if not isinstance(body, dict):
        return openai_error(400, "request body must be a JSON object", "invalid_request_error")
    if body.get("stream"):
        return openai_error(400, "stream: true is not supported yet", "invalid_request_error")
    model = body.get("model")
    if not isinstance(model, str) or not model:
        return openai_error(400, "model is required", "invalid_request_error")
    try:
        messages = _parse_messages(body.get("messages"))
    except (ValueError, ValidationError) as exc:
        return openai_error(400, f"invalid messages: {exc}", "invalid_request_error")

    metadata = body.get("metadata", {})
    if not isinstance(metadata, dict):
        return openai_error(400, "metadata must be an object", "invalid_request_error")
    try:
        max_tokens_key, max_tokens = _requested_max_tokens(body)
    except ValueError as exc:
        return openai_error(400, str(exc), "invalid_request_error")

    state = request.app.state
    service = state.service
    policy = state.policy_store.get()
    identity = resolve_agent(request.headers, policy)
    user = body.get("user") if isinstance(body.get("user"), str) else None
    run_id = run_id_of(messages, metadata)  # input and output of this call share the run

    def make_check(stage: Stage, **content: Any) -> Check:
        return Check(
            stage=stage,
            agent=identity.agent,
            user=user,
            metadata=metadata,
            run_id=run_id,
            transport=Transport.proxy,
            **content,
        )

    # Input Stage.
    input_check = make_check(
        Stage.input, messages=messages, max_tokens=max_tokens, usage=Usage(model=model)
    )
    if identity.allowed and model not in policy.allowed_models:
        finding = Finding(
            control="allowed_models", type="model_not_allowed", detail=f"model {model!r}"
        )
        reason = f"Blocked: model {model!r} is not in allowed_models"
        input_result = denied(input_check, policy, reason, finding)
        await service.record(input_result, policy)
    else:
        input_result = await service.run(input_check, policy, identity)
    if input_result.decision.action in ENFORCED:
        return JSONResponse(_blocked_completion(model, input_result, _firewall(input_result)))

    # The adapter sees only messages returned by the input pipeline.
    options = {key: value for key, value in body.items()
               if key not in {"model", "messages", "metadata", "stream", "enable_tools"}}
    if body.get("enable_tools") is True:
        options["tools"] = definitions()
    # A Control may have lowered or set the reply ceiling (request_limits).
    if input_result.after.max_tokens is not None:
        options[max_tokens_key] = input_result.after.max_tokens
    try:
        manager = ProviderManager(
            state.settings.upstream_timeout_seconds, state.upstream_transport,
            telemetry=state.telemetry,
            observation_context={
                "firewall.agent_id": identity.agent.id,
                "firewall.input_check_id": input_check.check_id,
                "firewall.policy_version": policy.version,
            },
        )
        result = await manager.chat(policy, ModelRequest(
            model=model, messages=input_result.after.messages, options=options,
        ))
        reply = result.message
    except (httpx.HTTPError, LookupError, KeyError, IndexError,
            TypeError, ValueError, ProviderError) as exc:
        logger.warning("Upstream failure for model %s: %s", model, exc)
        failure = make_check(Stage.output, usage=Usage(model=model))
        finding = Finding(control="upstream", type="upstream_error", detail=str(exc)[:500])
        reason = f"upstream error: {type(exc).__name__}"
        output_result = denied(failure, policy, reason, finding)
        await service.record(output_result, policy)
        return openai_error(
            502, reason, "upstream_error", firewall=_firewall(input_result, output_result)
        )

    # Output Stage.
    usage = result.usage
    output_check = make_check(Stage.output, message=reply, usage=usage)
    if reply.tool_calls:
        output_check.metadata = {
            **metadata, "execution": "model_proposed",
            "tool_name": ", ".join(call.function.name for call in reply.tool_calls),
            "tool_call_ids": [call.id for call in reply.tool_calls],
        }
    output_result = await service.run(output_check, policy, identity)
    firewall = _firewall(input_result, output_result)
    if output_result.decision.action in ENFORCED:
        blocked = _blocked_completion(model, output_result, firewall)
        blocked["usage"] = result.completion(reply)["usage"]
        return JSONResponse(blocked)
    completion = result.completion(output_result.after.message)
    completion["firewall"] = firewall
    return JSONResponse(completion)
