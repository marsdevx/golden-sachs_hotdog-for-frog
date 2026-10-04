from __future__ import annotations

from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from app.config import Settings
from app.models import ControlDecision, Message, ToolCall, Usage

Stage = Literal["input", "output", "tool_call", "tool_result"]

# The content fields the firewall must return for each Stage. The chat only ever uses
# content the firewall returned, never its own unverified copy.
CONTENT_FIELDS: dict[str, tuple[str, ...]] = {
    "input": ("messages",),
    "output": ("message",),
    "tool_call": ("tool",),
    "tool_result": ("tool", "tool_result"),
}


class WireDecision(ControlDecision):
    # Never interpret a missing remote Decision as an implicit allow.
    action: Literal["allow", "redact", "review", "block"] = Field(...)


class CheckResult(BaseModel):
    check_id: str
    policy_version: str
    decision: WireDecision
    messages: list[Message] | None = Field(default=None, min_length=1)
    message: Message | None = None
    tool: ToolCall | None = None
    tool_result: str | None = None


class ProxySection(BaseModel):
    check_id: str
    decision: WireDecision


class ProxyChecks(BaseModel):
    input: ProxySection
    output: ProxySection | None


class ProxyChoice(BaseModel):
    message: Message


class ProxyReply(BaseModel):
    model: str
    choices: list[ProxyChoice] = Field(min_length=1, max_length=1)
    firewall: ProxyChecks
    usage: Usage = Field(default_factory=Usage)


class ToolReply(BaseModel):
    operation_id: str
    tool_call_id: str
    executed: bool
    decision: WireDecision
    tool_result: str | None
    call_check_id: str
    result_check_id: str | None


class FirewallClient:
    """HTTP boundary; the chat service never imports firewall implementation code."""

    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.transport = transport

    async def _post(self, path: str, payload: dict) -> Any:
        try:
            async with httpx.AsyncClient(
                base_url=self.settings.firewall_url,
                timeout=self.settings.firewall_timeout_seconds,
                transport=self.transport,
                headers={"X-Agent-Key": self.settings.agent_key},
            ) as client:
                response = await client.post(path, json=payload)
                if response.is_error:
                    raise RuntimeError(f"Firewall {path} returned HTTP {response.status_code}")
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise RuntimeError("Firewall unavailable or returned an invalid response") from exc

    async def chat(self, messages: list[Message], metadata: dict[str, Any]) -> ProxyReply:
        user = metadata.get("user")
        payload = {
            "model": self.settings.llm_model,
            "messages": [message.model_dump() for message in messages],
            "stream": False,
            "enable_tools": True,
            **self._context(user if isinstance(user, str) else None, metadata),
        }
        data = await self._post("/v1/chat/completions", payload)
        try:
            reply = ProxyReply.model_validate(data)
            if reply.firewall.output is None and reply.firewall.input.decision.action not in {
                "block", "review"
            }:
                raise ValueError("missing output check")
            if reply.choices[0].message.role != "assistant":
                raise ValueError("expected assistant response")
        except (ValidationError, ValueError) as exc:
            raise RuntimeError("Firewall returned an invalid completion") from exc
        return reply

    async def execute_tool(
        self, tool: ToolCall, tool_call_id: str, metadata: dict[str, Any],
    ) -> ToolReply:
        user = metadata.get("user")
        data = await self._post("/v1/tools/execute", {
            "tool": tool.model_dump(), "tool_call_id": tool_call_id,
            **self._context(user if isinstance(user, str) else None, metadata),
        })
        try:
            result = ToolReply.model_validate(data)
            if result.tool_call_id != tool_call_id:
                raise ValueError("tool call mismatch")
            if result.decision.action not in {"block", "review"} and (
                not result.executed or result.tool_result is None or not result.result_check_id
            ):
                raise ValueError("missing checked tool result")
        except (ValidationError, ValueError) as exc:
            raise RuntimeError("Firewall returned an invalid tool response") from exc
        return result

    async def health(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(
                base_url=self.settings.firewall_url,
                timeout=self.settings.firewall_timeout_seconds,
                transport=self.transport,
            ) as client:
                response = await client.get("/health")
                response.raise_for_status()
                if response.json().get("status") != "ok":
                    raise ValueError("unhealthy firewall")
        except (httpx.HTTPError, ValueError, AttributeError) as exc:
            raise RuntimeError("Firewall unavailable") from exc
        return {"status": "ok", "dependency": "firewall", "upstream_checked": False}

    async def check(self, stage: Stage, payload: dict[str, Any]) -> CheckResult:
        """Run one Check. Raises RuntimeError on any failure: callers fail closed."""
        data = await self._post(f"/v1/check/{stage}", payload)
        try:
            result = CheckResult.model_validate(data)
        except ValidationError as exc:
            raise RuntimeError(f"Firewall returned an invalid {stage} decision") from exc
        if any(getattr(result, field) is None for field in CONTENT_FIELDS[stage]):
            raise RuntimeError(f"Firewall returned no {stage} content")
        return result

    @staticmethod
    def _context(user: str | None, metadata: dict[str, Any] | None) -> dict[str, Any]:
        context: dict[str, Any] = {"metadata": metadata or {}}
        if user:
            context["user"] = user
        return context

    async def check_input(
        self,
        messages: list[Message],
        user: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[ControlDecision, list[Message]]:
        payload = {"messages": [m.model_dump() for m in messages], **self._context(user, metadata)}
        result = await self.check("input", payload)
        return result.decision, result.messages

    async def check_output(
        self,
        message: Message,
        usage: Usage | None = None,
        user: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[ControlDecision, Message]:
        payload = {"message": message.model_dump(), **self._context(user, metadata)}
        if usage is not None:
            payload["usage"] = usage.model_dump()
        result = await self.check("output", payload)
        return result.decision, result.message

    async def check_tool_call(
        self,
        tool: ToolCall,
        user: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[ControlDecision, ToolCall]:
        payload = {"tool": tool.model_dump(), **self._context(user, metadata)}
        result = await self.check("tool_call", payload)
        return result.decision, result.tool

    async def check_tool_result(
        self,
        tool: ToolCall,
        tool_result: str,
        user: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[ControlDecision, str]:
        payload = {
            "tool": tool.model_dump(),
            "tool_result": tool_result,
            **self._context(user, metadata),
        }
        result = await self.check("tool_result", payload)
        return result.decision, result.tool_result
