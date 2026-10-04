from __future__ import annotations

import asyncio
import json
from typing import Any, TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from app.firewall_client import FirewallClient
from app.models import ChatRequest, ControlDecision, Message, ToolCall, Usage


class AgentState(TypedDict, total=False):
    request: ChatRequest
    input_decision: ControlDecision
    output_decision: ControlDecision | None
    response: Message
    model: str
    run_id: str
    steps: list[dict[str, Any]]
    usage: Usage


class AgentWorkflow:
    def __init__(self, control: FirewallClient) -> None:
        self.control = control
        builder = StateGraph(AgentState)
        builder.add_node("call_firewall", self._call_firewall)
        builder.add_edge(START, "call_firewall")
        builder.add_edge("call_firewall", END)
        self.graph = builder.compile()

    async def _call_firewall(self, state: AgentState) -> AgentState:
        try:
            async with asyncio.timeout(120):
                return await self._run(state["request"])
        except TimeoutError as exc:
            raise RuntimeError("Agent run exceeded its time limit") from exc

    async def _run(self, request: ChatRequest) -> AgentState:
        run_id = str(uuid4())
        metadata = {**request.metadata, "session_id": run_id}
        messages = list(request.messages)
        steps = []
        usages = []
        first_input = None
        tool_count = 0
        seen_calls: set[str] = set()

        def finish(message, output, model):
            def total(field):
                values = [getattr(usage, field) for usage in usages]
                return sum(values) if all(value is not None for value in values) else None
            return {
                "response": message, "model": model, "input_decision": first_input,
                "output_decision": output, "run_id": run_id, "steps": steps,
                "usage": Usage(model=model, prompt_tokens=total("prompt_tokens"),
                               completion_tokens=total("completion_tokens")),
            }

        for step in range(8):
            context = {**metadata, "step": step}
            reply = await self.control.chat(messages, context)
            usages.append(reply.usage)
            decision = reply.firewall.input.decision
            if first_input is None:
                first_input = decision
            output = reply.firewall.output.decision if reply.firewall.output else None
            steps.append({"step": step, "kind": "model",
                          "input_check_id": reply.firewall.input.check_id,
                          "output_check_id": (reply.firewall.output.check_id
                                              if reply.firewall.output else None)})
            message = reply.choices[0].message
            if decision.action in {"block", "review"}:
                # Preserve the initial blocked-input response contract; later denials still stop UI.
                return finish(message, decision if step else output, reply.model)
            if output.action in {"block", "review"} or not message.tool_calls:
                return finish(message, output, reply.model)
            messages.append(message)
            for call in message.tool_calls:
                if call.id in seen_calls:
                    raise RuntimeError("Model reused a tool call ID")
                seen_calls.add(call.id)
                tool_count += 1
                if tool_count > 8:
                    raise RuntimeError("Agent run exceeded its tool limit")
                try:
                    args = json.loads(call.function.arguments)
                    tool = ToolCall(resource="files", action=call.function.name, args=args)
                except (ValueError, TypeError) as exc:
                    raise RuntimeError("Invalid tool arguments from model") from exc
                result = await self.control.execute_tool(tool, call.id, context)
                steps.append({"step": step, "kind": "tool", "name": call.function.name,
                              **result.model_dump(exclude={"tool_result"})})
                if result.decision.action in {"block", "review"}:
                    return finish(Message(role="assistant", content=(
                        "AI Control Layer: " + result.decision.reason
                    )), result.decision, reply.model)
                messages.append(Message(role="tool", content=result.tool_result,
                                        tool_call_id=call.id))
        raise RuntimeError("Agent run exceeded its model-call limit")

    async def invoke(self, request: ChatRequest) -> AgentState:
        return await self.graph.ainvoke({"request": request})
