from __future__ import annotations

from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from app.firewall_client import FirewallClient
from app.models import ChatRequest, ControlDecision, Message, Usage


class AgentState(TypedDict, total=False):
    request: ChatRequest
    input_decision: ControlDecision
    output_decision: ControlDecision | None
    response: Message
    model: str
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
        request = state["request"]
        reply = await self.control.chat(request.messages, request.metadata)
        return {
            "response": reply.choices[0].message,
            "model": reply.model,
            "usage": reply.usage.model_copy(update={"model": reply.model}),
            "input_decision": reply.firewall.input.decision,
            "output_decision": (
                reply.firewall.output.decision if reply.firewall.output else None
            ),
        }

    async def invoke(self, request: ChatRequest) -> AgentState:
        return await self.graph.ainvoke({"request": request})
