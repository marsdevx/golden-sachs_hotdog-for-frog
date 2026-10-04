"""Local echo provider for demos and tests. Usage counts words, not tokens."""
import json
import re
from uuid import uuid4

import httpx

from firewall_app.domain import Message, ModelToolCall, Usage
from firewall_app.providers.base import Connection, ModelRequest, ModelResponse


class MockAdapter:
    def __init__(self, connection: Connection, client: httpx.AsyncClient) -> None:
        pass

    async def chat(self, request: ModelRequest) -> ModelResponse:
        latest = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
        calls = None
        content = f"Mock response: {latest}"
        if request.messages[-1].role == "tool":
            content = request.messages[-1].content
        elif request.options.get("tools"):
            # Explicit commands keep demonstrations deterministic, without pretending to reason.
            match = re.fullmatch(r"/(list_files|read_file|delete_file)(?:\s+(.+))?", latest.strip())
            if match:
                calls = [ModelToolCall(
                    id="call_" + uuid4().hex,
                    function={"name": match[1],
                              "arguments": json.dumps({"path": match[2] or "/demo"})},
                )]
                content = ""

        return ModelResponse(
            model=request.model,
            message=Message(role="assistant", content=content, tool_calls=calls),
            finish_reason="tool_calls" if calls else "stop",
            usage=Usage(model=request.model,
                        prompt_tokens=sum(len(m.content.split()) for m in request.messages),
                        completion_tokens=len(content.split())),
        )
