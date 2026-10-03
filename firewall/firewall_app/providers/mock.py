"""Local echo provider for demos and tests. Usage counts words, not tokens."""
import httpx

from firewall_app.domain import Message, Usage
from firewall_app.providers.base import Connection, ModelRequest, ModelResponse


class MockAdapter:
    def __init__(self, connection: Connection, client: httpx.AsyncClient) -> None:
        pass

    async def chat(self, request: ModelRequest) -> ModelResponse:
        latest = next((m.content for m in reversed(request.messages) if m.role == "user"), "")
        content = f"Mock response: {latest}"
        return ModelResponse(
            model=request.model, message=Message(role="assistant", content=content),
            usage=Usage(model=request.model,
                        prompt_tokens=sum(len(m.content.split()) for m in request.messages),
                        completion_tokens=len(content.split())),
        )
