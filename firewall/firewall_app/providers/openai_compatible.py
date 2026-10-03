"""Adapter for the existing /v1/chat/completions wire protocol."""
import httpx

from firewall_app.domain import Message, Usage
from firewall_app.providers.base import Connection, ModelRequest, ModelResponse


class OpenAICompatibleAdapter:
    def __init__(self, connection: Connection, client: httpx.AsyncClient) -> None:
        self.connection = connection
        self.client = client

    async def chat(self, request: ModelRequest) -> ModelResponse:
        payload = {
            **request.options,
            "model": request.model,
            "messages": [message.model_dump() for message in request.messages],
            "stream": False,
        }
        headers = (
            {"Authorization": f"Bearer {self.connection.api_key}"}
            if self.connection.api_key else {}
        )
        response = await self.client.post(
            self.connection.base_url.rstrip("/") + "/chat/completions",
            json=payload, headers=headers,
        )
        response.raise_for_status()
        body = response.json()
        choices = body["choices"]
        if len(choices) != 1:
            raise ValueError("only one text completion is supported")
        choice = choices[0]
        message = choice["message"]
        if message.get("tool_calls") or message.get("function_call"):
            raise ValueError("tool execution is not supported by the text gateway")
        content = message["content"]
        if not isinstance(content, str):
            raise ValueError("expected text completion")
        model = body.get("model") or request.model
        raw_usage = body.get("usage") or {}
        if not isinstance(raw_usage, dict):
            raise ValueError("expected usage object")
        return ModelResponse(
            model=model,
            message=Message(role="assistant", content=content),
            usage=Usage(model=model, prompt_tokens=raw_usage.get("prompt_tokens"),
                        completion_tokens=raw_usage.get("completion_tokens")),
            **{key: body[key] for key in ("id", "created") if key in body},
            finish_reason=choice.get("finish_reason") or "stop",
        )
