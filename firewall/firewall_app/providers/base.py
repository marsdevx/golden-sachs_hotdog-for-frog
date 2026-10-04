"""Provider-neutral contract for non-streaming text and tool-call generation."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

from pydantic import BaseModel, Field

from firewall_app.domain import Message, Usage


@dataclass(frozen=True)
class Connection:
    base_url: str
    api_key: str | None = None


class ModelRequest(BaseModel):
    model: str
    messages: list[Message]
    options: dict[str, Any] = Field(default_factory=dict)


class ModelResponse(BaseModel):
    model: str
    message: Message
    usage: Usage = Field(default_factory=Usage)
    id: str = Field(default_factory=lambda: f"chatcmpl-{uuid4().hex}")
    created: int = Field(default_factory=lambda: int(time.time()))
    finish_reason: str = "stop"

    def completion(self, checked_message: Message) -> dict[str, Any]:
        """Serialize only the content that passed the output pipeline."""
        usage = self.usage.model_dump(exclude={"model"}, exclude_none=True)
        if self.usage.prompt_tokens is not None and self.usage.completion_tokens is not None:
            usage["total_tokens"] = self.usage.prompt_tokens + self.usage.completion_tokens
        return {
            "id": self.id, "created": self.created, "object": "chat.completion",
            "model": self.model, "usage": usage,
            "choices": [{"index": 0, "message": checked_message.model_dump(),
                         "finish_reason": self.finish_reason}],
        }


class ProviderError(RuntimeError):
    """An adapter failed; the proxy must audit the failure and return no model content."""


class ModelProvider(Protocol):
    async def chat(self, request: ModelRequest) -> ModelResponse: ...
