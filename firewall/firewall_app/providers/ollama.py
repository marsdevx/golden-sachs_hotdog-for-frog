"""Ollama's OpenAI-compatible endpoint, with configurable thinking for tool runs."""
import os

from firewall_app.providers.base import ModelRequest, ModelResponse
from firewall_app.providers.openai_compatible import OpenAICompatibleAdapter


class OllamaAdapter(OpenAICompatibleAdapter):
    async def chat(self, request: ModelRequest) -> ModelResponse:
        options = dict(request.options)
        # Qwen's thinking after a tool result can exceed the non-streaming read timeout.
        # Keep explicit caller choices; "default" leaves Ollama's model default intact.
        effort = os.getenv("OLLAMA_TOOL_REASONING_EFFORT", "none")
        if (options.get("tools") and effort != "default"
                and "reasoning_effort" not in options and "reasoning" not in options):
            options["reasoning_effort"] = effort
        return await super().chat(request.model_copy(update={"options": options}))
