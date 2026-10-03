"""Resolve a model using the current policy snapshot and call its adapter."""
from __future__ import annotations

import os
from typing import TYPE_CHECKING

import httpx

from firewall_app.observability.tracing import Telemetry
from firewall_app.providers import registry
from firewall_app.providers.base import Connection, ModelRequest, ModelResponse, ProviderError
from firewall_app.providers.registry import ProviderRegistry

if TYPE_CHECKING:
    from firewall_app.policy.schema import Policy


class ProviderManager:
    def __init__(
        self, timeout: float, transport: httpx.AsyncBaseTransport | None = None,
        providers: ProviderRegistry = registry,
        telemetry: Telemetry | None = None,
        observation_context: dict[str, str] | None = None,
    ) -> None:
        self.telemetry = telemetry or Telemetry()
        self.observation_context = observation_context
        self.timeout = timeout
        self.transport = transport
        self.providers = providers

    async def chat(self, policy: Policy, request: ModelRequest) -> ModelResponse:
        if request.model not in policy.allowed_models:
            raise LookupError(f"model {request.model!r} is not allowed")
        entry = next((e for e in policy.upstreams if request.model in e.models), None)
        if entry is None:
            raise LookupError(f"no upstream configured for model {request.model!r}")
        override = os.getenv(entry.base_url_env) if entry.base_url_env else None
        api_key = os.getenv(entry.api_key_env) if entry.api_key_env else None
        if entry.api_key_env and not api_key:
            raise ValueError(f"upstream key env var {entry.api_key_env} is not set")
        connection = Connection(base_url=override or entry.base_url, api_key=api_key)
        async with httpx.AsyncClient(transport=self.transport, timeout=self.timeout) as client:
            provider = self.providers.create(entry.provider, connection, client)
            try:
                with self.telemetry.llm(
                    request.model, entry.provider, self.observation_context
                ) as observation:
                    result = ModelResponse.model_validate(await provider.chat(request))
                    if result.message.role != "assistant":
                        raise ValueError("expected assistant response")
                    usage = result.usage
                    observation.attributes({
                        "llm.model_name": result.model,
                        "llm.response.model_name": result.model,
                        "llm.token_count.prompt": usage.prompt_tokens,
                        "llm.token_count.completion": usage.completion_tokens,
                        "llm.token_count.total": (
                            usage.prompt_tokens + usage.completion_tokens
                            if (usage.prompt_tokens is not None
                                and usage.completion_tokens is not None)
                            else None
                        ),
                        "firewall.usage_source": (
                            "mock_word_count" if entry.provider == "mock" else "provider_reported"
                        ),
                    })
                result.usage.model = result.model
                return result
            except Exception as exc:
                raise ProviderError(f"adapter {entry.provider!r} failed") from exc
