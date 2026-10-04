"""Anthropic Messages API (Claude), translated to and from the OpenAI-shaped contract.

Raw httpx on purpose: adapters must use the supplied client (timeout, test transport),
and the Anthropic SDK is built on a different HTTP library.
"""
import json
from typing import Any

import httpx

from firewall_app.domain import Message, ModelToolCall, Usage
from firewall_app.providers.base import Connection, ModelRequest, ModelResponse

API_VERSION = "2023-06-01"
# Non-streaming: keep the reply ceiling well under the upstream timeout.
DEFAULT_MAX_TOKENS = 4096
FINISH_REASONS = {
    "end_turn": "stop", "stop_sequence": "stop", "max_tokens": "length",
    "tool_use": "tool_calls", "refusal": "content_filter", "pause_turn": "stop",
}
EFFORTS = {"low", "medium", "high", "xhigh", "max"}


def _tools(definitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    tools = []
    for definition in definitions:
        if definition.get("type") != "function":
            raise ValueError("only function tools are supported")
        function = definition["function"]
        tools.append({
            "name": function["name"],
            "description": function.get("description", ""),
            "input_schema": function.get("parameters") or {"type": "object", "properties": {}},
        })
    return tools


def _messages(messages: list[Message]) -> tuple[str, list[dict[str, Any]]]:
    """System text goes top level; tool results become user turns of tool_result blocks."""
    system: list[str] = []
    turns: list[dict[str, Any]] = []
    for message in messages:
        if message.role == "system":
            system.append(message.content)
            continue
        if message.role == "tool":
            block = {"type": "tool_result", "tool_use_id": message.tool_call_id,
                     "content": message.content}
            # All results of one parallel call belong in a single user turn.
            if turns and turns[-1]["role"] == "user" and isinstance(turns[-1]["content"], list):
                turns[-1]["content"].append(block)
            else:
                turns.append({"role": "user", "content": [block]})
            continue
        if message.role == "assistant" and message.tool_calls:
            blocks: list[dict[str, Any]] = (
                [{"type": "text", "text": message.content}] if message.content else []
            )
            for call in message.tool_calls:
                blocks.append({"type": "tool_use", "id": call.id, "name": call.function.name,
                               "input": json.loads(call.function.arguments or "{}")})
            turns.append({"role": "assistant", "content": blocks})
            continue
        turns.append({"role": message.role, "content": message.content})
    return "\n\n".join(system), turns


class AnthropicAdapter:
    def __init__(self, connection: Connection, client: httpx.AsyncClient) -> None:
        self.connection = connection
        self.client = client

    def _payload(self, request: ModelRequest) -> dict[str, Any]:
        options = request.options
        system, messages = _messages(request.messages)
        payload: dict[str, Any] = {
            "model": request.model,
            "messages": messages,
            "max_tokens": (options.get("max_tokens") or options.get("max_completion_tokens")
                           or DEFAULT_MAX_TOKENS),
        }
        if system:
            payload["system"] = system
        if options.get("tools"):
            payload["tools"] = _tools(options["tools"])
            # Current Claude models reject forced tool choice; only auto/none map.
            if options.get("tool_choice") in {"auto", "none"}:
                payload["tool_choice"] = {"type": options["tool_choice"]}
        stop = options.get("stop")
        if stop:
            payload["stop_sequences"] = [stop] if isinstance(stop, str) else list(stop)
        effort = options.get("reasoning_effort")
        if effort in EFFORTS:
            payload["output_config"] = {"effort": effort}
        if isinstance(options.get("user"), str):
            payload["metadata"] = {"user_id": options["user"]}
        # temperature/top_p and other OpenAI options are not forwarded: current
        # Claude models reject sampling parameters.
        return payload

    async def chat(self, request: ModelRequest) -> ModelResponse:
        if not self.connection.api_key:
            raise ValueError("the anthropic provider needs api_key_env")
        response = await self.client.post(
            self.connection.base_url.rstrip("/") + "/messages",
            json=self._payload(request),
            headers={"x-api-key": self.connection.api_key, "anthropic-version": API_VERSION},
        )
        response.raise_for_status()
        body = response.json()
        texts: list[str] = []
        calls: list[ModelToolCall] = []
        for block in body["content"]:
            if block["type"] == "text":
                texts.append(block["text"])
            elif block["type"] == "tool_use":
                calls.append(ModelToolCall(
                    id=block["id"],
                    function={"name": block["name"], "arguments": json.dumps(block["input"])},
                ))
            # thinking blocks are not returned to the Agent
        if calls and not request.options.get("tools"):
            raise ValueError("unsolicited tool calls")
        raw_usage = body.get("usage") or {}
        if not isinstance(raw_usage, dict):
            raise ValueError("expected usage object")
        prompt_tokens = raw_usage.get("input_tokens")
        if prompt_tokens is not None:
            prompt_tokens += ((raw_usage.get("cache_creation_input_tokens") or 0)
                              + (raw_usage.get("cache_read_input_tokens") or 0))
        model = body.get("model") or request.model
        return ModelResponse(
            model=model,
            message=Message(role="assistant", content="".join(texts), tool_calls=calls or None),
            usage=Usage(model=model, prompt_tokens=prompt_tokens,
                        completion_tokens=raw_usage.get("output_tokens")),
            finish_reason=FINISH_REASONS.get(body.get("stop_reason"), "stop"),
        )
