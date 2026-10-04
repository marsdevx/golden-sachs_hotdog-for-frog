"""Gemini transport: the firewall as a reverse proxy for Gemini CLI.

Point the CLI at the firewall; it keeps its own Google credentials:

    # Gemini API key sign-in
    GOOGLE_GEMINI_BASE_URL=http://localhost:8001/gemini \\
    GEMINI_CLI_CUSTOM_HEADERS="X-Agent-Key: demo-agent-key" gemini
    # Google account sign-in (Code Assist)
    CODE_ASSIST_ENDPOINT=http://localhost:8001/gemini \\
    GEMINI_CLI_CUSTOM_HEADERS="X-Agent-Key: demo-agent-key" gemini

Every request under /gemini/ is forwarded to Google, to the server its path belongs to:
`v1internal...` to Code Assist, anything else (`v1beta/models/...`) to the Gemini API. Model
calls (`generateContent`, `streamGenerateContent`) run the `input` Check on the conversation
before they leave and the `output` Check on the reply before the CLI sees it, with the same
Policy, Controls and audit as the OpenAI proxy. Everything else (sign-in setup, quota,
metrics) passes through unchanged.

Text is checked; function calls and their results are checked as text too. The CLI's own
system instruction is not checked. A streamed reply is buffered, checked as a whole, then
streamed back. Google credentials (`Authorization`, `x-goog-api-key`) are forwarded;
`X-Agent-Key` never is."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import httpx
from fastapi import APIRouter, Request, Response

from firewall_app.domain import Action, Check, Message, Stage, Transport, Usage
from firewall_app.identity import resolve_agent
from firewall_app.pipeline import PipelineResult
from firewall_app.runs import run_id_of

logger = logging.getLogger("firewall.gemini")
router = APIRouter(tags=["gemini"])

MODEL_METHODS = ("generateContent", "streamGenerateContent")
CODE_ASSIST = "https://cloudcode-pa.googleapis.com"  # Google account sign-in
GEMINI_API = "https://generativelanguage.googleapis.com"  # API key sign-in
_PATH_MODEL = re.compile(r"models/([^/:]+):")
ENFORCED = {Action.block, Action.review}
# Hop-by-hop or recomputed headers; and the firewall's own Agent key stays here.
DROP_REQUEST = {"host", "content-length", "connection", "accept-encoding", "x-agent-key"}
DROP_RESPONSE = {"content-length", "content-encoding", "transfer-encoding", "connection"}


# --- the Gemini shapes (Code Assist wraps them in `request` / `response`) -----------------


def _inner(payload: dict[str, Any], key: str) -> dict[str, Any]:
    inner = payload.get(key)
    return inner if isinstance(inner, dict) else payload


def _text_of(part: dict[str, Any]) -> tuple[str, str] | None:
    """(role, text) of a part the Controls should see, or None."""
    if isinstance(part.get("text"), str) and not part.get("thought"):
        return "", part["text"]
    if isinstance(part.get("functionCall"), dict):
        call = part["functionCall"]
        return "assistant", f"{call.get('name')}({json.dumps(call.get('args', {}))})"
    if isinstance(part.get("functionResponse"), dict):
        return "tool", json.dumps(part["functionResponse"].get("response", {}))
    return None


def _messages(contents: list[Any]) -> tuple[list[Message], list[tuple[int, int]]]:
    """One Message per checkable part, and where each one came from."""
    messages, where = [], []
    for ci, content in enumerate(contents):
        if not isinstance(content, dict):
            continue
        default = "assistant" if content.get("role") == "model" else "user"
        for pi, part in enumerate(content.get("parts") or []):
            found = _text_of(part) if isinstance(part, dict) else None
            if found:
                role, text = found
                messages.append(Message(role=role or default, content=text))
                where.append((ci, pi))
    return messages, where


def _write_back(contents: list[Any], where, before: list[Message], after: list[Message]) -> None:
    """Put redacted text back into the parts it came from."""
    for (ci, pi), old, new in zip(where, before, after):
        if old.content == new.content:
            continue
        part = contents[ci]["parts"][pi]
        if "text" in part:
            part["text"] = new.content
        elif "functionResponse" in part:
            try:  # the redacted JSON keeps its shape; anything else becomes plain output
                response = json.loads(new.content)
            except ValueError:
                response = None
            part["functionResponse"]["response"] = (
                response if isinstance(response, dict) else {"output": new.content}
            )
        # A functionCall the model made is not rewritten: the output Check sees text only.


def _events(body: bytes) -> list[dict[str, Any]]:
    """The JSON payloads of an SSE stream (`data: {...}` lines)."""
    events = []
    for line in body.decode("utf-8", errors="replace").splitlines():
        if line.startswith("data:"):
            try:
                events.append(json.loads(line[5:].strip()))
            except json.JSONDecodeError:
                continue
    return events


def _sse(events: list[dict[str, Any]]) -> bytes:
    return b"".join(b"data: " + json.dumps(e).encode() + b"\r\n\r\n" for e in events)


def _reply_text_parts(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every visible text part of the reply, in order, across all streamed events."""
    parts = []
    for event in events:
        for candidate in _inner(event, "response").get("candidates") or []:
            for part in (candidate.get("content") or {}).get("parts") or []:
                if isinstance(part.get("text"), str) and not part.get("thought"):
                    parts.append(part)
    return parts


def _usage(events: list[dict[str, Any]], model: str | None) -> Usage:
    meta = {}
    for event in events:
        meta = _inner(event, "response").get("usageMetadata") or meta
    return Usage(model=model, prompt_tokens=meta.get("promptTokenCount"),
                 completion_tokens=meta.get("candidatesTokenCount"))


def _stopped(result: PipelineResult, wrapped: bool) -> dict[str, Any]:
    """A normal-looking Gemini reply that carries the firewall's explanation."""
    reply = {"candidates": [{
        "content": {"role": "model",
                    "parts": [{"text": f"AI Control Layer: {result.decision.reason}"}]},
        "finishReason": "STOP", "index": 0,
    }]}
    return {"response": reply} if wrapped else reply


# --- the route ----------------------------------------------------------------------------


@router.api_route("/gemini/{path:path}", methods=["GET", "POST"], include_in_schema=False)
async def gemini(path: str, request: Request) -> Response:
    state = request.app.state
    url = (CODE_ASSIST if path.startswith("v1internal") else GEMINI_API) + "/" + path
    headers = {k: v for k, v in request.headers.items() if k.lower() not in DROP_REQUEST}
    body = await request.body()
    method = path.rsplit(":", 1)[-1] if ":" in path else ""
    if request.method != "POST" or method not in MODEL_METHODS:
        return await _forward(state, request.method, url, request.query_params, headers, body)

    try:
        payload = json.loads(body)
    except ValueError:
        return await _forward(state, request.method, url, request.query_params, headers, body)
    wrapped = isinstance(payload.get("request"), dict)
    inner = _inner(payload, "request")
    contents = inner.get("contents") if isinstance(inner.get("contents"), list) else []
    model = payload.get("model") if isinstance(payload.get("model"), str) else None
    if model is None and (found := _PATH_MODEL.search(path)):
        model = found.group(1)  # the Gemini API names the model in the path
    streaming = method == "streamGenerateContent"

    policy = state.policy_store.get()
    identity = resolve_agent(request.headers, policy)
    messages, where = _messages(contents)
    metadata = {"gemini_method": method}
    run_id = run_id_of(messages, metadata)

    def make_check(stage: Stage, **content: Any) -> Check:
        return Check(stage=stage, agent=identity.agent, metadata=metadata, run_id=run_id,
                     transport=Transport.gemini, **content)

    def reply(events: list[dict[str, Any]], status: int = 200) -> Response:
        if streaming:
            return Response(_sse(events), status_code=status, media_type="text/event-stream")
        return Response(json.dumps(events[0]), status_code=status,
                        media_type="application/json")

    # Input Stage: the conversation, before it leaves for Google.
    input_result = await state.service.run(
        make_check(Stage.input, messages=messages or [Message(role="user", content="")],
                   usage=Usage(model=model)),
        policy, identity,
    )
    if input_result.decision.action in ENFORCED:
        return reply([_stopped(input_result, wrapped)])
    if messages:
        _write_back(contents, where, messages, input_result.after.messages)

    upstream = await _send(state, "POST", url, request.query_params, headers,
                           json.dumps(payload).encode())
    if upstream is None or upstream.status_code >= 400:
        return _relay(upstream)
    events = _events(upstream.content) if streaming else [json.loads(upstream.content)]

    # Output Stage: the whole reply, before the CLI sees any of it.
    parts = _reply_text_parts(events)
    text = "".join(part["text"] for part in parts)
    output_result = await state.service.run(
        make_check(Stage.output, message=Message(role="assistant", content=text),
                   usage=_usage(events, model)),
        policy, identity,
    )
    if output_result.decision.action in ENFORCED:
        return reply([_stopped(output_result, wrapped)])
    checked = output_result.after.message.content if output_result.after.message else text
    if parts and checked != text:
        parts[0]["text"] = checked  # the redacted reply, whole, in the first text part
        for part in parts[1:]:
            part["text"] = ""
    return reply(events)


async def _send(state, method, url, params, headers, body) -> httpx.Response | None:
    timeout = state.settings.upstream_timeout_seconds
    try:
        async with httpx.AsyncClient(transport=state.upstream_transport,
                                     timeout=timeout) as client:
            return await client.request(method, url, params=params, headers=headers,
                                        content=body)
    except httpx.HTTPError as exc:
        logger.warning("Gemini upstream failure for %s: %s", url, exc)
        return None


def _relay(upstream: httpx.Response | None) -> Response:
    if upstream is None:
        return Response(json.dumps({"error": {"message": "upstream unreachable"}}),
                        status_code=502, media_type="application/json")
    headers = {k: v for k, v in upstream.headers.items() if k.lower() not in DROP_RESPONSE}
    return Response(upstream.content, status_code=upstream.status_code, headers=headers)


async def _forward(state, method, url, params, headers, body) -> Response:
    return _relay(await _send(state, method, url, params, headers, body or None))
