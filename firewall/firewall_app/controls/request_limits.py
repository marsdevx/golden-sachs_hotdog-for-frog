"""Request-level safety ceilings: no single interaction may be too big. Stops context bombs
(a huge prompt or Resource result), unbounded replies and oversized tool arguments before
they cost money or flood the model's context.

What can be fixed is fixed (the `max_tokens` ceiling is lowered or set, an oversized reply or
Resource result is truncated) and the Verdict is `redact`. What cannot be fixed (a prompt or
tool call that is simply too big) makes the Verdict `block`. Counts are estimated from the
text length unless the provider reported real token counts."""

from __future__ import annotations

import json
import math

from pydantic import BaseModel, Field

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Content, Finding, Stage, Verdict


def estimate_tokens(text: str, chars_per_token: float) -> int:
    return math.ceil(len(text) / chars_per_token)


@control("request_limits")
class RequestLimits(Control):
    stages = {Stage.input, Stage.output, Stage.tool_call, Stage.tool_result}
    feature = "usage_limits"
    description = "Caps the size of every single request, reply and Resource call."

    class Params(BaseModel):
        chars_per_token: float = Field(4.0, gt=0)  # estimate when the provider gives no count
        max_messages: int | None = Field(None, ge=1)  # conversation length sent to the LLM
        max_prompt_tokens: int | None = Field(None, ge=1)  # whole conversation, estimated
        max_completion_tokens: int | None = Field(None, ge=1)  # ceiling on max_tokens and reply
        require_max_tokens: bool = False  # a request without max_tokens gets the ceiling
        max_tool_args_tokens: int | None = Field(None, ge=1)
        max_tool_result_tokens: int | None = Field(None, ge=1)
        truncation_marker: str = " [truncated by AI Control Layer]"

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        if check.stage == Stage.input:
            findings, blocking, content = self._input(check, params)
        elif check.stage == Stage.output:
            findings, blocking, content = self._output(check, params)
        elif check.stage == Stage.tool_call:
            findings, blocking, content = self._tool_call(check, params)
        else:
            findings, blocking, content = self._tool_result(check, params)
        if not findings:
            return Verdict()
        # Like sensitive_data: `redact` when everything was fixed, `block` otherwise, and always
        # the fixed content, so Mode `redact` means "fix what can be fixed, never reject".
        return Verdict(
            action=Action.block if blocking else Action.redact,
            reason="; ".join(finding.detail for finding in findings),
            risk_score=0.8 if blocking else 0.4,
            findings=findings,
            rewritten=content,
        )

    def _finding(self, kind: str, detail: str) -> Finding:
        return Finding(control=self.id, type=kind, detail=detail)

    def _input(self, check: Check, params: Params):
        findings: list[Finding] = []
        blocking = False
        if params.max_messages is not None and len(check.messages) > params.max_messages:
            blocking = True
            findings.append(self._finding(
                "too_many_messages",
                f"{len(check.messages)} messages > limit {params.max_messages}",
            ))
        if params.max_prompt_tokens is not None:
            prompt = sum(
                estimate_tokens(message.content, params.chars_per_token)
                for message in check.messages
            )
            if prompt > params.max_prompt_tokens:
                blocking = True
                findings.append(self._finding(
                    "prompt_too_large",
                    f"prompt ~{prompt} tokens > limit {params.max_prompt_tokens}",
                ))
        max_tokens = check.max_tokens
        ceiling = params.max_completion_tokens
        if ceiling is not None:
            if max_tokens is not None and max_tokens > ceiling:
                findings.append(self._finding(
                    "max_tokens_too_high",
                    f"max_tokens {max_tokens} > limit {ceiling} (lowered to {ceiling})",
                ))
                max_tokens = ceiling
            elif max_tokens is None and params.require_max_tokens:
                findings.append(self._finding(
                    "max_tokens_missing", f"no max_tokens requested (set to {ceiling})"
                ))
                max_tokens = ceiling
        content = Content(messages=check.messages, max_tokens=max_tokens)
        return findings, blocking, content

    def _output(self, check: Check, params: Params):
        ceiling = params.max_completion_tokens
        if check.message is None or ceiling is None:
            return [], False, None
        text = check.message.content
        reported = check.usage.completion_tokens if check.usage else None
        tokens = reported if reported is not None else estimate_tokens(
            text, params.chars_per_token
        )
        if tokens <= ceiling:
            return [], False, None
        source = "" if reported is not None else "~"
        finding = self._finding(
            "reply_too_long", f"reply {source}{tokens} tokens > limit {ceiling} (truncated)"
        )
        truncated = self._truncate(text, ceiling, params)
        return [finding], False, Content(
            message=check.message.model_copy(update={"content": truncated})
        )

    def _tool_call(self, check: Check, params: Params):
        if check.tool is None or params.max_tool_args_tokens is None:
            return [], False, None
        args = json.dumps(check.tool.args, ensure_ascii=False, default=str)
        tokens = estimate_tokens(args, params.chars_per_token)
        if tokens <= params.max_tool_args_tokens:
            return [], False, None
        finding = self._finding(
            "tool_args_too_large",
            f"{check.tool.resource}.{check.tool.action} arguments ~{tokens} tokens "
            f"> limit {params.max_tool_args_tokens}",
        )
        return [finding], True, Content(tool=check.tool)

    def _tool_result(self, check: Check, params: Params):
        limit = params.max_tool_result_tokens
        if check.tool_result is None or limit is None:
            return [], False, None
        tokens = estimate_tokens(check.tool_result, params.chars_per_token)
        if tokens <= limit:
            return [], False, None
        finding = self._finding(
            "tool_result_too_large",
            f"Resource result ~{tokens} tokens > limit {limit} (truncated)",
        )
        return [finding], False, Content(
            tool_result=self._truncate(check.tool_result, limit, params)
        )

    @staticmethod
    def _truncate(text: str, tokens: int, params: Params) -> str:
        keep = int(tokens * params.chars_per_token)
        if len(text) <= keep:
            return text
        return text[:keep] + params.truncation_marker
