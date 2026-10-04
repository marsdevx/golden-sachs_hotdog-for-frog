"""Reference Control: blocks (or redacts) forbidden phrases. Copy this file to add a Control."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Content, Finding, Message, Stage, Verdict


@control("keyword_blocklist")
class KeywordBlocklist(Control):
    stages = {Stage.input, Stage.output}
    feature = "input_validation"
    description = "Blocks messages containing forbidden phrases."

    class Params(BaseModel):
        keywords: list[str] = Field(default_factory=list)
        replacement: str = "[REDACTED]"

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        keywords = [keyword for keyword in params.keywords if keyword.strip()]
        if not keywords:
            return Verdict()
        pattern = re.compile("|".join(re.escape(keyword) for keyword in keywords), re.IGNORECASE)

        # Input checks inspect every message of the conversation, output checks the reply.
        messages = check.messages if check.stage == Stage.input else [check.message]
        findings: list[Finding] = []
        phrases: set[str] = set()
        rewritten: list[Message] = []
        for index, message in enumerate(messages):
            if message is None:
                continue
            for match in pattern.finditer(message.content):
                phrases.add(match.group(0).lower())
                findings.append(
                    Finding(
                        control=self.id,
                        type="forbidden_phrase",
                        detail=f"message {index} contains {match.group(0)!r}",
                        span=match.span(),
                    )
                )
            content = pattern.sub(params.replacement, message.content)
            rewritten.append(message.model_copy(update={"content": content}))

        if not findings:
            return Verdict()
        # Return the redacted content too, so the Control also works in `redact` Mode.
        if check.stage == Stage.input:
            redacted = Content(messages=rewritten)
        else:
            redacted = Content(message=rewritten[0])
        return Verdict(
            action=Action.block,
            reason="forbidden phrase " + ", ".join(repr(phrase) for phrase in sorted(phrases)),
            risk_score=1.0,
            findings=findings,
            rewritten=redacted,
        )
