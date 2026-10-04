"""Finds Sensitive Data using categories written in the Policy. A new legal requirement
("PESEL numbers are sensitive") is a new category in policy.yaml, not a code change.

`level` is the strictness slider: each category belongs to a `group` (personal < financial <
secrets) and `level` switches the groups on cumulatively. `level: personal` covers personal
data only; `financial` adds payment data; `secrets` adds keys and tokens. A category without a
group (e.g. a deal's client names) runs at every level."""

from __future__ import annotations

import re
from collections import Counter
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from firewall_app.controls.base import Control, control
from firewall_app.controls.sensitive_validators import VALIDATORS
from firewall_app.domain import Action, Check, Content, Finding, Stage, Verdict

ValidatorName = Literal["luhn", "iban", "pesel_checksum", "entropy"]
Group = Literal["personal", "financial", "secrets"]
GROUP_RANK: dict[str, int] = {"personal": 0, "financial": 1, "secrets": 2}


class Category(BaseModel):
    """One kind of Sensitive Data, written by IT in the Policy."""

    model_config = ConfigDict(extra="forbid")  # a typo like `patern:` is a load error

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str = ""
    patterns: list[str] = Field(default_factory=list)  # regexes
    keywords: list[str] = Field(default_factory=list)  # literal terms, any case, whole words
    validator: ValidatorName | None = None
    context: list[str] = Field(default_factory=list)  # match only if one of these words is near
    context_window: int = Field(40, ge=1, le=500)  # "near" = this many characters either side
    replacement: str | None = None  # default "[NAME]"
    on_match: Literal["redact", "block"] = "redact"
    enabled: bool = True
    group: Group | None = None  # the slider step that switches it on; None: always on

    _regexes: list[re.Pattern[str]] = PrivateAttr(default_factory=list)

    @model_validator(mode="after")
    def _compile(self) -> Category:
        if not self.patterns and not self.keywords:
            raise ValueError(f"category {self.name!r} needs patterns or keywords")
        try:
            self._regexes = [re.compile(pattern) for pattern in self.patterns]
        except re.error as exc:
            raise ValueError(f"category {self.name!r}: invalid regex: {exc}") from exc
        words = [re.escape(word) for word in self.keywords if word.strip()]
        if words:
            self._regexes.append(re.compile(r"(?i)\b(?:" + "|".join(words) + r")\b"))
        return self

    @property
    def label(self) -> str:
        return self.replacement or f"[{self.name.upper()}]"

    def matches(self, text: str) -> list[tuple[int, int]]:
        """Spans of `text` that are this category, after the validator and context checks."""
        spans = []
        lowered_context = [word.lower() for word in self.context]
        for regex in self._regexes:
            for match in regex.finditer(text):
                start, end = match.span()
                if start == end:
                    continue
                if self.validator and not VALIDATORS[self.validator](match.group(0)):
                    continue
                if lowered_context:
                    window = text[max(0, start - self.context_window) : end + self.context_window]
                    if not any(word in window.lower() for word in lowered_context):
                        continue
                spans.append((start, end))
        return spans


def _resolve_overlaps(hits: list[tuple[int, int, Category]]) -> list[tuple[int, int, Category]]:
    """Earliest first, longest first at the same start; drop anything overlapping a kept hit."""
    kept: list[tuple[int, int, Category]] = []
    for start, end, category in sorted(hits, key=lambda hit: (hit[0], hit[0] - hit[1])):
        if kept and start < kept[-1][1]:
            continue
        kept.append((start, end, category))
    return kept


@control("sensitive_data")
class SensitiveData(Control):
    stages = {Stage.input, Stage.output, Stage.tool_result}
    feature = "data_protection"
    description = (
        "Finds Sensitive Data (personal, financial, secrets) "
        "using categories defined in the Policy."
    )

    class Params(BaseModel):
        # The slider: personal < financial < secrets. None: every category, whatever its group.
        level: Group | None = None
        categories: list[Category] = Field(default_factory=list)

        @model_validator(mode="after")
        def _unique_names(self) -> SensitiveData.Params:
            names = [category.name for category in self.categories]
            duplicates = sorted({name for name in names if names.count(name) > 1})
            if duplicates:
                raise ValueError(f"duplicate category names: {duplicates}")
            return self

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        if check.stage == Stage.input:
            texts = [message.content for message in check.messages]
        elif check.stage == Stage.output:
            texts = [check.message.content] if check.message is not None else []
        else:
            texts = [check.tool_result] if check.tool_result is not None else []
        categories = [
            category for category in params.categories
            if category.enabled and (
                params.level is None or category.group is None
                or GROUP_RANK[category.group] <= GROUP_RANK[params.level]
            )
        ]
        if not texts or not categories:
            return Verdict()

        findings: list[Finding] = []
        counts: Counter[str] = Counter()
        wants_block = False
        new_texts: list[str] = []
        for index, text in enumerate(texts):
            hits = [
                (start, end, category)
                for category in categories
                for start, end in category.matches(text)
            ]
            kept = _resolve_overlaps(hits)
            where = f" in message {index}" if check.stage == Stage.input else ""
            for start, end, category in kept:
                counts[category.name] += 1
                wants_block = wants_block or category.on_match == "block"
                # Never the matched value: Decisions go back to the Agent and into the audit log.
                findings.append(
                    Finding(
                        control=self.id,
                        type=category.name,
                        detail=f"{category.name}{where} at {start}..{end}",
                        span=(start, end),
                    )
                )
            for start, end, category in reversed(kept):
                text = text[:start] + category.label + text[end:]
            new_texts.append(text)

        if not findings:
            return Verdict()
        if check.stage == Stage.input:
            rewritten = Content(
                messages=[
                    message.model_copy(update={"content": text})
                    for message, text in zip(check.messages, new_texts)
                ]
            )
        elif check.stage == Stage.output:
            rewritten = Content(message=check.message.model_copy(update={"content": new_texts[0]}))
        else:
            rewritten = Content(tool_result=new_texts[0])
        # Always return `rewritten`: the Mode caps `block` to `redact` (see cap_by_mode).
        return Verdict(
            action=Action.block if wants_block else Action.redact,
            reason="sensitive data: "
            + ", ".join(f"{name} ({count})" for name, count in sorted(counts.items())),
            risk_score=1.0 if wants_block else 0.7,
            findings=findings,
            rewritten=rewritten,
        )
