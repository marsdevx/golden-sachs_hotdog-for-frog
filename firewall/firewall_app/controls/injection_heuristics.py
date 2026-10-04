"""Deterministic Injection detection (OWASP LLM01): known phrasing in English, Polish and
German, also when obfuscated (leetspeak, zero-width characters, Cyrillic look-alikes) or
encoded (base64, hex, URL encoding, rot13). Every Finding names the pattern that matched, so
a Decision is explainable; the Injection text itself is never repeated.

Scans `user` and `tool` messages at `input` (never `system` or `assistant`) and the whole
Resource result at `tool_result`. A hit in a `user` message is direct Injection: `block`,
nothing to rewrite. A hit in Resource content is indirect: the matched sentence (or the whole
encoded blob) is replaced and the Verdict is `redact`, or `block` with `on_indirect: block`.
The direct/indirect Verdict logic below is shared with `injection_classifier`.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal
from urllib.parse import unquote_plus

from pydantic import BaseModel, field_validator

from firewall_app.controls.base import Control, control
from firewall_app.controls.injection_patterns import PATTERNS, Pattern, normalize, quoted
from firewall_app.domain import Action, Check, Content, Finding, Stage, Verdict

REMOVED = "[removed: possible prompt injection]"

# --- shared with injection_classifier --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Source:
    """One scanned text: a message at `input`, or the Resource result at `tool_result`."""

    role: str  # user | tool | tool_result
    text: str
    index: int | None = None  # message index at `input`

    @property
    def indirect(self) -> bool:
        return self.role != "user"

    @property
    def label(self) -> str:
        return "tool_result" if self.index is None else f"{self.role} message #{self.index}"


@dataclass(frozen=True, slots=True)
class Hit:
    source: Source
    finding: Finding
    remove: tuple[int, int]  # span of `source.text` to replace with REMOVED (indirect only)
    risk: float
    name: str  # what matched, for the reason: a pattern id or a model score


def sources(check: Check, new_only: bool = False) -> list[Source]:
    """The texts to scan. `new_only`: only the messages after the last `assistant` message."""
    if check.stage == Stage.tool_result:
        return [Source("tool_result", check.tool_result)] if check.tool_result else []
    first = 0
    if new_only:
        for index, message in enumerate(check.messages):
            if message.role == "assistant":
                first = index + 1
    return [
        Source(message.role, message.content, index)
        for index, message in enumerate(check.messages)
        if index >= first and message.role in ("user", "tool") and message.content
    ]


def remove_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace every span with REMOVED; overlapping or touching spans become one."""
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    for start, end in reversed(merged):
        text = text[:start] + REMOVED + text[end:]
    return text


def injection_verdict(check: Check, hits: list[Hit], on_indirect: str) -> Verdict:
    """Direct Injection blocks; indirect Injection is removed (`redact`) or blocks."""
    if not hits:
        return Verdict()
    direct = any(not hit.source.indirect for hit in hits)
    indirect = [hit for hit in hits if hit.source.indirect]

    # The cleaned content: only indirect parts can be removed. It is returned with
    # `on_indirect: block` too, so Mode `redact` still cleans the Resource content. A direct
    # Injection has no rewrite, so Mode `redact` records it and lets it through.
    rewritten = None
    if indirect and not direct:
        spans: dict[Source, list[tuple[int, int]]] = {}
        for hit in indirect:
            spans.setdefault(hit.source, []).append(hit.remove)
        if check.stage == Stage.tool_result:
            (source, removed), = spans.items()
            rewritten = Content(tool_result=remove_spans(source.text, removed))
        else:
            messages = list(check.messages)
            for source, removed in spans.items():
                messages[source.index] = messages[source.index].model_copy(
                    update={"content": remove_spans(source.text, removed)}
                )
            rewritten = Content(messages=messages)

    kind = "direct" if direct else "indirect"
    names = sorted({hit.name for hit in hits})
    labels = sorted({hit.source.label for hit in hits})
    return Verdict(
        action=Action.block if direct or on_indirect == "block" else Action.redact,
        reason=f"possible {kind} prompt injection ({', '.join(names)}) in {', '.join(labels)}",
        risk_score=max(hit.risk for hit in hits),
        findings=[hit.finding for hit in hits],
        rewritten=rewritten,
    )


# --- heuristics ------------------------------------------------------------------------------

BASE64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,}(?![0-9A-Fa-f])")
URL_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
TOKEN = re.compile(r"\S+")
# A sentence ends at . ! ? followed by whitespace, or at a newline.
BOUNDARY = re.compile(r"[.!?](?=\s)|\n")


def _readable(data: bytes) -> str | None:
    """Decoded bytes as text, if they are mostly printable UTF-8 (not an image header)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(char.isprintable() or char.isspace() for char in text)
    return text if text and printable / len(text) >= 0.9 else None


def _blobs(text: str, decode: list[str]) -> Iterator[tuple[int, int, str, str]]:
    """Encoded blobs in `text`: (start, end, decoded text, encoding)."""
    if "base64" in decode:
        for match in BASE64.finditer(text):
            blob = match.group(0).rstrip("=")
            if len(blob) % 4 == 1:
                continue
            altchars = b"-_" if "-" in blob or "_" in blob else None
            try:
                data = base64.b64decode(blob + "=" * (-len(blob) % 4), altchars, validate=True)
            except (binascii.Error, ValueError):
                continue
            if (decoded := _readable(data)) is not None:
                yield match.start(), match.end(), decoded, "base64"
    if "hex" in decode:
        for match in HEX.finditer(text):
            if (decoded := _readable(bytes.fromhex(match.group(0)))) is not None:
                yield match.start(), match.end(), decoded, "hex"
    if "url" in decode and URL_ESCAPE.search(text):
        for match in TOKEN.finditer(text):
            if URL_ESCAPE.search(match.group(0)):
                yield match.start(), match.end(), unquote_plus(match.group(0)), "url"


def _layers(text: str, decode: list[str], depth: int = 2) -> Iterator[tuple[int, int, str, str]]:
    """Decoded blobs, plus the blobs inside them (one level of nesting)."""
    for start, end, decoded, via in _blobs(text, decode):
        yield start, end, decoded, via
        if depth > 1:
            for _, _, inner, inner_via in _layers(decoded, decode, depth - 1):
                yield start, end, inner, f"{via}+{inner_via}"


def _sentence(text: str, start: int, end: int) -> tuple[int, int]:
    """The sentence around a span: from the previous boundary to the next one."""
    first = 0
    for match in BOUNDARY.finditer(text, 0, start):
        first = match.end()
    while first < start and text[first].isspace():
        first += 1
    following = BOUNDARY.search(text, end)
    if following is None:
        return first, len(text)
    return first, following.start() if following.group(0) == "\n" else following.end()


def _matches(text: str, patterns: list[Pattern]) -> Iterator[tuple[Pattern, tuple[int, int]]]:
    """Pattern hits in `text`, as spans of `text`. Matches plain and leet-folded text."""
    normalized = normalize(text)
    leet = normalized.leet()
    variants = (normalized,) if leet.text == normalized.text else (normalized, leet)
    seen: set[tuple[str, tuple[int, int]]] = set()
    for variant in variants:
        for pattern in patterns:
            for match in pattern.regex.finditer(variant.text):
                if match.end() == match.start() or quoted(variant.text, *match.span()):
                    continue
                span = normalized.span(*match.span())
                if (key := (pattern.id + pattern.language, span)) not in seen:
                    seen.add(key)
                    yield pattern, span


@control("injection_heuristics")
class InjectionHeuristics(Control):
    stages = {Stage.input, Stage.tool_result}
    feature = "input_validation"
    description = (
        "Blocks known prompt-injection phrasing (English, Polish, German), also when hidden "
        "with encoding or look-alike letters; removes it from documents."
    )

    class Params(BaseModel):
        on_indirect: Literal["redact", "block"] = "redact"
        languages: list[Literal["en", "pl", "de"]] = ["en", "pl", "de"]
        decode: list[Literal["base64", "hex", "url", "rot13"]] = ["base64", "hex", "url", "rot13"]
        extra_patterns: list[str] = []  # regexes, matched after normalization

        @field_validator("extra_patterns")
        @classmethod
        def _compiles(cls, value: list[str]) -> list[str]:
            for regex in value:
                try:
                    re.compile(regex)
                except re.error as exc:
                    raise ValueError(f"invalid regex {regex!r}: {exc}") from exc
            return value

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        languages = {"any", *params.languages}
        patterns = [pattern for pattern in PATTERNS if pattern.language in languages]
        patterns += [
            Pattern(f"extra_pattern_{number}", "any", 0.8, re.compile(regex, re.IGNORECASE))
            for number, regex in enumerate(params.extra_patterns, 1)
        ]
        hits: list[Hit] = []
        for source in sources(check):
            active = [p for p in patterns if source.indirect or not p.indirect_only]
            hits.extend(self._scan(source, active, params.decode))
        return injection_verdict(check, hits, params.on_indirect)

    def _scan(self, source: Source, patterns: list[Pattern], decode: list[str]) -> list[Hit]:
        text = source.text
        hits: list[Hit] = []
        seen: set[tuple[str, tuple[int, int]]] = set()

        def hit(pattern: Pattern, remove: tuple[int, int], via: str | None, span=None) -> None:
            if (key := (pattern.id + pattern.language, remove)) in seen:
                return
            seen.add(key)
            detail = f"{pattern.id} ({pattern.language})"
            if via:
                detail += f", via {via}"
            hits.append(Hit(
                source=source,
                finding=Finding(control=self.id, type="injection_pattern",
                                detail=f"{detail}; {source.label}", span=span),
                remove=remove,
                risk=pattern.weight,
                name=pattern.id,
            ))

        for pattern, span in _matches(text, patterns):
            hit(pattern, _sentence(text, *span), None, span)
        if "rot13" in decode:
            # rot13 keeps every character in place, so its spans are spans of the original.
            for pattern, span in _matches(codecs.encode(text, "rot13"), patterns):
                hit(pattern, _sentence(text, *span), "rot13")
        for start, end, decoded, via in _layers(text, decode):
            for pattern, _ in _matches(decoded, patterns):
                hit(pattern, (start, end), via)
        return hits
