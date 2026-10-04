"""Historical attack mitigation (R4): blocks payloads matching exploits that worked before.

Signatures come from a feed managed outside the Policy (a file, or an https:// URL a security
team or vendor publishes) and are hot reloaded: a file when its mtime changes, a URL every
`refresh_seconds` (with ETag). A broken feed (bad YAML, bad regex, duplicate id) is rejected
and the last good feed stays in force; with no good feed at all, `evaluate` raises and the
Policy's `on_error` decides (fail closed by default).

Every signature carries its OWASP Agentic Top 10 code (ASI01..ASI10), cited in each Finding
together with the signature id and the feed version, so an Audit Event says which signature
of which feed stopped the call.

What is scanned, per Stage:
- `input`: every message of the conversation;
- `tool_call`: `resource.action` plus every argument as a `path.to.arg=value` line, so a
  signature can target an argument by name (e.g. `bcc=`);
- `tool_result`: what the Resource returned (indirect prompt injection, poisoned files).

A relative `feed` path is resolved against the folder of the Policy file (`POLICY_PATH`).
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from firewall_app.controls.base import Control, control
from firewall_app.domain import Action, Check, Content, Finding, Message, Stage, Verdict
from firewall_app.settings import DEFAULT_POLICY_PATH

logger = logging.getLogger("firewall.attack_signatures")

SUPPORTED_STAGES = {Stage.input, Stage.tool_call, Stage.tool_result}
FETCH_TIMEOUT_SECONDS = 5.0


class Signature(BaseModel):
    """One known attack pattern."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]*$")
    category: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    asi: str | None = Field(None, pattern=r"^ASI(?:0[1-9]|10)$")
    stages: list[Stage] = Field(default_factory=lambda: sorted(SUPPORTED_STAGES), min_length=1)
    pattern: str
    action: Literal["block", "review"] = "block"
    severity: float = Field(0.9, ge=0, le=1)
    description: str
    reference: str = ""

    _regex: re.Pattern[str] = PrivateAttr()

    @field_validator("stages")
    @classmethod
    def _supported(cls, value: list[Stage]) -> list[Stage]:
        unsupported = set(value) - SUPPORTED_STAGES
        if unsupported:
            raise ValueError(f"stages {sorted(unsupported)} not supported")
        return value

    @model_validator(mode="after")
    def _compile(self) -> Signature:
        try:
            self._regex = re.compile(self.pattern)
        except re.error as exc:
            raise ValueError(f"signature {self.id!r}: invalid regex: {exc}") from exc
        return self

    @property
    def regex(self) -> re.Pattern[str]:
        return self._regex

    @property
    def label(self) -> str:
        return f"{self.id} ({self.asi})" if self.asi else self.id


class Feed(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = ""
    signatures: list[Signature] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids(self) -> Feed:
        ids = [signature.id for signature in self.signatures]
        duplicates = sorted({sid for sid in ids if ids.count(sid) > 1})
        if duplicates:
            raise ValueError(f"duplicate signature ids {duplicates}")
        return self


class FeedError(RuntimeError):
    pass


def parse_feed(data: bytes) -> Feed:
    try:
        raw = yaml.safe_load(data.decode("utf-8"))
        return Feed.model_validate(raw or {})
    except (yaml.YAMLError, UnicodeDecodeError, ValidationError) as exc:
        raise FeedError(f"invalid feed: {exc}") from exc


async def http_get(url: str, headers: dict[str, str]) -> httpx.Response:
    """Fetch a URL feed. Tests replace this function."""
    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT_SECONDS) as client:
        return await client.get(url, headers=headers)


class FeedSource:
    """The last good Feed of one location, reloaded when it changes."""

    def __init__(self, location: str, refresh_seconds: int) -> None:
        self.location = location
        self.refresh_seconds = refresh_seconds
        self.is_url = location.startswith(("https://", "http://"))
        self.feed: Feed | None = None
        self.last_error: str | None = None
        self._stamp: Any = None  # (mtime_ns, size) for a file, the ETag for a URL
        self._fetched_at: float | None = None
        self._lock = asyncio.Lock()

    async def get(self) -> Feed:
        if self.is_url:
            if self._refresh_due():
                async with self._lock:
                    await self._refresh_url()
        else:
            self._refresh_file()
        if self.feed is None:
            raise FeedError(f"no usable signature feed: {self.last_error}")
        return self.feed

    def _refresh_due(self) -> bool:
        if self._fetched_at is None:
            return True
        return time.monotonic() - self._fetched_at >= self.refresh_seconds

    def _refresh_file(self) -> None:
        path = Path(self.location)
        try:
            stat = path.stat()
            stamp = (stat.st_mtime_ns, stat.st_size)
            if stamp == self._stamp:
                return
            data = path.read_bytes()
        except OSError as exc:
            self._fail(f"cannot read {path}: {exc}")
            return
        # Remember the stamp even on failure, so a broken file is not re-parsed on every Check.
        self._stamp = stamp
        self._load(data)

    async def _refresh_url(self) -> None:
        if not self._refresh_due():
            return  # another Check refreshed it while we waited for the lock
        self._fetched_at = time.monotonic()
        headers = {"If-None-Match": self._stamp} if self._stamp and self.feed else {}
        try:
            response = await http_get(self.location, headers)
        except httpx.HTTPError as exc:
            self._fail(f"cannot fetch {self.location}: {type(exc).__name__}")
            return
        if response.status_code == 304:
            return
        if response.status_code != 200:
            self._fail(f"cannot fetch {self.location}: HTTP {response.status_code}")
            return
        if self._load(response.content):
            self._stamp = response.headers.get("etag")

    def _load(self, data: bytes) -> bool:
        try:
            feed = parse_feed(data)
        except FeedError as exc:
            self._fail(str(exc))
            return False
        self.feed = feed
        self.last_error = None
        logger.info(
            "Signature feed %s loaded from %s (%d signatures)",
            feed.version or "(no version)", self.location, len(feed.signatures),
        )
        return True

    def _fail(self, error: str) -> None:
        if error != self.last_error:
            if self.feed is not None:
                logger.error("Signature feed rejected, keeping the last good feed: %s", error)
            else:
                logger.error("Signature feed rejected: %s", error)
        self.last_error = error


def resolve_feed(location: str) -> str:
    if location.startswith("https://"):
        return location
    if location.startswith("http://"):
        # A plain-http feed can be swapped in transit: only allow it on this machine.
        if urlparse(location).hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("feed URL must use https:// (http:// only for localhost)")
        return location
    if "://" in location:
        raise ValueError("feed must be a file path or an https:// URL")
    path = Path(location).expanduser()
    if not path.is_absolute():
        policy_dir = Path(os.getenv("POLICY_PATH", DEFAULT_POLICY_PATH)).parent
        path = policy_dir / path
    return str(path.resolve())


class Params(BaseModel):
    # File path (relative to the Policy's folder) or https:// URL of the signature feed.
    feed: str | None = None
    refresh_seconds: int = Field(60, ge=1, le=86400)  # URL feeds only; files reload on change
    # Only these categories run (None: all). E.g. [deserialization, code_exec, supply_chain].
    categories: list[str] | None = None
    # Signature ids switched off here, e.g. after a false positive, without editing the feed.
    disabled: list[str] = Field(default_factory=list)
    # Signatures of this Policy on top of the feed; same id replaces the feed's.
    signatures: list[Signature] = Field(default_factory=list)
    # Tool argument names never scanned at tool_call (e.g. a trusted `content` field).
    skip_args: list[str] = Field(default_factory=list)
    replacement: str = "[REMOVED:{id}]"  # redact Mode, input and tool_result only

    _source: FeedSource | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _source_from_feed(self) -> Params:
        if self.feed is None and not self.signatures:
            raise ValueError("set a feed or at least one signature")
        if self.feed is not None:
            self._source = FeedSource(resolve_feed(self.feed), self.refresh_seconds)
        return self

    async def active_signatures(self, stage: Stage) -> tuple[list[Signature], str]:
        """The signatures that run at `stage`, and the feed version."""
        feed = await self._source.get() if self._source else Feed()
        by_id = {signature.id: signature for signature in feed.signatures}
        by_id.update({signature.id: signature for signature in self.signatures})
        disabled = set(self.disabled)
        active = [
            signature
            for signature in by_id.values()
            if stage in signature.stages
            and signature.id not in disabled
            and (self.categories is None or signature.category in self.categories)
        ]
        return active, feed.version


def flatten_args(args: Any, skip: set[str], prefix: str = "") -> list[str]:
    """`path.to.arg=value` lines for every scalar argument, lists and nested dicts included."""
    lines: list[str] = []
    if isinstance(args, dict):
        for name, value in args.items():
            if str(name) in skip:
                continue
            lines.extend(flatten_args(value, skip, f"{prefix}.{name}" if prefix else str(name)))
    elif isinstance(args, list):
        for index, item in enumerate(args):
            lines.extend(flatten_args(item, skip, f"{prefix}[{index}]"))
    elif args is not None:
        lines.append(f"{prefix}={args}")
    return lines


@control("attack_signatures")
class AttackSignatures(Control):
    stages = SUPPORTED_STAGES
    feature = "attack_mitigation"
    description = (
        "Blocks payloads matching known historical attacks on AI systems (unsafe "
        "deserialization, code execution, supply chain, destructive commands, injected "
        "instructions), from an externally managed signature feed."
    )
    Params = Params

    async def evaluate(self, check: Check, params: Params) -> Verdict:
        signatures, version = await params.active_signatures(check.stage)
        if not signatures:
            return Verdict()

        # (where, text) segments to scan.
        if check.stage == Stage.input:
            segments = [(f"message {i}", m.content) for i, m in enumerate(check.messages)]
        elif check.stage == Stage.tool_call:
            tool = check.tool
            if tool is None:
                raise ValueError("tool_call Check without a tool")
            args = flatten_args(tool.args, set(params.skip_args))
            lines = [f"{tool.resource}.{tool.action}", *args]
            segments = [("tool call", "\n".join(lines))]
        else:
            segments = [("tool result", check.tool_result or "")]

        findings: list[Finding] = []
        hits: dict[str, Signature] = {}
        rewritten = [text for _, text in segments]
        feed = f"feed {version}" if version else "local signatures"
        for index, (where, text) in enumerate(segments):
            for signature in signatures:
                matches = list(signature.regex.finditer(text))
                if not matches:
                    continue
                hits[signature.id] = signature
                # Never put the matched text in a Finding: it may be a live payload or a secret.
                count = f", {len(matches)} matches" if len(matches) > 1 else ""
                findings.append(
                    Finding(
                        control=self.id,
                        type=signature.category,
                        detail=f"{signature.label} {signature.description}; {where}{count}; {feed}",
                        span=None if check.stage == Stage.tool_call else matches[0].span(),
                    )
                )
                token = params.replacement.replace("{id}", signature.id)
                rewritten[index] = signature.regex.sub(token, rewritten[index])

        if not hits:
            return Verdict()
        matched = list(hits.values())
        blocking = any(signature.action == "block" for signature in matched)
        return Verdict(
            action=Action.block if blocking else Action.review,
            reason="matches known attack " + ", ".join(s.label for s in matched),
            risk_score=max(signature.severity for signature in matched),
            findings=findings,
            rewritten=self._rewrite(check, rewritten),
        )

    @staticmethod
    def _rewrite(check: Check, texts: list[str]) -> Content | None:
        # Tool arguments are never rewritten: a half-removed payload is still a command.
        if check.stage == Stage.input:
            messages: list[Message] = [
                message.model_copy(update={"content": text})
                for message, text in zip(check.messages, texts, strict=True)
            ]
            return Content(messages=messages)
        if check.stage == Stage.tool_result:
            return Content(tool_result=texts[0])
        return None
