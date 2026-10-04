"""What one Agent run is: the single definition every transport and Control uses.

A run is one conversation or task. The Agent can name it with `metadata.session_id`;
otherwise a conversation is its run, recognised by its start (first system and first user
message), because LLM Agents resend the whole conversation with the same start every turn.
The transports stamp the run on every Check of a request, so the output Check of a proxied
call belongs to the same run as its input."""

from __future__ import annotations

import hashlib
from typing import Any

from firewall_app.domain import Message


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:32]


def run_id_of(messages: list[Message] | None, metadata: dict[str, Any]) -> str | None:
    """The run of a request, or None when it cannot be told (no session id, no conversation)."""
    given = metadata.get("session_id")
    if isinstance(given, str | int) and not isinstance(given, bool) and str(given):
        return "session:" + _digest(str(given))
    if not messages:
        return None
    start = [
        next((message.content for message in messages if message.role == role), "")
        for role in ("system", "user")
    ]
    return "conversation:" + _digest("\x00".join(start))
