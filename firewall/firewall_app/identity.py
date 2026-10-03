"""Agent identity: the `X-Agent-Key` header (or `Authorization: Bearer <key>`) -> Agent."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from firewall_app.domain import UNKNOWN_AGENT, Agent
from firewall_app.policy.schema import Policy


@dataclass(frozen=True, slots=True)
class Identity:
    agent: Agent
    known: bool
    # False when the key is missing or unknown and the Policy says `unknown_agent: block`.
    allowed: bool


def agent_key(headers: Mapping[str, str]) -> str | None:
    key = headers.get("x-agent-key")
    if key:
        return key.strip()
    scheme, _, token = (headers.get("authorization") or "").partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    return None


def resolve_agent(headers: Mapping[str, str], policy: Policy) -> Identity:
    key = agent_key(headers)
    if key:
        for entry in policy.agents:
            if hmac.compare_digest(entry.key.encode(), key.encode()):
                agent = Agent(id=entry.id, owner=entry.owner, team=entry.team)
                return Identity(agent=agent, known=True, allowed=True)
    allowed = policy.defaults.unknown_agent == "allow"
    return Identity(agent=UNKNOWN_AGENT.model_copy(), known=False, allowed=allowed)
