from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    llm_model: str = "mock"
    firewall_url: str = "http://localhost:8001"
    firewall_timeout_seconds: float = 130.0
    agent_key: str = "demo-agent-key"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            llm_model=os.getenv("LLM_MODEL", "mock"),
            firewall_url=os.getenv("FIREWALL_URL", "http://localhost:8001").rstrip("/"),
            firewall_timeout_seconds=float(os.getenv("FIREWALL_TIMEOUT_SECONDS", "130")),
            agent_key=os.getenv("AGENT_KEY", "demo-agent-key"),
        )
