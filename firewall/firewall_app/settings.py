from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Settings:
    telemetry_endpoint: str | None = None
    telemetry_project: str = "ai-control-layer"
    policy_path: str = "policies/standard.yaml"
    database_url: str = "sqlite+aiosqlite:///./firewall.db"
    admin_key: str | None = None
    upstream_timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            telemetry_endpoint=os.getenv("TELEMETRY_OTLP_ENDPOINT") or None,
            telemetry_project=os.getenv("TELEMETRY_PROJECT", "ai-control-layer"),
            policy_path=os.getenv("POLICY_PATH", "policies/standard.yaml"),
            database_url=os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./firewall.db"),
            admin_key=os.getenv("ADMIN_KEY") or None,
            upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "60")),
        )
