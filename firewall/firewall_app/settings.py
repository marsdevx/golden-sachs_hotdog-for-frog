from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# The one Policy file: policy.yaml in the repository root. Docker sets POLICY_PATH instead.
DEFAULT_POLICY_PATH = str(Path(__file__).resolve().parents[2] / "policy.yaml")


@dataclass(frozen=True, slots=True)
class Settings:
    telemetry_endpoint: str | None = None
    telemetry_project: str = "ai-control-layer"
    policy_path: str = DEFAULT_POLICY_PATH
    database_url: str = "sqlite+aiosqlite:///./firewall.db"
    upstream_timeout_seconds: float = 60.0

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            telemetry_endpoint=os.getenv("TELEMETRY_OTLP_ENDPOINT") or None,
            telemetry_project=os.getenv("TELEMETRY_PROJECT", "ai-control-layer"),
            policy_path=os.getenv("POLICY_PATH", DEFAULT_POLICY_PATH),
            database_url=os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./firewall.db"),
            upstream_timeout_seconds=float(os.getenv("UPSTREAM_TIMEOUT_SECONDS", "60")),
        )
