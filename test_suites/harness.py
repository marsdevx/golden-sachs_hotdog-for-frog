"""Helpers for the acceptance suites (no pytest hooks here, so the module name never clashes).

Every test gets its own copy of the real Policy (`policy.yaml`), its own SQLite file and its
own firewall app, all in a temp dir. Tests drive the firewall the way an operator does: by
editing the Policy file, which the firewall hot reloads. The built-in `mock` model echoes the
last user message, so whatever a test sends comes back as the model's answer.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from fastapi.testclient import TestClient
from firewall_app.controls.base import utcnow

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_FILE = REPO_ROOT / "policy.yaml"
DATA = Path(__file__).resolve().parent / "data"
SETTINGS = "/v1/settings"  # the user's own API: policy, controls, events, metrics (no admin role)
AGENT_KEY = "demo-agent-key"  # research-assistant, owner alice@bank.example
TRADER_KEY = "trading-agent-key"  # trading-assistant, owner bob@bank.example


def load_cases(name: str, group: str) -> list[dict[str, Any]]:
    """Test data lives in test_suites/data/<name>.yaml, apart from the test code."""
    return yaml.safe_load((DATA / f"{name}.yaml").read_text())[group]


class FakeClock:
    """Time the firewall's windows, cooldowns and daily budgets run on. Tests move it forward
    instead of waiting. It starts at the real current time and stands still until advanced."""

    def __init__(self) -> None:
        self.now = utcnow()

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def advance_to_next_utc_day(self) -> None:
        self.now = (self.now + timedelta(days=1)).replace(hour=0, minute=0, second=1, microsecond=0)


def _merge(target: dict[str, Any], changes: dict[str, Any]) -> None:
    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            _merge(target[key], value)
        else:
            target[key] = value


class PolicyFile:
    """A temp copy of a Preset. Edits are written to disk; the firewall picks them up itself."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._writes = 0

    def load(self) -> dict[str, Any]:
        return yaml.safe_load(self.path.read_text())

    def save(self, data: dict[str, Any]) -> None:
        self.path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))
        self._writes += 1
        stat = self.path.stat()
        # Make sure a change is seen even on filesystems with coarse mtime.
        os.utime(self.path, ns=(stat.st_atime_ns, stat.st_mtime_ns + self._writes * 1_000_000_000))

    def set_mode(self, control: str, mode: str) -> None:
        data = self.load()
        data["controls"][control]["mode"] = mode
        self.save(data)

    def set_params(self, control: str, **params: Any) -> None:
        """Change settings of a Control; nested sections are merged, not replaced.
        `set_params("token_budget", per_user={"tokens_per_day": 15})`"""
        data = self.load()
        _merge(data["controls"][control].setdefault("params", {}), params)
        self.save(data)

    def set_category(self, name: str, **fields: Any) -> None:
        """Change one `sensitive_data` category, e.g. `set_category("card", enabled=False)`."""
        data = self.load()
        categories = data["controls"]["sensitive_data"]["params"]["categories"]
        next(c for c in categories if c["name"] == name).update(fields)
        self.save(data)

    def set_store_content(self, value: str) -> None:
        data = self.load()
        data["audit"]["store_content"] = value
        self.save(data)

    def label(self, category: str) -> str:
        """What a redacted value is replaced with."""
        for item in self.load()["controls"]["sensitive_data"]["params"]["categories"]:
            if item["name"] == category:
                return item.get("replacement") or f"[{category.upper()}]"
        raise KeyError(category)


@dataclass
class Reply:
    """A chat completion from the firewall proxy."""

    status: int
    body: dict[str, Any]

    @property
    def answer(self) -> str:
        return self.body["choices"][0]["message"]["content"]

    @property
    def finish_reason(self) -> str:
        return self.body["choices"][0]["finish_reason"]

    @property
    def firewall(self) -> dict[str, Any]:
        return self.body["firewall"]

    @property
    def blocked(self) -> bool:
        return self.finish_reason == "content_filter"

    @property
    def reason(self) -> str:
        return self.firewall["reason"]

    @property
    def reached_the_model(self) -> bool:
        """The output Check only exists when the request got past the input Check."""
        return self.firewall["output"] is not None

    def input_findings(self) -> list[dict[str, Any]]:
        return self.firewall["input"]["decision"]["findings"]

    @property
    def output_verdicts(self) -> list[dict[str, Any]]:
        return self.firewall["output"]["decision"]["verdicts"]

    def dump(self) -> str:
        return json.dumps(self.body)


class Gateway:
    def __init__(
        self, client: TestClient, policy: PolicyFile, clock: FakeClock | None = None
    ) -> None:
        self.client = client
        self.policy = policy
        self.clock = clock or FakeClock()

    def chat(
        self,
        text: str | None = None,
        *,
        messages: list[dict[str, str]] | None = None,
        user: str | None = None,
        session_id: str | None = None,
        max_tokens: int | None = None,
        model: str = "mock",
        key: str = AGENT_KEY,
    ) -> Reply:
        """One call through the proxy. `session_id` names the Agent run; `user` is who asked."""
        body: dict[str, Any] = {
            "model": model,
            "messages": messages or [{"role": "user", "content": text}],
        }
        if user is not None:
            body["user"] = user
        if session_id is not None:
            body["metadata"] = {"session_id": session_id}
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        response = self.client.post(
            "/v1/chat/completions", headers={"Authorization": f"Bearer {key}"}, json=body
        )
        return Reply(response.status_code, response.json())

    def breakers(self) -> list[dict[str, Any]]:
        """Agents the loop detector has stopped right now."""
        return self.client.get(f"{SETTINGS}/breakers").json()

    def reset_breaker(self, agent_id: str) -> int:
        return self.client.delete(f"{SETTINGS}/breakers/{agent_id}").status_code

    def policy_view(self) -> dict[str, Any]:
        """What the firewall has loaded, and the error of the last rejected edit, if any."""
        return self.client.get(f"{SETTINGS}/policy").json()

    def budgets(self) -> dict[str, Any]:
        return self.client.get(f"{SETTINGS}/budgets").json()

    def check(self, stage: str, body: dict[str, Any], *, key: str = AGENT_KEY) -> dict[str, Any]:
        response = self.client.post(
            f"/v1/check/{stage}", headers={"X-Agent-Key": key}, json=body
        )
        assert response.status_code == 200, response.text
        return response.json()

    def events(self, **filters: Any) -> list[dict[str, Any]]:
        response = self.client.get(f"{SETTINGS}/events", params={"limit": 100, **filters})
        assert response.status_code == 200, response.text
        return response.json()
