"""Client for the firewall admin API. The dashboard talks to the firewall only through this."""

from __future__ import annotations

import os
from typing import Any

import httpx

MODES = ["off", "monitor", "redact", "block"]


class AdminAPIError(RuntimeError):
    pass


class AdminClient:
    def __init__(
        self,
        base_url: str | None = None,
        admin_key: str | None = None,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
    ) -> None:
        base_url = (base_url or os.getenv("FIREWALL_URL", "http://localhost:8001")).rstrip("/")
        admin_key = admin_key if admin_key is not None else os.getenv("ADMIN_KEY", "")
        headers = {"X-Admin-Key": admin_key} if admin_key else {}
        if client is None:
            client = httpx.Client(base_url=base_url, timeout=timeout)
        client.headers.update(headers)
        self.http = client

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            response = self.http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise AdminAPIError(f"firewall unreachable: {exc}") from exc
        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                detail = response.text
            if isinstance(detail, dict) and "errors" in detail:
                detail = "; ".join(detail["errors"])
            raise AdminAPIError(f"{response.status_code}: {detail}")
        return response

    def policy(self) -> dict[str, Any]:
        return self._request("GET", "/v1/admin/policy").json()

    def put_policy(self, yaml_text: str) -> dict[str, Any]:
        return self._request(
            "PUT",
            "/v1/admin/policy",
            content=yaml_text.encode(),
            headers={"Content-Type": "application/yaml"},
        ).json()

    def controls(self) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/admin/controls").json()

    def patch_control(
        self, control_id: str, mode: str | None = None, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        body: dict[str, Any] = {}
        if mode is not None:
            body["mode"] = mode
        if params is not None:
            body["params"] = params
        return self._request("PATCH", f"/v1/admin/controls/{control_id}", json=body).json()

    @staticmethod
    def _filters(**filters: Any) -> dict[str, Any]:
        return {key: value for key, value in filters.items() if value not in (None, "", "any")}

    def events(
        self,
        stage: str | None = None,
        agent_id: str | None = None,
        action: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        params = self._filters(
            stage=stage, agent_id=agent_id, action=action, since=since, limit=limit
        )
        return self._request("GET", "/v1/admin/events", params=params).json()

    def export(self, export_format: str = "jsonl", **filters: Any) -> bytes:
        params = self._filters(format=export_format, **filters)
        return self._request("GET", "/v1/admin/events/export", params=params).content

    def metrics(self) -> dict[str, Any]:
        return self._request("GET", "/v1/admin/metrics").json()
