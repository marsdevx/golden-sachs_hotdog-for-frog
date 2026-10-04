from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from firewall_app.api import check, console, gemini, proxy, tools, user_settings
from firewall_app.controls import REGISTRY
from firewall_app.observability.tracing import configure
from firewall_app.policy import PolicyStore
from firewall_app.service import CheckService
from firewall_app.settings import Settings
from firewall_app.storage import AuditStore


def create_app(
    policy_path: str | None = None,
    database_url: str | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Wiring only. Run with `uvicorn firewall_app.main:create_app --factory`."""
    settings = Settings.from_env()
    policy_store = PolicyStore(policy_path or settings.policy_path, REGISTRY)
    audit = AuditStore(database_url or settings.database_url)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        await audit.init()
        application.state.telemetry = configure(
            settings.telemetry_endpoint, settings.telemetry_project
        )
        try:
            yield
        finally:
            await asyncio.to_thread(application.state.telemetry.shutdown)
            await audit.close()

    application = FastAPI(title="AI Control Layer Firewall", version="0.2.0", lifespan=lifespan)
    application.state.telemetry = configure(None, settings.telemetry_project)
    application.state.settings = settings
    application.state.policy_store = policy_store
    application.state.audit = audit
    application.state.service = CheckService(audit, REGISTRY)
    application.state.upstream_transport = upstream_transport

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    application.include_router(check.router)
    application.include_router(proxy.router)
    application.include_router(tools.router)
    application.include_router(gemini.router)
    if os.getenv("FIREWALL_SETTINGS_ENABLED", "true").lower() == "true":
        application.include_router(user_settings.router)
        application.include_router(console.router)

    return application
