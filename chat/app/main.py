from __future__ import annotations

import logging
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.agent.graph import AgentWorkflow
from app.config import Settings
from app.firewall_client import FirewallClient
from app.models import ChatRequest, ChatResponse

logger = logging.getLogger("ai_control_layer")


def create_app(control: FirewallClient | None = None) -> FastAPI:
    settings = Settings.from_env()
    control_client = control or FirewallClient(settings)
    workflow = AgentWorkflow(control_client)

    application = FastAPI(title="Demo Chat", version="0.1.0")
    static_dir = Path(__file__).parent / "static"
    application.mount("/static", StaticFiles(directory=static_dir), name="static")

    @application.get("/", response_class=FileResponse, include_in_schema=False)
    async def chat_page() -> FileResponse:
        return FileResponse(static_dir / "index.html")

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/llm", deprecated=True)
    @application.get("/health/firewall")
    async def llm_health() -> dict[str, object]:
        try:
            return await control_client.health()
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    @application.post("/v1/chat", response_model=ChatResponse)
    async def chat(request: ChatRequest) -> ChatResponse:
        request_id = str(uuid4())
        try:
            result = await workflow.invoke(request)
        except RuntimeError as exc:
            logger.error("Chat dependency failed request_id=%s: %s", request_id, exc)
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        return ChatResponse(
            request_id=request_id,
            run_id=result["run_id"], steps=result["steps"],
            message=result["response"],
            model=result["model"],
            usage=result["usage"],
            input_decision=result["input_decision"],
            output_decision=result["output_decision"],
        )

    return application


app = create_app()
