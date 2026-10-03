"""Admin API for the dashboard: Policy, Controls, Audit Events, export and metrics.

Protected by `X-Admin-Key` when `ADMIN_KEY` is set; open otherwise (development)."""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Any, Literal

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from firewall_app.domain import Action, Mode, Stage
from firewall_app.policy import PolicyError, dump_policy


async def require_admin(request: Request) -> None:
    expected = request.app.state.settings.admin_key
    if not expected:
        return
    given = request.headers.get("x-admin-key", "")
    if not hmac.compare_digest(given.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="missing or invalid X-Admin-Key")


router = APIRouter(prefix="/v1/admin", tags=["admin"], dependencies=[Depends(require_admin)])


class ControlPatch(BaseModel):
    mode: Mode | None = None
    params: dict[str, Any] | None = None


def _policy_view(store) -> dict[str, Any]:
    policy = store.get()
    return {
        "yaml": store.text,
        "parsed": policy.model_dump(mode="json"),
        "version": policy.version,
        "loaded_at": store.loaded_at.isoformat() if store.loaded_at else None,
        "last_error": store.last_error,
        "path": str(store.path),
    }


def _write(store, text: str) -> dict[str, Any]:
    try:
        store.write(text)
    except PolicyError as exc:
        raise HTTPException(status_code=422, detail={"errors": exc.errors}) from exc
    return _policy_view(store)


@router.get("/policy")
async def get_policy(request: Request) -> dict[str, Any]:
    return _policy_view(request.app.state.policy_store)


@router.put(
    "/policy",
    openapi_extra={
        "requestBody": {"content": {"application/yaml": {"schema": {"type": "string"}}}}
    },
)
async def put_policy(request: Request) -> dict[str, Any]:
    raw = await request.body()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=422, detail={"errors": ["body is not UTF-8"]}) from exc
    return _write(request.app.state.policy_store, text)


@router.get("/controls")
async def list_controls(request: Request) -> list[dict[str, Any]]:
    store = request.app.state.policy_store
    policy = store.get()
    registry = store.registry
    in_policy = [cid for cid in policy.controls if cid in registry]
    others = [cid for cid in registry.all() if cid not in policy.controls]
    result = []
    for control_id in in_policy + others:
        cls = registry.get(control_id)
        settings = policy.controls.get(control_id)
        result.append(
            {
                "id": control_id,
                "description": settings.description if settings else cls.description,
                "supported_stages": sorted(cls.stages),
                "in_policy": settings is not None,
                "mode": settings.mode if settings else Mode.off,
                "stages": sorted(settings.effective_stages) if settings else sorted(cls.stages),
                "on_error": (settings.on_error if settings else None)
                or policy.defaults.on_error,
                "params": settings.params if settings else {},
                "params_schema": cls.Params.model_json_schema(),
            }
        )
    return result


@router.patch("/controls/{control_id}")
async def patch_control(control_id: str, patch: ControlPatch, request: Request) -> dict[str, Any]:
    """Edit one Control in the Policy file. The file is re-serialized: comments are lost."""
    store = request.app.state.policy_store
    if control_id not in store.registry:
        raise HTTPException(status_code=404, detail=f"unknown Control {control_id!r}")
    policy = store.get()
    data = yaml.safe_load(dump_policy(policy))
    controls = data.setdefault("controls", {})
    section = controls.setdefault(control_id, {"mode": Mode.off.value})
    if patch.mode is not None:
        section["mode"] = patch.mode.value
    if patch.params is not None:
        section["params"] = {**section.get("params", {}), **patch.params}
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    return _write(store, text)


def _filters(
    stage: Stage | None = None,
    agent_id: str | None = None,
    action: Action | None = None,
    since: datetime | None = None,
) -> dict[str, Any]:
    return {"stage": stage, "agent_id": agent_id, "action": action, "since": since}


@router.get("/events")
async def list_events(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, Any]]:
    events = await request.app.state.audit.query(**filters, limit=limit)
    return [event.model_dump(mode="json") for event in events]


@router.get("/events/export")
async def export_events(
    request: Request,
    filters: dict[str, Any] = Depends(_filters),
    format: Literal["jsonl", "csv"] = "jsonl",
) -> StreamingResponse:
    media_type = "application/x-ndjson" if format == "jsonl" else "text/csv"
    return StreamingResponse(
        request.app.state.audit.export(format, **filters),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="audit-events.{format}"'},
    )


@router.get("/metrics")
async def metrics(request: Request) -> dict[str, Any]:
    return await request.app.state.audit.metrics()
