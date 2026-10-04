"""Settings API for the web console: Policy, Controls, Audit Events, export and metrics.

Read-only for the Policy: the Policy file is changed only by editing it, never through this
API (the firewall picks up a saved file on the next Check).

The firewall runs on the user's own PC and the user owns it, so there is no separate
administrator and no key: the port is bound to 127.0.0.1 and reachable only from this PC."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from firewall_app.controls.base import utcnow
from firewall_app.controls.token_budget import TokenBudget
from firewall_app.domain import Action, Mode, Stage
from firewall_app.storage.budget_state import BudgetState
from firewall_app.storage.loop_state import LoopState
from firewall_app.storage.summary import build_summary

router = APIRouter(prefix="/v1/settings", tags=["settings"])


def _policy_view(store) -> dict[str, Any]:
    policy = store.get()
    return {
        "yaml": store.text,
        "parsed": policy.model_dump(mode="json"),
        "version": policy.version,
        "loaded_at": store.loaded_at.isoformat() if store.loaded_at else None,
        "last_error": store.last_error,
        "warnings": policy.warnings,
        "path": str(store.path),
    }


@router.get("/policy")
async def get_policy(request: Request) -> dict[str, Any]:
    return _policy_view(request.app.state.policy_store)


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
                "feature": cls.feature,
                "feature_on": getattr(policy.features, cls.feature),
                "stages": sorted(settings.effective_stages) if settings else sorted(cls.stages),
                "on_error": (settings.on_error if settings else None)
                or policy.defaults.on_error,
                "params": settings.params if settings else {},
                "params_schema": cls.Params.model_json_schema(),
            }
        )
    return result


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
    session_id: str | None = None,
) -> list[dict[str, Any]]:
    events = await request.app.state.audit.query(**filters, limit=limit, session_id=session_id)
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


@router.get("/summary")
async def summary(request: Request) -> dict[str, Any]:
    """Everything the web console shows, derived from the last 24 hours of Audit Events."""
    return await build_summary(request.app.state.audit, request.app.state.policy_store)


async def _loop_state(request: Request) -> LoopState:
    audit = request.app.state.audit
    await audit.init()
    return LoopState(audit.sessions)


@router.get("/breakers")
async def list_breakers(request: Request) -> list[dict[str, Any]]:
    """Agents stopped by `loop_detector` right now."""
    breakers = await (await _loop_state(request)).breakers(utcnow())
    return [
        {"agent_id": b.agent_id, "opened_at": b.opened_at.isoformat() + "Z",
         "open_until": b.open_until.isoformat() + "Z", "reason": b.reason}
        for b in breakers
    ]


@router.delete("/breakers/{agent_id}")
async def reset_breaker(agent_id: str, request: Request) -> dict[str, Any]:
    """Let a stopped Agent run again before its cooldown ends."""
    if not await (await _loop_state(request)).reset(agent_id):
        raise HTTPException(status_code=404, detail=f"no circuit breaker for {agent_id!r}")
    return {"agent_id": agent_id, "reset": True}


def _budget_line(used: int, limit: int | None, warn_at: float | None) -> dict[str, Any]:
    if limit is None:
        return {"used": used, "limit": None, "percent": None, "state": "no_limit"}
    state = "exhausted" if used >= limit else (
        "warning" if warn_at is not None and used >= warn_at * limit else "ok"
    )
    return {"used": used, "limit": limit, "percent": round(100 * used / limit, 1),
            "state": state}


@router.get("/budgets")
async def budgets(request: Request) -> dict[str, Any]:
    """Token budget usage today (UTC) per Agent and user, and the runs active right now,
    against the limits of the current Policy."""
    settings = request.app.state.policy_store.get().controls.get("token_budget")
    params = settings.parsed_params if settings else TokenBudget.Params()
    audit = request.app.state.audit
    await audit.init()
    state = BudgetState(audit.sessions)
    now = utcnow()
    days = await state.days(now.date().isoformat())
    run = params.per_run
    runs = await state.runs(now - timedelta(seconds=run.idle_seconds))

    def daily(scope: str, budget) -> list[dict[str, Any]]:
        return [
            {"id": d.subject, **_budget_line(d.tokens, budget.tokens_per_day, budget.warn_at)}
            for d in days if d.scope == scope
        ]

    return {
        "day": now.date().isoformat(),
        "mode": settings.mode if settings else Mode.off,
        "active": bool(settings and settings.active),  # false when usage_limits is off
        "agents": daily("agent", params.default),
        "users": daily("user", params.per_user),
        "runs": [
            {
                "agent_id": r.agent_id, "run_id": r.run_id,
                "started_at": r.started_at.isoformat() + "Z",
                "last_seen": r.last_seen.isoformat() + "Z",
                "seconds": int((now - r.started_at).total_seconds()),
                "requests": _budget_line(r.requests, run.requests, run.warn_at),
                "tool_calls": _budget_line(r.tool_calls, run.tool_calls, run.warn_at),
                "tokens": _budget_line(r.tokens, run.tokens, run.warn_at),
            }
            for r in runs
        ],
    }
