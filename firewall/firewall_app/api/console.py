"""The web console: a single static page. It holds no data; it reads /v1/settings/summary.
The firewall runs on the user's own PC (127.0.0.1), so there is no key.
`features.console: false` in the Policy removes the page (404) on the next request."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

PAGE = Path(__file__).resolve().parent.parent / "console" / "index.html"

router = APIRouter(tags=["console"])


@router.get("/console", response_class=HTMLResponse, include_in_schema=False)
async def console(request: Request) -> HTMLResponse:
    if not request.app.state.policy_store.get().features.console:
        raise HTTPException(status_code=404, detail="the web console is switched off")
    return HTMLResponse(PAGE.read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})
