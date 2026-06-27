"""DASH-01/02/03 — minimal server-rendered operator dashboard (Jinja2 + HTMX).

Browser page requests cannot carry the API Bearer header, so the dashboard authenticates via a
token-login -> httponly cookie holding the shared API token; `require_session` gates every page and
action POST. An unauthenticated request raises `_NotLoggedIn`, translated by the router's exception
handler into a 303 redirect to /dashboard/login (the page/action never executes). The action POSTs
(resolve / kill / clear) call the SAME ApprovalStore / KillSwitchStore methods the JSON API uses, so
dashboard and API never drift. Recent decisions are read directly from the AuditRecord chain via the
shared session factory. This router is NOT behind the Bearer guard — it has its own cookie gate.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.killswitch import KillSwitchStore

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_COOKIE = "agentos_session"


class _NotLoggedIn(Exception):
    """Raised by require_session when the cookie is absent/invalid; the router's handler
    translates it to a 303 redirect to /dashboard/login (the page never executes)."""


def make_require_session(api_token: str):
    def require_session(request: Request) -> bool:
        cookie = request.cookies.get(_COOKIE)
        if cookie is None or not secrets.compare_digest(cookie, api_token):
            raise _NotLoggedIn()
        return True

    return require_session


def _approval_row(row) -> dict:
    return {
        "id": str(row.id),
        "agent_id": row.agent_id,
        "action_type": row.action_type,
        "target": row.target,
        "risk_score": row.risk_score,
        "trust_score": row.trust_score,
        "status": row.status,
    }


def build_dashboard_router(
    api_token: str,
    *,
    approvals: ApprovalStore | None = None,
    kill_store: KillSwitchStore | None = None,
    inventory: InventoryStore | None = None,
    session_factory=None,
) -> APIRouter:
    router = APIRouter()
    require_session = make_require_session(api_token)

    # --- auth: cookie login + session gate ----------------------------------
    @router.get("/dashboard/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return _TEMPLATES.TemplateResponse(request, "login.html", {})

    @router.post("/dashboard/login")
    def login(token: str = Form(...)):
        if not secrets.compare_digest(token, api_token):
            return RedirectResponse("/dashboard/login?error=1", status_code=303)
        resp = RedirectResponse("/dashboard", status_code=303)
        resp.set_cookie(_COOKIE, api_token, httponly=True, samesite="strict")
        return resp

    # --- DASH-01: inventory + recent-decisions landing page (read-only) ------
    @router.get("/dashboard", response_class=HTMLResponse)
    def inventory_page(request: Request, _: bool = Depends(require_session)):
        components = inventory.list_inventory() if inventory is not None else []
        decisions = []
        if session_factory is not None:
            from sqlalchemy import select

            from agentos_controlplane.store.models import AuditRecord

            with session_factory() as s:
                rows = s.scalars(
                    select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(50)
                ).all()
            decisions = [
                {
                    "seq": r.seq,
                    "agent_id": r.body.get("agent_id"),
                    "action_type": r.body.get("action_type"),
                    "outcome": r.body.get("outcome"),
                    "kind": r.body.get("kind"),
                }
                for r in rows
            ]
        return _TEMPLATES.TemplateResponse(
            request,
            "inventory.html",
            {"components": [vars(c) for c in components], "decisions": decisions},
        )

    # --- DASH-02: list + resolve approvals ----------------------------------
    @router.get("/dashboard/approvals", response_class=HTMLResponse)
    def approvals_page(request: Request, _: bool = Depends(require_session)):
        pending = approvals.list_requests("pending") if approvals is not None else []
        return _TEMPLATES.TemplateResponse(
            request, "approvals.html", {"approvals": [_approval_row(a) for a in pending]}
        )

    @router.post("/dashboard/approvals/{approval_id}/resolve")
    async def resolve_approval(
        approval_id: str,
        _: bool = Depends(require_session),
        decision: str = Form(...),
        resolver: str = Form("operator"),
    ):
        # SAME ApprovalStore.resolve the JSON API calls (no behavior drift).
        await approvals.resolve(
            UUID(approval_id), approved=(decision == "approve"), resolver=resolver
        )
        return RedirectResponse("/dashboard/approvals", status_code=303)

    return router


def mount_dashboard(
    app: FastAPI,
    api_token: str,
    *,
    approvals: ApprovalStore | None = None,
    kill_store: KillSwitchStore | None = None,
    inventory: InventoryStore | None = None,
    session_factory=None,
) -> None:
    """Mount the dashboard router and register the _NotLoggedIn -> 303 redirect handler.

    The router is included WITHOUT the Bearer guard (it has its own cookie gate)."""
    app.include_router(
        build_dashboard_router(
            api_token,
            approvals=approvals,
            kill_store=kill_store,
            inventory=inventory,
            session_factory=session_factory,
        )
    )

    @app.exception_handler(_NotLoggedIn)
    async def _not_logged_in_handler(request: Request, exc: _NotLoggedIn):
        return RedirectResponse("/dashboard/login", status_code=303)
