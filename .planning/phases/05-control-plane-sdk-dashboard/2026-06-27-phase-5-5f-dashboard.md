# Phase 5 · Slice 5f — Minimal Operator Dashboard (DASH-01/02/03) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) green at every commit.

**Goal (DASH-01/02/03):** A minimal, server-rendered operator dashboard: read-only **agent inventory
+ recent decisions/audit** (DASH-01); **resolve pending approvals** (DASH-02); **trigger agent/fleet
kill switches** (DASH-03). Server-rendered Jinja2 + HTMX, mounted on the same FastAPI app — no SPA, no
Node toolchain (per `STACK.md`).

**Architecture:** A `build_dashboard_router(...)` returns a router serving HTML pages from Jinja2
templates shipped as package data. Because browser page requests cannot carry the API Bearer header,
the dashboard authenticates via a **token-login → httponly cookie**: the operator submits the shared
`AGENTOS_API_TOKEN`, the cookie is set, and a `require_session` dependency gates the dashboard pages
(redirect to login if absent/invalid). The dashboard's action POSTs (resolve / kill / clear) call the
SAME `ApprovalStore` / `KillSwitchStore` methods the JSON API uses, so behavior never diverges. Recent
decisions are read directly from `AuditRecord` via the session factory.

**Tech Stack:** FastAPI + `fastapi.templating.Jinja2Templates`, `jinja2` (new controlplane dep),
HTMX (CDN script tag, no build), pytest + `fastapi.testclient`.

> First commit in this slice: `docs(phase-5): Slice 5f plan` for this file, then the tasks below.

## File structure
- Create `.../agentos_controlplane/dashboard.py` — `require_session`, `build_dashboard_router(...)`,
  `mount_dashboard(app, ...)`.
- Create `.../agentos_controlplane/templates/*.html` — `base.html`, `login.html`, `inventory.html`,
  `approvals.html`, `kill.html` (shipped as package data).
- Modify `.../agentos_controlplane/api.py` — `create_app(..., session_factory=None, dashboard=False)`.
- Modify `packages/controlplane/pyproject.toml` — add `jinja2>=3.1`.
- Tests: `tests/integration/test_dashboard.py`.

---

### Task 1: Jinja2 setup + cookie login + session gate (auth)

**Files:**
- Create: `.../agentos_controlplane/dashboard.py`, `.../templates/base.html`, `.../templates/login.html`
- Modify: `.../api.py`, `packages/controlplane/pyproject.toml`
- Test: `tests/integration/test_dashboard.py`

`dashboard.py` (auth + login; the data routes land in later tasks on the same router):

```python
"""DASH-01/02/03 — minimal server-rendered operator dashboard (Jinja2 + HTMX). Browser pages cannot
send the API Bearer header, so the dashboard authenticates via a token-login -> httponly cookie
holding the shared API token; require_session gates every page. Action POSTs call the SAME stores as
the JSON API (no behavior drift)."""
from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

_TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
_COOKIE = "agentos_session"


def make_require_session(api_token: str):
    def require_session(request: Request) -> bool:
        cookie = request.cookies.get(_COOKIE)
        if cookie is None or not secrets.compare_digest(cookie, api_token):
            # Signal the caller to redirect; raised as a sentinel the routes translate to a 303.
            raise _NotLoggedIn()
        return True
    return require_session


class _NotLoggedIn(Exception):
    pass
```

`build_dashboard_router(api_token, *, approvals, kill_store, inventory, session_factory)` creates the
router; register an exception handler (or per-route try) translating `_NotLoggedIn` →
`RedirectResponse("/dashboard/login", status_code=303)`. Login routes:

```python
    @router.get("/dashboard/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return _TEMPLATES.TemplateResponse(request, "login.html", {})

    @router.post("/dashboard/login")
    def login(token: str = Form(...)):
        if not secrets.compare_digest(token, api_token):
            resp = RedirectResponse("/dashboard/login?error=1", status_code=303)
            return resp
        resp = RedirectResponse("/dashboard", status_code=303)
        resp.set_cookie(_COOKIE, api_token, httponly=True, samesite="strict")
        return resp
```

`api.py`: `create_app(store, kill_store=None, resource_store=None, inventory_store=None,
session_factory=None, registry=None, api_token=None, dashboard=False)`. When `dashboard` is True,
`app.include_router(build_dashboard_router(token, approvals=store, kill_store=kill_store,
inventory=inventory_store, session_factory=session_factory))` and register the `_NotLoggedIn`
handler. (The dashboard router is NOT behind the Bearer `guard` — it has its own cookie gate. Keep all
existing callers working — `dashboard` defaults False.) Add `jinja2>=3.1` to controlplane deps.

`base.html` (minimal; HTMX from CDN):
```html
<!doctype html><html><head><title>agentos-guard</title>
<script src="https://unpkg.com/htmx.org@2"></script></head>
<body><h1>agentos-guard</h1>
<nav><a href="/dashboard">inventory</a> | <a href="/dashboard/approvals">approvals</a> |
<a href="/dashboard/kill">kill switch</a></nav><hr>{% block body %}{% endblock %}</body></html>
```
`login.html`: a `<form method="post" action="/dashboard/login">` with a password input named `token`
and a submit button; show an error note when `request.query_params.get("error")`.

**Steps (TDD):**
- [ ] Failing test: app = `create_app(ApprovalStore(sf, AuditWriter(sf)), inventory_store=InventoryStore(sf),
  session_factory=sf, api_token="test-token", dashboard=True)`; `TestClient(app)`. GET `/dashboard`
  with no cookie → redirects (303) to `/dashboard/login`; GET `/dashboard/login` → 200 with a token
  field; POST `/dashboard/login` `data={"token":"test-token"}` → 303 to `/dashboard` and sets the
  `agentos_session` cookie; POST with a wrong token → back to login (no valid cookie). `create_app`
  without `dashboard=True` → GET `/dashboard/login` → 404 (backward compat). Run → fails.
- [ ] Implement auth + login + templates + create_app wiring + dep. Run → passes.
- [ ] Commit `feat(controlplane): dashboard cookie-login + session gate (DASH P0)`.

---

### Task 2: inventory + recent-decisions view (DASH-01)

**Files:**
- Modify: `.../dashboard.py`; Create: `.../templates/inventory.html`
- Test: `tests/integration/test_dashboard.py`

Add the read-only landing page (gated by `require_session`):

```python
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
                {"seq": r.seq, "agent_id": r.body.get("agent_id"),
                 "action_type": r.body.get("action_type"), "outcome": r.body.get("outcome"),
                 "kind": r.body.get("kind")}
                for r in rows
            ]
        return _TEMPLATES.TemplateResponse(
            request, "inventory.html",
            {"components": [vars(c) for c in components], "decisions": decisions},
        )
```

`inventory.html` (extends base): a table of components (`agent_id`, `kind`, `name`, `source`,
`last_seen_at`) and a table of recent decisions (`seq`, `agent_id`, `action_type`, `outcome`/`kind`).
Read-only — no action buttons.

**Steps (TDD):**
- [ ] Failing test: log in (POST login → cookie on the client). Declare some inventory rows and append
  a couple of decision audit records (via `AuditWriter` + a `Decision`, or a pipeline `evaluate`).
  GET `/dashboard` → 200; the HTML contains a declared component name (e.g. `http_get`) and a recent
  decision outcome (`allow`/`deny`). Run → fails.
- [ ] Implement the route + template. Run → passes.
- [ ] Commit `feat(controlplane): dashboard inventory + recent-decisions view (DASH-01)`.

---

### Task 3: approvals view + resolve action (DASH-02)

**Files:**
- Modify: `.../dashboard.py`; Create: `.../templates/approvals.html`
- Test: `tests/integration/test_dashboard.py`

```python
    @router.get("/dashboard/approvals", response_class=HTMLResponse)
    def approvals_page(request: Request, _: bool = Depends(require_session)):
        pending = approvals.list_requests("pending") if approvals is not None else []
        return _TEMPLATES.TemplateResponse(
            request, "approvals.html", {"approvals": [_row(a) for a in pending]})

    @router.post("/dashboard/approvals/{approval_id}/resolve")
    async def resolve(approval_id: str, request: Request, _: bool = Depends(require_session),
                      decision: str = Form(...), resolver: str = Form("operator")):
        from uuid import UUID
        await approvals.resolve(UUID(approval_id), approved=(decision == "approve"), resolver=resolver)
        return RedirectResponse("/dashboard/approvals", status_code=303)
```

(`_row(a)` maps the `ApprovalRequest` to the fields the template shows — reuse the existing
`_approval_json` in `api.py` by importing it, or a small local mapper.) `approvals.html`: a table of
pending requests, each row with an Approve and a Deny `<form method="post"
action="/dashboard/approvals/{id}/resolve">` (hidden `decision` field) — HTMX or plain form POST.

**Steps (TDD):**
- [ ] Failing test: park an `ApprovalRequest` (via `ApprovalStore`); log in; GET `/dashboard/approvals`
  → 200 listing it; POST `/dashboard/approvals/{id}/resolve` `data={"decision":"approve"}` → 303 and
  the underlying request is now `approved` (assert via `store.list_requests("approved")` or the row);
  unauthenticated POST → redirect to login (not resolved). Run → fails.
- [ ] Implement. Run → passes.
- [ ] Commit `feat(controlplane): dashboard approvals view + resolve action (DASH-02)`.

---

### Task 4: kill-switch view + actions (DASH-03)

**Files:**
- Modify: `.../dashboard.py`; Create: `.../templates/kill.html`
- Test: `tests/integration/test_dashboard.py`

```python
    @router.get("/dashboard/kill", response_class=HTMLResponse)
    def kill_page(request: Request, _: bool = Depends(require_session)):
        active = kill_store.list_active() if kill_store is not None else []
        return _TEMPLATES.TemplateResponse(request, "kill.html", {"active": active})

    @router.post("/dashboard/kill/agent")
    async def kill_agent(request: Request, _: bool = Depends(require_session),
                         agent_id: str = Form(...), reason: str = Form(""), set_by: str = Form("operator")):
        await kill_store.kill(agent_id, set_by=set_by, reason=reason)
        return RedirectResponse("/dashboard/kill", status_code=303)

    @router.post("/dashboard/kill/agent/clear")
    async def clear_agent(request: Request, _: bool = Depends(require_session),
                          agent_id: str = Form(...), set_by: str = Form("operator")):
        await kill_store.clear(agent_id, set_by=set_by)
        return RedirectResponse("/dashboard/kill", status_code=303)

    @router.post("/dashboard/kill/fleet")
    async def kill_fleet(request: Request, _: bool = Depends(require_session),
                         reason: str = Form(""), set_by: str = Form("operator")):
        await kill_store.kill_fleet(set_by=set_by, reason=reason)
        return RedirectResponse("/dashboard/kill", status_code=303)

    @router.post("/dashboard/kill/fleet/clear")
    async def clear_fleet(request: Request, _: bool = Depends(require_session), set_by: str = Form("operator")):
        await kill_store.clear_fleet(set_by=set_by)
        return RedirectResponse("/dashboard/kill", status_code=303)
```

`kill.html`: the list of active kills (target/scope/reason) + a kill-agent form (agent_id + reason),
a clear-agent form, and fleet kill / fleet clear buttons.

**Steps (TDD):**
- [ ] Failing test: log in; POST `/dashboard/kill/agent` `data={"agent_id":"a","reason":"rogue"}` →
  303 and `kill_store.status("a")` is killed (`scope=="agent"`); GET `/dashboard/kill` → 200 listing
  `a`; POST `/dashboard/kill/agent/clear` `data={"agent_id":"a"}` → cleared; POST
  `/dashboard/kill/fleet` → a different agent is killed (`fleet`); unauthenticated POST → redirect, no
  kill. Run → fails.
- [ ] Implement. Run → passes.
- [ ] Commit `feat(controlplane): dashboard kill-switch view + actions (DASH-03)`.

---

### Task 5: full gate + e2e
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy.
- [ ] An e2e in `test_dashboard.py`: build an app sharing the SAME `KillSwitchStore` instance with a
  real `Pipeline` (mirror `test_kill_switch_api.py`); a dashboard kill POST → that agent is then
  denied by `pipeline.evaluate` (`agent_killed`); a dashboard clear → allowed again. (Closes the loop:
  the dashboard action really halts the agent.)
- [ ] Confirm the templates ship in the wheel (`uv build --wheel`; the `templates/*.html` appear under
  `agentos_controlplane/`); add `force-include` only if missing.
- [ ] Commit only if incidental fixes were needed.

## Self-review
DASH-01: read-only inventory + recent decisions; DASH-02: list + resolve approvals (same
`ApprovalStore.resolve` as the API); DASH-03: agent + fleet kill/clear (same `KillSwitchStore`),
proven by the e2e that a dashboard kill denies the agent in the pipeline. Server-rendered Jinja2 +
HTMX, no SPA. Cookie-login gate (httponly, compare_digest) distinct from the API Bearer gate; an
unauthenticated page/action redirects to login (never executes). `create_app(dashboard=False)` default
keeps every existing caller working; templates ship as package data; `jinja2` added. Gates green; hot
path untouched.
