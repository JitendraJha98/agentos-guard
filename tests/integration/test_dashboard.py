"""DASH-01/02/03 — minimal server-rendered operator dashboard (Jinja2 + HTMX).

The dashboard has its OWN cookie-login gate (httponly cookie holding the shared API token,
compare_digest) DISTINCT from the Bearer API guard: a browser cannot send the Bearer header on a
page nav, so an unauthenticated page OR action POST must redirect to /dashboard/login and must NOT
execute. The action POSTs (resolve / kill / clear) call the SAME ApprovalStore / KillSwitchStore
methods the JSON API uses — so dashboard and API never drift.
"""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.engine import create_all, create_session_factory

_COOKIE = "agentos_session"


def _sf():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def _dashboard_app(sf, *, token="test-token", **kw):
    return create_app(
        ApprovalStore(sf, AuditWriter(sf)),
        inventory_store=InventoryStore(sf),
        session_factory=sf,
        api_token=token,
        dashboard=True,
        **kw,
    )


# --- Task 1: auth (cookie login + session gate) ---------------------------------


def test_dashboard_page_without_cookie_redirects_to_login():
    from fastapi.testclient import TestClient

    client = TestClient(_dashboard_app(_sf()), follow_redirects=False)
    resp = client.get("/dashboard")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"


def test_login_form_renders_token_field():
    from fastapi.testclient import TestClient

    client = TestClient(_dashboard_app(_sf()))
    resp = client.get("/dashboard/login")
    assert resp.status_code == 200
    assert 'name="token"' in resp.text


def test_login_with_correct_token_sets_httponly_cookie_and_redirects():
    from fastapi.testclient import TestClient

    client = TestClient(_dashboard_app(_sf()), follow_redirects=False)
    resp = client.post("/dashboard/login", data={"token": "test-token"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard"
    set_cookie = resp.headers["set-cookie"]
    assert _COOKIE in set_cookie
    assert "httponly" in set_cookie.lower()


def test_login_with_wrong_token_does_not_authenticate():
    from fastapi.testclient import TestClient

    client = TestClient(_dashboard_app(_sf()), follow_redirects=False)
    resp = client.post("/dashboard/login", data={"token": "wrong"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login?error=1"
    # No valid session cookie was set, so the dashboard still redirects.
    assert client.get("/dashboard").status_code == 303


def test_logged_in_client_reaches_dashboard():
    from fastapi.testclient import TestClient

    client = TestClient(_dashboard_app(_sf()))  # follow redirects: login -> dashboard
    client.post("/dashboard/login", data={"token": "test-token"})
    resp = client.get("/dashboard")
    assert resp.status_code == 200


def test_dashboard_off_by_default_no_login_route():
    from fastapi.testclient import TestClient

    sf = _sf()
    app = create_app(ApprovalStore(sf, AuditWriter(sf)), api_token="test-token")
    client = TestClient(app)
    # Backward compat: the dashboard router is not mounted -> 404 (not 401/303).
    assert client.get("/dashboard/login").status_code == 404


# --- Task 2: inventory + recent-decisions view (DASH-01) ------------------------


def _login(client):
    client.post("/dashboard/login", data={"token": "test-token"})


def test_dashboard_renders_inventory_and_recent_decisions():
    import asyncio

    from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
    from fastapi.testclient import TestClient

    sf = _sf()
    # Seed a declared inventory component and a real decision audit record.
    InventoryStore(sf).declare("agent-a", tools=["http_get"])
    audit = AuditWriter(sf)
    action = AgentAction(
        agent_id="agent-a",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/data", "content": ""},
    )
    decision = Decision(
        action_id=action.id,
        outcome=Outcome.allow,
        risk_score=0.1,
        trust_score=0.5,
        reasons=[Reason(stage="policy", code="no_match_allow")],
    )
    asyncio.run(audit.append(action, decision))

    app = create_app(
        ApprovalStore(sf, audit),
        inventory_store=InventoryStore(sf),
        session_factory=sf,
        api_token="test-token",
        dashboard=True,
    )
    client = TestClient(app)
    _login(client)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    # DASH-01: the declared component and the recent decision's outcome both render.
    assert "http_get" in resp.text
    assert "agent-a" in resp.text
    assert "allow" in resp.text


# --- Task 3: approvals view + resolve action (DASH-02) --------------------------


def _park_approval(approvals):
    import asyncio

    from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason

    action = AgentAction(
        agent_id="agent-a",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/data", "content": ""},
    )
    decision = Decision(
        action_id=action.id,
        outcome=Outcome.require_approval,
        risk_score=0.2,
        trust_score=0.5,
        reasons=[Reason(stage="policy", code="constitution_principle_fired", principle_ref="1.1")],
    )
    # ApprovalStore.create is sync; deadline far out so it stays pending.
    return approvals.create(action, decision, deadline_s=3600)


def test_dashboard_lists_pending_approval():
    from fastapi.testclient import TestClient

    sf = _sf()
    approvals = ApprovalStore(sf, AuditWriter(sf))
    approval_id = _park_approval(approvals)
    app = create_app(approvals, session_factory=sf, api_token="test-token", dashboard=True)
    client = TestClient(app)
    _login(client)
    resp = client.get("/dashboard/approvals")
    assert resp.status_code == 200
    assert str(approval_id) in resp.text
    assert "agent-a" in resp.text


def test_dashboard_resolve_approval_flips_the_row():
    from fastapi.testclient import TestClient

    sf = _sf()
    approvals = ApprovalStore(sf, AuditWriter(sf))
    approval_id = _park_approval(approvals)
    app = create_app(approvals, session_factory=sf, api_token="test-token", dashboard=True)
    client = TestClient(app, follow_redirects=False)
    _login(client)
    resp = client.post(
        f"/dashboard/approvals/{approval_id}/resolve", data={"decision": "approve"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/approvals"
    # The SAME ApprovalStore the JSON API uses now reports the row as approved.
    approved = [r.id for r in approvals.list_requests("approved")]
    assert approval_id in approved


def test_unauthenticated_resolve_redirects_and_does_not_resolve():
    from fastapi.testclient import TestClient

    sf = _sf()
    approvals = ApprovalStore(sf, AuditWriter(sf))
    approval_id = _park_approval(approvals)
    app = create_app(approvals, session_factory=sf, api_token="test-token", dashboard=True)
    client = TestClient(app, follow_redirects=False)  # NO login
    resp = client.post(
        f"/dashboard/approvals/{approval_id}/resolve", data={"decision": "approve"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"
    # The action did NOT execute: the row is still pending.
    pending = [r.id for r in approvals.list_requests("pending")]
    assert approval_id in pending


# --- Task 4: kill-switch view + actions (DASH-03) ------------------------------


def _kill_app(sf, *, token="test-token"):
    from agentos_controlplane.killswitch import KillSwitchStore

    audit = AuditWriter(sf)
    kill_store = KillSwitchStore(sf, audit)
    app = create_app(
        ApprovalStore(sf, audit),
        kill_store=kill_store,
        session_factory=sf,
        api_token=token,
        dashboard=True,
    )
    return app, kill_store


def test_dashboard_kill_agent_flips_killswitch_and_lists_it():
    from fastapi.testclient import TestClient

    sf = _sf()
    app, kill_store = _kill_app(sf)
    client = TestClient(app, follow_redirects=False)
    _login(client)
    resp = client.post("/dashboard/kill/agent", data={"agent_id": "a", "reason": "rogue"})
    assert resp.status_code == 303
    status = kill_store.status("a")
    assert status is not None and status.scope == "agent"
    # The active kill renders on the page.
    page = client.get("/dashboard/kill")
    assert page.status_code == 200
    assert "a" in page.text


def test_dashboard_clear_agent_unkills():
    import asyncio

    from fastapi.testclient import TestClient

    sf = _sf()
    app, kill_store = _kill_app(sf)
    asyncio.run(kill_store.kill("a", set_by="op", reason="rogue"))
    client = TestClient(app, follow_redirects=False)
    _login(client)
    resp = client.post("/dashboard/kill/agent/clear", data={"agent_id": "a"})
    assert resp.status_code == 303
    assert kill_store.status("a") is None


def test_dashboard_fleet_kill_kills_a_different_agent():
    from fastapi.testclient import TestClient

    sf = _sf()
    app, kill_store = _kill_app(sf)
    client = TestClient(app, follow_redirects=False)
    _login(client)
    resp = client.post("/dashboard/kill/fleet", data={"reason": "incident"})
    assert resp.status_code == 303
    status = kill_store.status("any-agent")
    assert status is not None and status.scope == "fleet"
    cleared = client.post("/dashboard/kill/fleet/clear", data={})
    assert cleared.status_code == 303
    assert kill_store.status("any-agent") is None


def test_unauthenticated_kill_redirects_and_does_not_kill():
    from fastapi.testclient import TestClient

    sf = _sf()
    app, kill_store = _kill_app(sf)
    client = TestClient(app, follow_redirects=False)  # NO login
    resp = client.post("/dashboard/kill/agent", data={"agent_id": "a", "reason": "rogue"})
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"
    # The action did NOT execute: the agent is not killed.
    assert kill_store.status("a") is None
