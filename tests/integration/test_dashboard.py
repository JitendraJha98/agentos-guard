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
