"""Phase 16 — named principals, route roles and actor binding (AUTH-01..03), end to end.

The shared token remains the bootstrap admin; everything else here is what it could not do: tell
two operators apart, keep a viewer from killing agents, and stop anyone recording an action under a
name that is not theirs.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.auth import ADMIN_ROUTES, PrincipalStore, required_role
from agentos_controlplane.circuit_breaker import CircuitBreakerStore
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import ApiPrincipal, AuditRecord

BOOT = "boot-token"


@pytest.fixture
def env():
    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=__import__("sqlalchemy").pool.StaticPool)
    create_all(engine)
    sf = create_session_factory(engine)
    audit = AuditWriter(sf)
    principals = PrincipalStore(sf, audit)
    app = create_app(
        ApprovalStore(sf, audit),
        kill_store=KillSwitchStore(sf, audit),
        resource_store=ResourceStore(sf),
        breaker_store=CircuitBreakerStore(sf, audit),
        api_token=BOOT,
        principals=principals,
        dashboard=True,
        session_factory=sf,
    )
    client = TestClient(app)
    tokens = {}
    for name, role in (("vera", "viewer"), ("otto", "operator"), ("ada", "admin")):
        r = client.post("/principals", json={"name": name, "role": role}, headers=_h(BOOT))
        assert r.status_code == 201, r.text
        tokens[name] = r.json()["token"]
    return client, tokens, sf, principals, app


def _h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _events(sf, kind):
    with sf() as s:
        return [r.body for r in s.scalars(select(AuditRecord)).all() if r.body.get("kind") == kind]


# ---- roles ----


def test_viewer_reads_but_cannot_act(env) -> None:
    client, t, *_ = env
    assert client.get("/kill", headers=_h(t["vera"])).status_code == 200
    r = client.post("/kill/agents/a1", json={"set_by": "vera"}, headers=_h(t["vera"]))
    assert r.status_code == 403


def test_operator_acts_but_cannot_change_what_is_enforced(env) -> None:
    client, t, *_ = env
    assert client.post("/kill/agents/a1", json={"set_by": "otto"}, headers=_h(t["otto"])).status_code == 200
    r = client.put("/trust-profiles/a1", json={"trust_score": 0.1}, headers=_h(t["otto"]))
    assert r.status_code == 403
    assert client.post("/principals", json={"name": "x", "role": "admin"}, headers=_h(t["otto"])).status_code == 403


def test_admin_can_manage_principals_and_the_actor_is_the_admin(env) -> None:
    client, t, sf, *_ = env
    r = client.post("/principals", json={"name": "newbie", "role": "viewer"}, headers=_h(t["ada"]))
    assert r.status_code == 201
    created = [e for e in _events(sf, "principal_created") if e["name"] == "newbie"]
    assert created == [{"kind": "principal_created", "name": "newbie", "role": "viewer",
                        "set_by": "ada", "seq": created[0]["seq"], "prev_hash": created[0]["prev_hash"]}]
    assert "token" not in str(_events(sf, "principal_created"))  # never in the chain


# ---- actor binding ----


def test_a_named_principal_cannot_act_under_another_name(env) -> None:
    client, t, sf, *_ = env
    r = client.post("/kill/agents/a1", json={"set_by": "ada"}, headers=_h(t["otto"]))
    assert r.status_code == 403
    assert _events(sf, "kill_switch_set") == []  # nothing was killed under a false name


def test_the_recorded_actor_is_the_principal(env) -> None:
    client, t, sf, *_ = env
    client.post("/kill/agents/a1", json={"set_by": "otto"}, headers=_h(t["otto"]))
    assert _events(sf, "kill_switch_set")[0]["set_by"] == "otto"


def test_binding_cannot_be_bypassed_by_dropping_the_content_type(env) -> None:
    """A spoofed actor without a JSON Content-Type never executes: either the binding refuses it
    (403) or the route refuses the body (422, the pinned FastAPI) — never a kill under 'ada'."""
    client, t, sf, *_ = env
    r = client.post(
        "/kill/agents/a1",
        content=b'{"set_by": "ada"}',
        headers={**_h(t["otto"]), "content-type": ""},
    )
    assert r.status_code in (403, 422)
    assert _events(sf, "kill_switch_set") == []


def test_every_actor_field_is_bound(env) -> None:
    client, t, *_ = env
    cases = [
        ("post", "/approvals/00000000-0000-0000-0000-000000000000/resolve",
         {"approved": True, "resolver": "someone"}),
        ("post", "/circuit/reset", {"scope": "agent", "agent_id": "a", "set_by": "someone"}),
    ]
    for method, path, body in cases:
        r = getattr(client, method)(path, json=body, headers=_h(t["otto"]))
        assert r.status_code == 403, (path, r.status_code, r.text)


def test_the_bootstrap_token_keeps_its_legacy_unverified_actor(env) -> None:
    client, _, sf, *_ = env
    client.post("/kill/agents/a1", json={"set_by": "legacy-ops"}, headers=_h(BOOT))
    assert _events(sf, "kill_switch_set")[0]["set_by"] == "legacy-ops"


# ---- credentials ----


def test_a_revoked_principal_is_refused_immediately_on_every_instance(env) -> None:
    client, t, sf, principals, _ = env
    other = TestClient(create_app(ApprovalStore(sf, AuditWriter(sf)), api_token=BOOT,
                                  principals=PrincipalStore(sf, AuditWriter(sf))))
    assert other.get("/approvals", headers=_h(t["vera"])).status_code == 200
    assert client.post("/principals/vera/revoke", headers=_h(t["ada"])).status_code == 200
    assert client.get("/approvals", headers=_h(t["vera"])).status_code == 401
    assert other.get("/approvals", headers=_h(t["vera"])).status_code == 401  # no cache anywhere


@pytest.mark.parametrize(
    "bad",
    ["", "agp_", "agp_nothex_secret", "agp_" + "0" * 32 + "_wrong", "Bearer", "é" * 40, "x" * 5000],
)
def test_malformed_or_wrong_credentials_are_a_clean_401(env, bad) -> None:
    client, t, *_ = env
    # Raw bytes: a hostile client sends whatever octets it likes; the server must answer 401.
    raw = {"Authorization": ("Bearer " + bad).encode("utf-8")}
    assert client.get("/approvals", headers=raw).status_code == 401
    real_id = t["vera"].split("_")[1]
    forged = f"agp_{real_id}_notthesecret"
    assert client.get("/approvals", headers=_h(forged)).status_code == 401


def test_only_the_secret_hash_is_stored(env) -> None:
    _, t, sf, *_ = env
    secret = t["vera"].split("_", 2)[2]
    with sf() as s:
        row = s.scalar(select(ApiPrincipal).where(ApiPrincipal.name == "vera"))
    assert secret not in row.token_hash and len(row.token_hash) == 64


@pytest.mark.parametrize("name,status", [("bootstrap", 422), ("has space", 422), ("vera", 409), ("", 422)])
def test_principal_names_are_validated(env, name, status) -> None:
    client, t, *_ = env
    r = client.post("/principals", json={"name": name, "role": "viewer"}, headers=_h(t["ada"]))
    assert r.status_code == status


def test_listing_never_returns_tokens(env) -> None:
    client, t, *_ = env
    listed = client.get("/principals", headers=_h(t["ada"])).json()
    assert {p["name"] for p in listed} == {"vera", "otto", "ada"}
    assert all("token" not in p and "token_hash" not in p for p in listed)


# ---- the role table itself ----


def test_every_admin_route_entry_names_a_real_route(env) -> None:
    """A typo in ADMIN_ROUTES would silently downgrade that route to operator."""
    *_, app = env
    from agentos_controlplane.api import create_app as _ca  # noqa: F401  (all routers mounted below)

    real = {(m, r.path) for r in app.routes for m in getattr(r, "methods", ())}
    missing = {entry for entry in ADMIN_ROUTES if entry not in real}
    # Routes whose routers this fixture does not mount (they need other stores) are checked by
    # name against the api module's source instead, so a typo there is caught too.
    import inspect

    import agentos_controlplane.api as api

    src = inspect.getsource(api)
    assert all(f'"{path}"' in src for _, path in missing), missing


def test_required_role_defaults() -> None:
    assert required_role("GET", "/anything") == "viewer"
    assert required_role("POST", "/anything") == "operator"
    assert required_role("DELETE", "/anything") == "operator"
    assert required_role("PUT", "/trust-profiles/{agent_id}") == "admin"
    assert required_role("get", "/compliance/export/{framework}") == "admin"


# ---- dashboard ----


def _login(client, token):
    r = client.post("/dashboard/login", data={"token": token}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"


def test_dashboard_viewer_sees_pages_but_cannot_kill(env) -> None:
    client, t, sf, *_ = env
    _login(client, t["vera"])
    assert client.get("/dashboard/kill").status_code == 200
    r = client.post("/dashboard/kill/agent", data={"agent_id": "a1"}, follow_redirects=False)
    assert r.status_code == 403
    assert _events(sf, "kill_switch_set") == []


def test_dashboard_operator_action_is_recorded_under_the_principal(env) -> None:
    client, t, sf, *_ = env
    _login(client, t["otto"])
    client.post("/dashboard/kill/agent", data={"agent_id": "a1", "set_by": "operator"},
                follow_redirects=False)
    assert _events(sf, "kill_switch_set")[0]["set_by"] == "otto"


def test_dashboard_refuses_a_revoked_principals_cookie(env) -> None:
    client, t, *_ = env
    _login(client, t["otto"])
    TestClient(client.app).post("/principals/otto/revoke", headers=_h(t["ada"]))
    r = client.get("/dashboard/kill", follow_redirects=False)
    assert r.status_code == 303 and "/dashboard/login" in r.headers["location"]
