"""SDK ControlPlaneClient against the LIVE app via httpx.ASGITransport — no network/server (SDK-02/04).

The client is pure HTTP (httpx): it carries the shared token as a Bearer header, self-registers an
agent (returning its identity token + declaring its manifest into the inventory), lists/resolves
approvals, does resource CRUD (surfacing a stale-version 409 as ControlPlaneError), applies a
constitution + reads the compiled policy, and reads the inventory. A wrong token -> ControlPlaneError
(401). The SDK client must NOT import agentos_controlplane / agentos_pipeline (no PDP/PEP coupling).
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
import yaml
from starlette.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_sdk import ControlPlaneClient, ControlPlaneError

TOKEN = "test-token"
_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "test_constitution.yaml"


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def app(store):
    inv = InventoryStore(store)
    return create_app(
        ApprovalStore(store, AuditWriter(store)),
        resource_store=ResourceStore(store),
        inventory_store=inv,
        registry=Registry(store, inventory=inv),
        api_token=TOKEN,
    )


def _sync_asgi_transport(app) -> httpx.BaseTransport:
    """A SYNC in-process transport bound to the ASGI `app` (no network/server). httpx.ASGITransport
    is async-only, so a sync httpx.Client cannot drive it directly; Starlette's TestClient builds a
    sync transport that bridges to the ASGI app through an anyio portal thread — we reuse exactly
    that transport to drive the SYNC ControlPlaneClient in-process."""
    return TestClient(app)._transport


@pytest.fixture
def client(app) -> ControlPlaneClient:
    return ControlPlaneClient("http://test", TOKEN, transport=_sync_asgi_transport(app))


@pytest.fixture
def src() -> dict:
    return yaml.safe_load(_FIXTURE.read_text(encoding="utf-8"))


# ---- decoupling guard: pure HTTP, no PDP/PEP import ----
def test_client_module_has_no_controlplane_or_pipeline_import() -> None:
    mod = importlib.import_module("agentos_sdk.client")
    src_text = inspect.getsource(mod)
    assert "agentos_controlplane" not in src_text
    assert "agentos_pipeline" not in src_text


# ---- SDK-02 self-registration ----
def test_register_returns_token_and_persists(client, store) -> None:
    token = client.register("a", manifest={"tools": ["http_get"]})
    assert token  # non-empty identity token
    assert Registry(store).is_registered("a") is True


def test_register_with_wrong_token_raises_401(app, store) -> None:
    bad = ControlPlaneClient("http://test", "nope", transport=_sync_asgi_transport(app))
    with pytest.raises(ControlPlaneError):
        bad.register("a")


# ---- approvals (SDK-04) ----
def _park_approval(store) -> str:
    """Park a pending ApprovalRequest directly in the store; return its id."""
    approvals = ApprovalStore(store, AuditWriter(store))
    action = AgentAction(
        agent_id="a", type=ActionType.tool_call, target="drop_table",
        payload={"url": "https://api.example.com/x", "content": ""},
    )
    decision = Decision(
        action_id=action.id,
        outcome=Outcome.require_approval,
        reasons=[Reason(stage="policy", code="constitution_principle_fired", principle_ref="2.1")],
    )
    return str(approvals.create(action, decision, deadline_s=60))


def test_list_and_resolve_approval(client, store) -> None:
    approval_id = _park_approval(store)
    listed = client.list_approvals()
    assert any(a["id"] == approval_id for a in listed)
    assert client.list_approvals(status="pending")

    resolved = client.resolve_approval(approval_id, approved=True, resolver="op")
    assert resolved["status"] == "approved"
    assert resolved["resolver"] == "op"
    # second resolve of the now-terminal row -> 409 surfaced as ControlPlaneError
    with pytest.raises(ControlPlaneError):
        client.resolve_approval(approval_id, approved=True, resolver="op")


def test_resolve_unknown_approval_raises(client) -> None:
    with pytest.raises(ControlPlaneError):
        client.resolve_approval(str(uuid4()), approved=True, resolver="op")


# ---- resources (SDK-04) ----
def test_trust_profile_crud_and_version_conflict(client) -> None:
    d = client.put_trust_profile("a", trust_score=0.7)
    assert d["version"] == 1 and d["trust_score"] == 0.7

    d = client.put_trust_profile("a", trust_score=0.8, version=1)
    assert d["version"] == 2

    # stale version -> 409 surfaced as ControlPlaneError
    with pytest.raises(ControlPlaneError):
        client.put_trust_profile("a", trust_score=0.9, version=1)

    assert client.get_trust_profile("a")["version"] == 2
    assert any(p["agent_id"] == "a" for p in client.list_trust_profiles())


def test_abom_put(client) -> None:
    d = client.put_abom("a", components={"tools": ["http_get"]})
    assert d["version"] == 1
    d = client.put_abom("a", components={"tools": ["drop_table"]}, version=1)
    assert d["version"] == 2


def test_apply_constitution_then_get_latest_policy(client, src) -> None:
    applied = client.apply_constitution("t", src)
    version = applied["policy_version"]
    assert version
    policy = client.get_latest_policy()
    assert "package agentos.constitution" in policy["rego"]
    assert policy["constitution_version"] == version


def test_inventory_reads_after_register(client) -> None:
    client.register("a", manifest={"tools": ["http_get"], "memories": ["m1"]})
    all_rows = client.list_inventory()
    assert {(d["kind"], d["name"]) for d in all_rows if d["agent_id"] == "a"} == {
        ("tool", "http_get"),
        ("memory", "m1"),
    }
    agent_rows = client.get_inventory("a")
    assert {d["name"] for d in agent_rows} == {"http_get", "m1"}
