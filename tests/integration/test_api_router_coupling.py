"""Router-coupling coverage — a supplied store that serves nothing is never silent.

Twelve read surfaces (discovery, graph, disclosure, economics, validation, health,
forensics, conflicts, amendments) all ride the ONE inventory router, which mounts only
when `inventory_store` is supplied. So `create_app(..., graph_store=g)` without an
inventory store answers 404 on the very route `g` was passed for — a composition mistake
that looks exactly like a working control plane until someone calls it.

Passing nothing dependent stays silent on purpose: a deliberately minimal control plane
is a valid composition, not a mistake, and warning about it would train operators to
filter the logger that carries the real warning.
"""
from __future__ import annotations

import logging

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.graph import AgentGraphStore
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory

TOKEN = "coupling-token"
LOGGER = "agentos_controlplane.api"


def _parts():
    # StaticPool + check_same_thread: TestClient serves the request on another thread, and a
    # fresh connection to ":memory:" is a fresh EMPTY database — the table would vanish.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    store = create_session_factory(engine)
    inventory = InventoryStore(store)
    registry = Registry(store, inventory=inventory)
    audit = AuditWriter(store, signer=registry.identity)
    return store, inventory, audit


def test_a_dependent_store_without_an_inventory_store_warns_and_names_it(caplog) -> None:
    store, inventory, audit = _parts()
    graph = AgentGraphStore(store, inventory=inventory)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        create_app(ApprovalStore(store, audit), api_token=TOKEN, graph_store=graph)
    assert "graph_store" in caplog.text and "404" in caplog.text


def test_the_warning_is_true_the_route_really_is_absent() -> None:
    # The warning has to describe reality, or it is just noise: assert the 404 it predicts.
    store, inventory, audit = _parts()
    graph = AgentGraphStore(store, inventory=inventory)
    app = create_app(ApprovalStore(store, audit), api_token=TOKEN, graph_store=graph)
    resp = TestClient(app).get(
        "/discovery/graph", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert resp.status_code == 404


def test_a_deliberately_minimal_app_warns_about_nothing(caplog) -> None:
    store, _inventory, audit = _parts()
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        create_app(ApprovalStore(store, audit), api_token=TOKEN)
    assert "inventory_store" not in caplog.text


def test_wiring_the_inventory_store_silences_the_warning_and_serves_the_route(caplog) -> None:
    store, inventory, audit = _parts()
    graph = AgentGraphStore(store, inventory=inventory)
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        app = create_app(
            ApprovalStore(store, audit),
            api_token=TOKEN,
            inventory_store=inventory,
            graph_store=graph,
        )
    assert "graph_store" not in caplog.text
    resp = TestClient(app).get(
        "/discovery/graph", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    assert resp.status_code == 200
