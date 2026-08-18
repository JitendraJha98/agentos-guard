"""DISC-04 e2e — shadow-agent detection over the REAL governed stack (Slice 10d).

The full stack on ONE shared store: the real registry + identity stage, the real compiled
constitution, the real audit chain, and the real `ShadowAgentStore` wired into both the pipeline
and the API. That sharing is the point — the unit tests prove the store's rules, and this proves
the two halves are actually the same store, so what the pipeline saw is what an operator can read.

What DISC-04 delivers: an unregistered actor is denied exactly as it always was (IDN-02), and is
now also VISIBLE. The assertions below pin both halves — the deny is unchanged, the sighting
appears with a live attempt counter, a registered agent never shows up in it, and a flood from one
claimed id still appends exactly one chain entry.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.shadow import ShadowAgentStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
AGENT_ID = "registered-agent"
GHOST_ID = "ghost-agent"
ALLOWED_URL = "https://api.example.com/data"  # in the test constitution's egress_allowlist


class _Stack:
    """The pipeline and the app over ONE store and ONE ShadowAgentStore instance."""

    def __init__(self, constitution_wasm, *, wire_shadow: bool = True) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        # ONE AuditWriter per store (the chain-head cache): the pipeline and the shadow store
        # share the same appender rather than opening a second one.
        audit = AuditWriter(self.store, signer=registry.identity)
        self.shadow = ShadowAgentStore(self.store, audit) if wire_shadow else None
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(constitution_wasm.wasm_path),
                lists=constitution_wasm.bundle.lists,
                constitution_version=constitution_wasm.bundle.constitution_version,
                principles_meta=constitution_wasm.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=audit,
            shadow=self.shadow,
        )
        inventory = InventoryStore(self.store)
        inventory.declare(AGENT_ID, tools=["http_get"])
        self.app = create_app(
            ApprovalStore(self.store, audit),
            inventory_store=inventory,
            api_token=TOKEN,
            shadow_store=self.shadow,
        )
        self.client = TestClient(self.app)
        self.client.headers.update(AUTH)

    def act(self, *, agent_id: str, token: str | None):
        return asyncio.run(
            self.pipeline.evaluate(
                AgentAction(
                    agent_id=agent_id,
                    type=ActionType.tool_call,
                    target="http_get",
                    payload={"url": ALLOWED_URL},
                    identity_token=token,
                )
            )
        )

    def sightings(self) -> list[dict]:
        r = self.client.get("/discovery/shadow-agents")
        assert r.status_code == 200, r.text
        return r.json()

    def shadow_events(self) -> list[dict]:
        with self.store() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()
            return [r.body for r in rows if r.body.get("kind") == "shadow_agent_detected"]


@pytest.fixture
def stack(constitution_wasm) -> _Stack:
    return _Stack(constitution_wasm)


def test_unregistered_actor_is_denied_and_becomes_visible(stack) -> None:
    """Both halves of DISC-04 in one assertion set: the deny is what it always was, and the probe
    is no longer lost among routine denies."""
    assert stack.sightings() == []

    decision = stack.act(agent_id=GHOST_ID, token=None)

    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    rows = stack.sightings()
    assert len(rows) == 1
    assert rows[0]["claimed_agent_id"] == GHOST_ID
    assert rows[0]["action_type"] == "tool_call"
    assert rows[0]["attempts"] == 1
    assert rows[0]["first_seen_at"] and rows[0]["last_seen_at"]


def test_repeat_probes_raise_attempts_but_append_one_event(stack) -> None:
    """A probing actor is ONE incident with a counter, not N chain entries — an unregistered
    caller must not be able to grow the tamper-evident chain at will."""
    for _ in range(5):
        assert stack.act(agent_id=GHOST_ID, token="forged").outcome is Outcome.deny

    assert stack.sightings()[0]["attempts"] == 5
    assert len(stack.shadow_events()) == 1
    assert verify_chain(stack.store).ok


def test_registered_agent_never_appears_in_the_sightings(stack) -> None:
    """The negative control. Without it every assertion above would pass on a store that simply
    records everyone."""
    decision = stack.act(agent_id=AGENT_ID, token=stack.token)

    assert decision.outcome is Outcome.allow
    assert stack.sightings() == []
    assert stack.shadow_events() == []


def test_forged_token_for_a_REGISTERED_id_is_still_a_sighting(stack) -> None:
    """Impersonating a real agent is exactly the case worth seeing: the claimed id is a known
    name, but nothing verified it, so it is recorded as CLAIMED — the row is evidence about the
    caller, never a statement about the real agent."""
    decision = stack.act(agent_id=AGENT_ID, token="not-the-real-token")

    assert decision.outcome is Outcome.deny
    assert [r["claimed_agent_id"] for r in stack.sightings()] == [AGENT_ID]


def test_hostile_claimed_id_is_bounded_in_the_api_response(stack) -> None:
    """End to end, an oversized attacker-chosen id reaches the operator BOUNDED — the pipeline
    passes it whole and the store is the one place that trims it."""
    stack.act(agent_id="z" * 9000, token=None)

    rows = stack.sightings()
    assert len(rows) == 1
    assert len(rows[0]["claimed_agent_id"]) == 255
    assert verify_chain(stack.store).ok


def test_the_route_is_behind_the_shared_token_gate(stack) -> None:
    """Who is probing the fleet is not public information."""
    unauthenticated = TestClient(stack.app)  # no default auth header

    assert unauthenticated.get("/discovery/shadow-agents").status_code == 401


def test_app_without_a_shadow_store_has_no_route(constitution_wasm) -> None:
    """Backward compat: unwired -> 404, and the sibling discovery/inventory routes still work."""
    stack = _Stack(constitution_wasm, wire_shadow=False)

    assert stack.client.get("/discovery/shadow-agents").status_code == 404
    assert stack.client.get("/inventory").status_code == 200


def test_unwired_pipeline_still_denies_unregistered_actors(constitution_wasm) -> None:
    """`shadow=None` changes nothing about enforcement — the slice is purely additive."""
    stack = _Stack(constitution_wasm, wire_shadow=False)

    decision = stack.act(agent_id=GHOST_ID, token=None)

    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    assert stack.shadow_events() == []
