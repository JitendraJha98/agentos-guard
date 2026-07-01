"""Kill-switch resolve API + e2e halt/restore proof (RUN-01/02, API-03, Task 4).

The RUN-01/02 acceptance proof over ONE shared store and the SAME KillSwitchStore
instance (so the in-memory flag the pipeline checks is the one the API flips):

  - POST /kill/agents/{id}  -> that agent's NEXT pipeline.evaluate is denied (agent_killed)
  - POST .../clear          -> the agent's action is allowed again
  - POST /kill/fleet        -> a DIFFERENT agent is denied (fleet_killed)
  - GET  /kill              -> lists the active kills
  - operator inputs bounded -> 200-char set_by is a 422

The pipeline runs the REAL compiled-constitution engine over a benign allowed action, so
the ONLY reason a kill denies is the stage-0 switch.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.api import create_app
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

AGENT_ID = "test-agent"
OTHER_AGENT = "other-agent"


class Wired:
    """Pipeline, KillSwitchStore, and API over ONE shared store and the SAME
    KillSwitchStore instance (the in-memory flag is shared API<->pipeline)."""

    def __init__(self, constitution_wasm) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        self.other_token = registry.register(OTHER_AGENT)
        audit = AuditWriter(self.store)
        self.kill_store = KillSwitchStore(self.store, audit)
        from agentos_controlplane.approvals import ApprovalStore

        approvals = ApprovalStore(self.store, audit)
        self.client = TestClient(create_app(approvals, kill_store=self.kill_store))
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
            posture=PostureMap(),
            kill_switch=self.kill_store,  # SAME instance the API flips
        )

    def action(self, agent_id: str, token: str) -> AgentAction:
        # A benign, allowed action: the only thing that can deny it is the kill switch.
        return AgentAction(
            agent_id=agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=token,
        )

    def evaluate(self, agent_id: str, token: str):
        return asyncio.run(self.pipeline.evaluate(self.action(agent_id, token)))


@pytest.fixture
def wired(constitution_wasm) -> Wired:
    return Wired(constitution_wasm)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_baseline_action_is_allowed(wired: Wired) -> None:
    """Sanity: with no kill, the benign action is allowed — so a later deny is the switch."""
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow


def test_kill_via_api_then_pipeline_denies_then_clear_allows(wired: Wired) -> None:
    """The RUN-01 acceptance proof: API kill -> pipeline denies -> clear -> allows."""
    resp = wired.client.post(
        f"/kill/agents/{AGENT_ID}", json={"set_by": "op@x", "reason": "rogue"}
    )
    assert resp.status_code == 200

    denied = wired.evaluate(AGENT_ID, wired.token)
    assert denied.outcome is Outcome.deny
    assert denied.reasons[0].stage == "killswitch"
    assert denied.reasons[0].code == "agent_killed"

    cleared = wired.client.post(f"/kill/agents/{AGENT_ID}/clear", json={"set_by": "op@x"})
    assert cleared.status_code == 200
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow

    # Both toggles landed on the audit chain (short-identifier bodies).
    assert len(_events(wired.store, "kill_switch_set")) == 1
    assert len(_events(wired.store, "kill_switch_cleared")) == 1


def test_fleet_kill_via_api_denies_a_different_agent(wired: Wired) -> None:
    """The RUN-02 acceptance proof: fleet kill denies ALL agents."""
    resp = wired.client.post("/kill/fleet", json={"set_by": "op", "reason": "incident"})
    assert resp.status_code == 200

    other = wired.evaluate(OTHER_AGENT, wired.other_token)
    assert other.outcome is Outcome.deny
    assert other.reasons[0].code == "fleet_killed"

    cleared = wired.client.post("/kill/fleet/clear", json={"set_by": "op"})
    assert cleared.status_code == 200
    assert wired.evaluate(OTHER_AGENT, wired.other_token).outcome is Outcome.allow


def test_get_kill_lists_active(wired: Wired) -> None:
    wired.client.post(f"/kill/agents/{AGENT_ID}", json={"set_by": "op", "reason": "r1"})
    wired.client.post("/kill/fleet", json={"set_by": "op", "reason": "r2"})
    resp = wired.client.get("/kill")
    assert resp.status_code == 200
    rows = {r["target"]: r for r in resp.json()}
    assert rows[AGENT_ID]["scope"] == "agent" and rows[AGENT_ID]["reason"] == "r1"
    assert rows["*"]["scope"] == "fleet"


def test_set_by_bounds_enforced_422(wired: Wired) -> None:
    resp = wired.client.post(
        f"/kill/agents/{AGENT_ID}", json={"set_by": "x" * 200}
    )
    assert resp.status_code == 422
    # Nothing got killed (the agent still evaluates to allow).
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow


def test_reason_bounds_enforced_422(wired: Wired) -> None:
    resp = wired.client.post(
        f"/kill/agents/{AGENT_ID}", json={"set_by": "op", "reason": "r" * 513}
    )
    assert resp.status_code == 422


def test_create_app_without_kill_store_has_no_kill_routes() -> None:
    """Backward compat: create_app(store) (no kill_store) still works and exposes
    no /kill routes."""
    from agentos_controlplane.approvals import ApprovalStore

    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    app = create_app(ApprovalStore(sf, AuditWriter(sf)))
    client = TestClient(app)
    assert client.get("/kill").status_code == 404
