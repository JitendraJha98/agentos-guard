"""RUN-07 e2e — the emergency-shutdown acceptance proof (Slice 9e, Task 3).

One shared store, the SAME KillSwitchStore instance behind both the operator surfaces and a REAL
pipeline (mirrors tests/integration/test_kill_switch_api.py), so the halt asserted here is the one
the pipeline's stage-0 check reads:

  - POST /kill/emergency-shutdown -> EVERY agent is denied, including one never seen before, with
    reason code `emergency_killed` (distinguishable from a routine fleet kill's `fleet_killed`)
  - an empty / whitespace-only justification -> 422 and NOTHING is halted (mandatory at the boundary)
  - POST /kill/emergency-resume -> service is restored and the incident row is closed
  - the audited bodies carry short identifiers + the incident id, never the justification text
  - the cookie-gated dashboard actions do the same, and an UNAUTHENTICATED post halts nothing
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
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, EmergencyShutdown
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

AGENT_ID = "test-agent"
UNSEEN_AGENT = "never-seen-agent"
# A justification that WOULD trip the AUD-04 secret gate if it ever reached an audit body.
CANARY = "rotate AKIA1234567890ABCDEF now"


class Wired:
    """Pipeline + KillSwitchStore + API + dashboard over ONE store and the SAME store instance."""

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
        # UNSEEN_AGENT is registered only so identity passes — it has never been killed, seen by the
        # kill switch, or named in any policy: the emergency halt must reach it anyway.
        self.unseen_token = registry.register(UNSEEN_AGENT)
        audit = AuditWriter(self.store)
        self.kill_store = KillSwitchStore(self.store, audit)
        app = create_app(
            ApprovalStore(self.store, audit),
            kill_store=self.kill_store,
            session_factory=self.store,
            api_token="test-token",
            dashboard=True,
        )
        self.client = TestClient(app)
        self.client.headers["Authorization"] = "Bearer test-token"
        # A separate client for the cookie-gated dashboard (no Bearer header, no redirect follow).
        self.browser = TestClient(app, follow_redirects=False)
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
            kill_switch=self.kill_store,  # SAME instance the operator surfaces flip
        )

    def evaluate(self, agent_id: str, token: str):
        # A benign, allowed action: the only thing that can deny it is the kill switch.
        action = AgentAction(
            agent_id=agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com/data", "content": ""},
            identity_token=token,
        )
        return asyncio.run(self.pipeline.evaluate(action))

    def login(self) -> None:
        self.browser.post("/dashboard/login", data={"token": "test-token"})


@pytest.fixture
def wired(constitution_wasm) -> Wired:
    return Wired(constitution_wasm)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def _all_bodies(store) -> str:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return "\n".join(canonical_json(r.body).decode("utf-8") for r in rows)


def test_baseline_actions_are_allowed(wired: Wired) -> None:
    """Sanity: with no halt both agents are allowed — so a later deny is the shutdown."""
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow
    assert wired.evaluate(UNSEEN_AGENT, wired.unseen_token).outcome is Outcome.allow


def test_shutdown_halts_every_agent_then_resume_restores(wired: Wired) -> None:
    """The RUN-07 acceptance proof: shutdown -> every agent denied `emergency_killed`; resume ->
    allowed again and the incident row closed."""
    resp = wired.client.post(
        "/kill/emergency-shutdown", json={"set_by": "op", "justification": "incident 42"}
    )
    assert resp.status_code == 200
    incident_id = resp.json()["incident_id"]
    assert incident_id

    for agent_id, token in ((AGENT_ID, wired.token), (UNSEEN_AGENT, wired.unseen_token)):
        denied = wired.evaluate(agent_id, token)
        assert denied.outcome is Outcome.deny
        assert denied.reasons[0].stage == "killswitch"
        assert denied.reasons[0].code == "emergency_killed"

    resumed = wired.client.post("/kill/emergency-resume", json={"set_by": "op2"})
    assert resumed.status_code == 200
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow
    assert wired.evaluate(UNSEEN_AGENT, wired.unseen_token).outcome is Outcome.allow

    with wired.store() as s:
        row = s.scalar(select(EmergencyShutdown))
    assert str(row.id) == incident_id
    assert row.resumed_at is not None and row.resumed_by == "op2"

    shutdown_events = _events(wired.store, "emergency_shutdown")
    resume_events = _events(wired.store, "emergency_resume")
    assert len(shutdown_events) == 1 and shutdown_events[0]["incident_id"] == incident_id
    assert len(resume_events) == 1 and resume_events[0]["incident_id"] == incident_id
    assert "justification" not in shutdown_events[0]
    assert "incident 42" not in _all_bodies(wired.store)
    assert verify_chain(wired.store).ok


def test_routine_fleet_kill_still_reports_fleet_killed(wired: Wired) -> None:
    """Regression guard: a routine RUN-02 fleet kill must STILL read `fleet_killed`, so forensics
    can tell it apart from an emergency stop."""
    assert wired.client.post("/kill/fleet", json={"set_by": "op", "reason": "routine"}).status_code
    denied = wired.evaluate(UNSEEN_AGENT, wired.unseen_token)
    assert denied.outcome is Outcome.deny
    assert denied.reasons[0].code == "fleet_killed"


@pytest.mark.parametrize("bad", ["", "   "])
def test_missing_justification_is_422_and_halts_nothing(wired: Wired, bad: str) -> None:
    """The justification is MANDATORY at the boundary too: empty fails Pydantic's min_length, and
    whitespace-only survives it but is refused by the store — both 422, both halt NOTHING."""
    resp = wired.client.post(
        "/kill/emergency-shutdown", json={"set_by": "op", "justification": bad}
    )
    assert resp.status_code == 422
    assert wired.kill_store.status(AGENT_ID) is None
    assert wired.kill_store.active_incident() is None
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow
    with wired.store() as s:
        assert s.scalar(select(EmergencyShutdown)) is None
    assert _events(wired.store, "emergency_shutdown") == []


def test_secret_bearing_justification_still_shuts_down(wired: Wired) -> None:
    """A hostile justification must never be able to BLOCK an emergency stop."""
    resp = wired.client.post(
        "/kill/emergency-shutdown", json={"set_by": "op", "justification": CANARY}
    )
    assert resp.status_code == 200
    assert wired.evaluate(UNSEEN_AGENT, wired.unseen_token).reasons[0].code == "emergency_killed"
    with wired.store() as s:
        assert s.scalar(select(EmergencyShutdown)).justification == CANARY
    assert CANARY not in _all_bodies(wired.store)
    assert "AKIA1234567890ABCDEF" not in _all_bodies(wired.store)


def test_dashboard_shutdown_halts_and_shows_the_incident_banner(wired: Wired) -> None:
    wired.login()
    resp = wired.browser.post(
        "/dashboard/kill/emergency-shutdown", data={"justification": "incident 42"}
    )
    assert resp.status_code == 303
    status = wired.kill_store.status(UNSEEN_AGENT)
    assert status is not None and status.scope == "emergency"

    page = wired.browser.get("/dashboard/kill")
    assert page.status_code == 200
    assert wired.kill_store.active_incident() in page.text

    resumed = wired.browser.post("/dashboard/kill/emergency-resume", data={})
    assert resumed.status_code == 303
    assert wired.kill_store.status(UNSEEN_AGENT) is None


def test_unauthenticated_dashboard_shutdown_redirects_and_halts_nothing(wired: Wired) -> None:
    resp = wired.browser.post(  # NO login
        "/dashboard/kill/emergency-shutdown", data={"justification": "incident 42"}
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/dashboard/login"
    assert wired.kill_store.status(AGENT_ID) is None
    assert wired.kill_store.active_incident() is None
