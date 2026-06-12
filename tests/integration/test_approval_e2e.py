"""Approval lifecycle e2e (6b-2) — REAL pipeline, REAL store, API-resolved.

The full POL-07 loop over one shared SQLite store: the compiled-constitution
pipeline decides require_approval (principle 2.1 on destructive intent), the
SDK core parks via StoreApprovalCoordinator and block-awaits the PERSISTED row,
the operator resolves through the FastAPI endpoint (a different writer — the
D3 store-rendezvous proof), and only then does the governed operation run.
Every lifecycle event lands on the ONE audit hash chain.

Plus the POL-13 loop: a human-ratified exception granted through resolve(...,
exception_expires_at=...) is consumed by the pipeline's transform on the next
matching action — outcome temporary_exception, executed by the same core.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.coordinator import StoreApprovalCoordinator
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_sdk.enforce import GovernanceDenied, governed_call

AGENT_ID = "test-agent"


class Wired:
    """Everything over ONE shared store: pipeline, approvals, coordinator, API."""

    def __init__(self, constitution_wasm) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,                      # TestClient resolves from a
            connect_args={"check_same_thread": False},  # portal thread (one shared conn)
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        audit = AuditWriter(self.store)
        self.approvals = ApprovalStore(self.store, audit)
        self.coordinator = StoreApprovalCoordinator(
            self.approvals, audit, PostureMap(), deadline_s=5.0, poll_s=0.05
        )
        self.client = TestClient(create_app(self.approvals))
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
            exceptions=self.approvals,  # ApprovalStore.active_for == the POL-13 lookup
        )


@pytest.fixture
def wired(constitution_wasm) -> Wired:
    return Wired(constitution_wasm)


def _destructive_action(wired: Wired) -> AgentAction:
    """Fires 2.1 (destructive intent -> require_approval) on an allowlisted host."""
    return AgentAction(
        agent_id=AGENT_ID, type=ActionType.tool_call, target="drop_table",
        payload={"url": "https://api.example.com/x", "content": ""},
        identity_token=wired.token,
    )


def _exfil_action(wired: Wired) -> AgentAction:
    """Fires 1.1 (unlisted host -> deny)."""
    return AgentAction(
        agent_id=AGENT_ID, type=ActionType.tool_call, target="http_get",
        payload={"url": "https://attacker.example/x", "content": ""},
        identity_token=wired.token,
    )


class _Op:
    def __init__(self) -> None:
        self.ran = 0

    async def __call__(self):
        self.ran += 1
        return "ran"


async def _api_resolve_when_parked(wired: Wired, body: dict) -> dict:
    """Resolve the first pending approval via the FastAPI endpoint — a separate
    writer against the same persisted row (the D3 rendezvous)."""
    while not (pending := wired.approvals.list_pending()):
        await asyncio.sleep(0.02)
    resp = await asyncio.to_thread(
        wired.client.post, f"/approvals/{pending[0].id}/resolve", json=body
    )
    assert resp.status_code == 200
    return resp.json()


def test_approve_flow_e2e_real_pipeline_api_resolved(wired: Wired) -> None:
    action = _destructive_action(wired)
    op = _Op()

    async def scenario():
        resolver = asyncio.create_task(
            _api_resolve_when_parked(
                wired, {"approved": True, "resolver": "op@example.com"}
            )
        )
        result = await governed_call(
            wired.pipeline, action, op, coordinator=wired.coordinator
        )
        await resolver
        return result

    assert asyncio.run(scenario()) == "ran" and op.ran == 1
    # The parked row carries the REDACTED context and is now approved.
    row = wired.approvals.list_requests()[0]
    assert row.status == "approved"
    assert row.context["url"] == "https://api.example.com"  # host-only
    # One continuous hash chain: the decision record AND the lifecycle event.
    with wired.store() as session:
        records = list(session.scalars(select(AuditRecord).order_by(AuditRecord.seq)))
    assert [r.seq for r in records] == list(range(len(records)))
    for prev, cur in zip(records, records[1:]):
        assert cur.prev_hash == prev.record_hash
    kinds = [r.body.get("kind") for r in records]
    assert "approval_resolved" in kinds
    decision_bodies = [r.body for r in records if "outcome" in r.body]
    assert any(b["outcome"] == "require_approval" for b in decision_bodies)


def test_timeout_flow_e2e_blocks_fail_closed(wired: Wired) -> None:
    wired.coordinator._deadline_s = 0.15  # nobody resolves; tool_call fails closed
    action = _destructive_action(wired)
    op = _Op()
    with pytest.raises(GovernanceDenied) as exc:
        asyncio.run(governed_call(wired.pipeline, action, op, coordinator=wired.coordinator))
    assert op.ran == 0
    assert any(r.code == "approval_timeout" for r in exc.value.decision.reasons)
    assert wired.approvals.list_requests()[0].status == "timed_out"


def test_exception_grant_then_consumption_e2e(wired: Wired) -> None:
    """POL-13 end to end: the deny stands; a human grants a time-boxed exception
    through the resolve API; the SAME action now rides temporary_exception and
    the governed call executes — auto-revoke is read-time, so this whole loop
    needed no background job."""
    op = _Op()
    # 1) The deny floor stands (1.1: unlisted host).
    with pytest.raises(GovernanceDenied):
        asyncio.run(governed_call(wired.pipeline, _exfil_action(wired), op))
    assert op.ran == 0

    # 2) An operator parks-and-ratifies the exception for the denying principle.
    #    (The approval row's fired reasons carry ref 1.1 — the grant scope.)
    parked_action = _exfil_action(wired)
    parked_decision = Decision(
        action_id=parked_action.id,
        outcome=Outcome.require_approval,
        reasons=[
            Reason(
                stage="policy", code="constitution_principle_fired",
                principle_ref="1.1", evidence={"effect": "deny"},
            )
        ],
    )
    approval_id = wired.approvals.create(parked_action, parked_decision, deadline_s=60)
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    resp = wired.client.post(
        f"/approvals/{approval_id}/resolve",
        json={
            "approved": True,
            "resolver": "op@example.com",
            "exception_expires_at": until.isoformat(),
        },
    )
    assert resp.status_code == 200

    # 3) The same exfil action now converts: temporary_exception -> executes.
    op2 = _Op()
    result = asyncio.run(governed_call(wired.pipeline, _exfil_action(wired), op2))
    assert result == "ran" and op2.ran == 1
    decision = asyncio.run(wired.pipeline.evaluate(_exfil_action(wired)))
    assert decision.outcome is Outcome.temporary_exception
    assert decision.expires_at is not None
