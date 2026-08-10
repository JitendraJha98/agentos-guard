"""POL-09 — the consensus round/vote records + the StoreConsensusCoordinator (Slice 9f).

Two halves, both fail-closed:

* the DURABLE record — a `consensus_round` (who was asked, how many approved, the quorum,
  whether it was reached) and one `consensus_vote` per voter, with `error` naming a voter
  that raised or timed out;
* the COORDINATOR — voters asked CONCURRENTLY with a per-voter timeout, where an error, a
  timeout, or a non-boolean truthy value is a NO-VOTE and never an approval (Task 3).

The AUD-04 secret gate scans every audit body, so a consensus event carrying the action's
payload could be REFUSED — meaning a consensus resolution would fail to audit. The bodies
therefore carry SHORT IDENTIFIERS + COUNTS ONLY; `SECRET-CANARY` proves it.
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, ConsensusRound, ConsensusVote


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _action(content: str = "SECRET-CANARY") -> AgentAction:
    return AgentAction(
        agent_id="consensus-agent",
        type=ActionType.tool_call,
        target="http_post",
        payload={"url": "https://api.example.com/send", "content": content},
        identity_token="tok",
    )


def _decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.require_consensus,
        reasons=[Reason(stage="graduated", code="require_consensus")],
    )


def _events(store, kind: str) -> list[dict]:
    with store() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


# --- the records + the event kinds ----------------------------------------------


def test_consensus_rows_round_trip(store) -> None:
    round_id = uuid4()
    with store() as session:
        session.add(
            ConsensusRound(
                id=round_id,
                action_id=_action().id,
                agent_id="a1",
                voters=3,
                approvals=2,
                quorum=2,
                reached=True,
            )
        )
        session.add(ConsensusVote(round_id=round_id, voter="v1", approved=True))
        session.add(ConsensusVote(round_id=round_id, voter="v2", approved=False, error="timeout"))
        session.commit()
    with store() as session:
        row = session.scalars(select(ConsensusRound)).one()
        assert row.voters == 3 and row.approvals == 2 and row.quorum == 2
        assert row.reached is True and row.agent_id == "a1"
        assert row.created_at is not None
        votes = {v.voter: v for v in session.scalars(select(ConsensusVote))}
    assert votes["v1"].approved is True and votes["v1"].error is None
    assert votes["v2"].approved is False and votes["v2"].error == "timeout"
    assert votes["v2"].round_id == round_id


def test_consensus_event_kinds_are_allowlisted(store) -> None:
    audit = AuditWriter(store)
    asyncio.run(audit.append_event("consensus_vote", {"action_id": "x"}))
    asyncio.run(audit.append_event("consensus_resolved", {"action_id": "x"}))
    assert len(_events(store, "consensus_vote")) == 1
    assert len(_events(store, "consensus_resolved")) == 1
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("consensus_invented", {"action_id": "x"}))
