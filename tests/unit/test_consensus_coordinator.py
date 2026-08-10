"""POL-09 — the consensus round/vote records + the StoreConsensusCoordinator (Slice 9f).

Two halves, both fail-closed:

* the DURABLE record — a `consensus_round` (who was asked, how many approved, the quorum,
  whether it was reached) and one `consensus_vote` per voter, with `error` naming a voter
  that raised or timed out;
* the COORDINATOR — voters asked CONCURRENTLY with a per-voter timeout, where an error, a
  timeout, or a non-boolean truthy value is a NO-VOTE and never an approval.

The AUD-04 secret gate scans every audit body, so a consensus event carrying the action's
payload could be REFUSED — meaning a consensus resolution would fail to audit. The bodies
therefore carry SHORT IDENTIFIERS + COUNTS ONLY; `SECRET-CANARY` proves it.
"""

from __future__ import annotations

import asyncio
import time
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


# --- the coordinator -------------------------------------------------------------


class _Voter:
    """A stub ConsensusVoter: a fixed verdict, optionally after a delay or an exception."""

    def __init__(self, name: str, verdict=True, *, delay: float = 0.0, raises: bool = False):
        self.name = name
        self._verdict = verdict
        self._delay = delay
        self._raises = raises
        self.calls = 0

    async def vote(self, action, decision):
        self.calls += 1
        if self._delay:
            await asyncio.sleep(self._delay)
        if self._raises:
            raise RuntimeError("voter offline")
        return self._verdict


def _coordinator(store, voters, **kw):
    from agentos_controlplane.consensus import StoreConsensusCoordinator

    return StoreConsensusCoordinator(store, AuditWriter(store), voters, **kw)


def _round(store) -> ConsensusRound:
    with store() as session:
        return session.scalars(select(ConsensusRound)).one()


def _votes(store) -> dict[str, ConsensusVote]:
    with store() as session:
        return {v.voter: v for v in session.scalars(select(ConsensusVote))}


def test_two_of_three_reaches_quorum_and_persists_and_audits(store) -> None:
    action = _action()
    coord = _coordinator(
        store, [_Voter("v1", True), _Voter("v2", True), _Voter("v3", False)]
    )

    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is True

    row = _round(store)
    assert row.voters == 3 and row.approvals == 2 and row.quorum == 2 and row.reached is True
    assert row.action_id == action.id and row.agent_id == action.agent_id

    votes = _votes(store)
    assert {n: v.approved for n, v in votes.items()} == {"v1": True, "v2": True, "v3": False}
    assert all(v.error is None for v in votes.values())

    vote_events = _events(store, "consensus_vote")
    assert len(vote_events) == 3
    resolved = _events(store, "consensus_resolved")
    assert len(resolved) == 1
    assert resolved[0]["approvals"] == 2 and resolved[0]["voters"] == 3
    assert resolved[0]["quorum"] == 2 and resolved[0]["reached"] is True
    assert resolved[0]["round_id"] == str(row.id)
    assert verify_chain(store).ok


def test_one_of_three_is_short_of_quorum(store) -> None:
    action = _action()
    coord = _coordinator(
        store, [_Voter("v1", True), _Voter("v2", False), _Voter("v3", False)]
    )
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is False
    row = _round(store)
    assert row.approvals == 1 and row.reached is False
    assert _events(store, "consensus_resolved")[0]["reached"] is False


def test_three_of_three_reaches_quorum(store) -> None:
    action = _action()
    coord = _coordinator(store, [_Voter("v1"), _Voter("v2"), _Voter("v3")])
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is True
    assert _round(store).approvals == 3


def test_a_raising_voter_is_a_no_vote(store) -> None:
    """Fail-closed: an error is NEVER an approval — but the other voters still carry the round."""
    action = _action()
    coord = _coordinator(
        store, [_Voter("v1", True), _Voter("v2", True), _Voter("v3", raises=True)]
    )
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is True
    votes = _votes(store)
    assert votes["v3"].approved is False and votes["v3"].error == "RuntimeError"


def test_two_raising_voters_deny_the_round(store) -> None:
    action = _action()
    coord = _coordinator(
        store, [_Voter("v1", True), _Voter("v2", raises=True), _Voter("v3", raises=True)]
    )
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is False
    votes = _votes(store)
    assert votes["v2"].error == "RuntimeError" and votes["v3"].error == "RuntimeError"
    assert _round(store).approvals == 1 and _round(store).reached is False


def test_a_hanging_voter_times_out_as_a_no_vote_and_returns_promptly(store) -> None:
    """A voter that never answers must not hang the action, and silence is not consent."""
    action = _action()
    coord = _coordinator(
        store,
        [_Voter("v1", True), _Voter("v2", True, delay=30.0), _Voter("v3", False)],
        timeout_s=0.05,
    )
    started = time.monotonic()
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is False
    elapsed = time.monotonic() - started
    assert elapsed < 5.0  # the call returned promptly — it never waited on the hung voter
    votes = _votes(store)
    assert votes["v2"].approved is False and votes["v2"].error == "timeout"
    assert _round(store).approvals == 1 and _round(store).reached is False


def test_votes_are_collected_concurrently(store) -> None:
    """Three 0.2s voters resolve in ~0.2s, not ~0.6s — concurrent, not serial."""
    action = _action()
    coord = _coordinator(
        store,
        [_Voter("v1", True, delay=0.2), _Voter("v2", True, delay=0.2), _Voter("v3", True, delay=0.2)],
        timeout_s=5.0,
    )
    started = time.monotonic()
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is True
    assert time.monotonic() - started < 0.5


def test_a_truthy_non_bool_is_not_an_approval(store) -> None:
    """Only a genuine `True` approves: a voter returning `"yes"`, `1`, or an object must
    not smuggle a truthy value past the quorum."""
    action = _action()
    coord = _coordinator(
        store, [_Voter("v1", "yes"), _Voter("v2", 1), _Voter("v3", object())]
    )
    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is False
    votes = _votes(store)
    assert all(v.approved is False for v in votes.values())
    assert _round(store).approvals == 0


@pytest.mark.parametrize(
    "voters,quorum",
    [([], 2), ([_Voter("v1"), _Voter("v2"), _Voter("v3")], 0), ([_Voter("v1"), _Voter("v2"), _Voter("v3")], 4)],
)
def test_construction_validation(store, voters, quorum) -> None:
    with pytest.raises(ValueError):
        _coordinator(store, voters, quorum=quorum)


def test_no_payload_reaches_any_audit_body(store) -> None:
    """Short identifiers + counts ONLY — so the AUD-04 gate can never refuse (and thereby
    block) a consensus resolution."""
    action = _action()
    coord = _coordinator(
        store, [_Voter("v1", True), _Voter("v2", raises=True), _Voter("v3", False)]
    )
    asyncio.run(coord.reach_consensus(action, _decision(action)))

    bodies = _events(store, "consensus_vote") + _events(store, "consensus_resolved")
    assert len(bodies) == 4
    for body in bodies:
        assert "SECRET-CANARY" not in str(body)
        assert "target" not in body and "payload" not in body
    assert verify_chain(store).ok
