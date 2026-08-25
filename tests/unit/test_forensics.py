"""AUD-09 / OBS-05 — the evidence graph.

The claim under test is narrower than the word "evidence" suggests, and that narrowness is the
point: a reconstructed chain is what the fleet CLAIMED about its own causation, not proof of it.
These tests pin both halves — that the reconstruction is correct, and that it never says more than
it can support.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionContext, ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.forensics import _MAX_DEPTH, _MAX_RECORDS, EvidenceGraph
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    """ONE writer — a second instance caches a stale chain head."""
    return AuditWriter(store)


def _decision(action: AgentAction, outcome: Outcome = Outcome.allow) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=outcome,
        reasons=[Reason(stage="policy", code="no_match_posture", detail="ok")],
    )


def _act(
    audit: AuditWriter,
    agent_id: str = "a1",
    *,
    action_type: ActionType = ActionType.tool_call,
    parent=None,
    conversation: str | None = None,
) -> AgentAction:
    payload = {
        ActionType.tool_call: {"url": "https://api.example.com/x", "content": ""},
        ActionType.delegation: {"to_agent": "b", "task": "t"},
        ActionType.model_invocation: {"model": "m", "messages": ["hi"]},
        ActionType.memory_access: {"operation": "read", "key": "k"},
        ActionType.mcp_call: {"server": "s", "tool": "t"},
    }[action_type]
    action = AgentAction(
        agent_id=agent_id,
        type=action_type,
        target="http_get",
        payload=payload,
        context=ActionContext(parent_action_id=parent, conversation_id=conversation),
    )
    asyncio.run(audit.append(action, _decision(action)))
    return action


# --- the reconstruction itself ------------------------------------------------


def test_a_chain_reconstructs_the_causal_path_nearest_first(store, audit) -> None:
    a = _act(audit, "a1")
    b = _act(audit, "a2", parent=a.id)
    c = _act(audit, "a3", parent=b.id)

    chain = EvidenceGraph(store).ancestors(str(c.id))

    assert [r["agent_id"] for r in chain.records] == ["a3", "a2", "a1"]
    assert chain.truncated is False


def test_a_chain_stops_at_a_parent_no_record_claims(store, audit) -> None:
    """A dangling parent is not an error: the referenced action may predate retention, or may never
    have existed. The chain ends where the evidence ends, and does not call that truncation — this
    IS the whole chain we hold."""
    orphan = _act(audit, "a1", parent=uuid4())

    chain = EvidenceGraph(store).ancestors(str(orphan.id))

    assert len(chain.records) == 1 and chain.truncated is False


# --- the two structural hazards ------------------------------------------------


def test_a_CYCLE_terminates_and_is_reported_as_truncated(store, audit) -> None:
    """REGRESSION GUARD, and the reason this module bounds anything at all.

    `parent_action_id` is caller-supplied, so an agent can claim A's parent is B while B's parent is
    A. An unbounded walk never returns — a denial of service against the tool an operator reaches
    for DURING an incident, triggerable by the very agent under investigation. This builds a real
    cycle rather than arguing about one.
    """
    a = _act(audit, "a1")
    b = _act(audit, "a2", parent=a.id)
    with store() as s:  # close the loop: a's parent becomes b
        row = s.scalars(
            select(AuditRecord).where(AuditRecord.body["action_id"].as_string() == str(a.id))
        ).one()
        row.body = dict(row.body, parent_action_id=str(b.id))
        s.commit()

    chain = EvidenceGraph(store).ancestors(str(b.id))

    assert chain.truncated is True, "a cycle must be reported, not silently trimmed"
    assert len(chain.records) <= _MAX_DEPTH


def test_a_self_parent_terminates(store, audit) -> None:
    """The one-node cycle, which an off-by-one in the visited check would miss."""
    a = _act(audit, "a1")
    with store() as s:
        row = s.scalars(
            select(AuditRecord).where(AuditRecord.body["action_id"].as_string() == str(a.id))
        ).one()
        row.body = dict(row.body, parent_action_id=str(a.id))
        s.commit()

    chain = EvidenceGraph(store).ancestors(str(a.id))

    assert chain.truncated is True and len(chain.records) == 1


def test_a_chain_deeper_than_the_cap_is_truncated_and_says_so(store, audit) -> None:
    """A chain that stops early without saying so reads as a complete account of what happened."""
    parent = None
    for _ in range(_MAX_DEPTH + 5):
        parent = _act(audit, "a1", parent=parent).id

    chain = EvidenceGraph(store).ancestors(str(parent))

    assert chain.truncated is True
    assert len(chain.records) == _MAX_DEPTH


# --- what the answer is worth --------------------------------------------------


def test_every_chain_carries_the_claimed_lineage_qualifier(store, audit) -> None:
    """SPEC D-2, asserted rather than documented.

    `identity_verified` authenticates who ACTED, not that `parent_action_id` names a real
    delegation. An investigator reading a chain as proven causation would attribute an action to an
    agent on the strength of a field that agent's own caller supplied.
    """
    a = _act(audit, "a1")

    chain = EvidenceGraph(store).ancestors(str(a.id))

    assert "CLAIMED, not proven" in chain.lineage
    assert "TRST-04" in chain.lineage
    assert "lineage" in chain.as_dict()


def test_the_qualifier_survives_serialization(store, audit) -> None:
    """`as_dict` is what the route returns. A serializer that dropped `lineage` would strip exactly
    the field that keeps the answer honest."""
    a = _act(audit, "a1")

    payload = EvidenceGraph(store).ancestors(str(a.id)).as_dict()

    assert set(payload) == {"records", "truncated", "depth_limit", "lineage"}


# --- conversations (OBS-05) ----------------------------------------------------


def test_a_conversation_reconstructs_across_tools_AND_delegations(store, audit) -> None:
    """OBS-05 says "across tools and delegations". A reconstruction confined to one action type
    would satisfy the words and miss the point — the filter is the conversation, not the kind."""
    cid = "conv-1"
    _act(audit, "a1", action_type=ActionType.tool_call, conversation=cid)
    _act(audit, "a1", action_type=ActionType.delegation, conversation=cid)
    _act(audit, "a2", action_type=ActionType.model_invocation, conversation=cid)
    _act(audit, "a9", conversation="other-conversation")

    convo = EvidenceGraph(store).conversation(cid)

    assert {r["action_type"] for r in convo.records} == {
        "tool_call",
        "delegation",
        "model_invocation",
    }
    assert all(r["conversation_id"] == cid for r in convo.records)


def test_a_conversation_is_ordered_by_the_chains_OWN_sequence(store, audit) -> None:
    """`seq` is covered by the record hash; `created_at` is not, and SQLite's has one-second
    granularity. Ordering forensic evidence by an unauthenticated, low-resolution column would let
    two records be presented in an order the evidence does not support — and the order IS the causal
    claim a reader takes away.

    The rows are stamped with DESCENDING created_at, so anything sorting by it comes back reversed.
    """
    cid = "conv-ordered"
    for _ in range(4):
        _act(audit, "a1", conversation=cid)
    base = datetime(2026, 8, 19, 12, 0, 30)
    with store() as s:
        for offset, seq in enumerate(sorted(r.seq for r in s.scalars(select(AuditRecord)).all())):
            s.execute(
                update(AuditRecord)
                .where(AuditRecord.seq == seq)
                .values(created_at=base - timedelta(seconds=offset))
            )
        s.commit()

    seqs = [r["seq"] for r in EvidenceGraph(store).conversation(cid).records]

    assert seqs == sorted(seqs)


def test_an_unknown_action_or_conversation_is_empty_not_an_error(store, audit) -> None:
    """During an incident, "nothing matched" is an answer; a traceback is not."""
    graph = EvidenceGraph(store)

    assert graph.ancestors(str(uuid4())).records == ()
    assert graph.conversation("no-such-conversation").records == ()


def test_the_conversation_read_is_bounded_and_reports_truncation(store, audit) -> None:
    """`conversation_id` is caller-supplied, so an agent chooses how much this returns."""
    cid = "big"
    with store() as s:  # seed past the cap directly; appending 2001 governed actions is not the point
        for i in range(_MAX_RECORDS + 3):
            s.add(
                AuditRecord(
                    seq=1000 + i,
                    prev_hash=None,
                    record_hash=f"{i:064x}",
                    body={"action_id": str(uuid4()), "conversation_id": cid, "agent_id": "a1"},
                )
            )
        s.commit()

    convo = EvidenceGraph(store).conversation(cid)

    assert len(convo.records) == _MAX_RECORDS and convo.truncated is True


def test_the_bodies_are_the_redacted_ones_the_chain_already_holds(store, audit) -> None:
    """AUD-04 redacts at write time, so a reconstruction inherits it. This asserts the forensic
    surface adds no un-redacted read path: it is the most sensitive read in the product, and it must
    not become the way around the redactor."""
    action = AgentAction(
        agent_id="a1",
        type=ActionType.model_invocation,
        target="chat",
        payload={"model": "m", "messages": ["my password is hunter2-CANARY"]},
    )
    asyncio.run(audit.append(action, _decision(action)))

    chain = EvidenceGraph(store).ancestors(str(action.id))

    assert "hunter2-CANARY" not in str(chain.records)


def test_components_without_a_graph_store_is_empty_not_an_error(store) -> None:
    """The absence of an optional collaborator is not a forensic finding, and an operator who has
    not wired the Phase-10 graph should not lose the chain."""
    assert EvidenceGraph(store).components_for(["a1"]) == []
