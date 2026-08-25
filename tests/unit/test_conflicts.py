"""POL-11 — transitive permission closure and emergent capability conflicts.

The load-bearing test here is the random-chain subset property. A union anywhere in the fold lets a
chain manufacture a capability nobody in it held — trust laundering by composition — and hand-written
examples pass straight through that, which is why the invariant is checked over generated chains
rather than a chosen one.

The second is that a finding denies nothing. POL-11 says "flags", and an engine that denied on its own
authority would be a second enforcer beside the constitution.
"""

from __future__ import annotations

import asyncio
import random
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionContext, ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.conflicts import ConflictEngine, effective_scope
from agentos_controlplane.forensics import EvidenceGraph
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.delegation import ALL, WILDCARD, Authority, DelegationLedger


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
def audit(store) -> AuditWriter:
    return AuditWriter(store)


class _Scopes:
    """The injected `ScopeLookup` seam."""

    def __init__(self, mapping):
        self._m = dict(mapping)

    def scope_for(self, agent_id: str):
        return self._m.get(agent_id, ALL)


def _act(audit, agent_id, *, parent=None) -> AgentAction:
    action = AgentAction(
        agent_id=agent_id,
        type=ActionType.delegation,
        target="delegate",
        payload={"to_agent": "b", "task": "t"},
        context=ActionContext(parent_action_id=parent),
    )
    asyncio.run(
        audit.append(
            action,
            Decision(
                action_id=action.id,
                outcome=Outcome.allow,
                reasons=[Reason(stage="identity", code="identity_verified", detail="ok")],
            ),
        )
    )
    return action


def _engine(store, audit, *, scopes=None, ledger=None) -> ConflictEngine:
    return ConflictEngine(EvidenceGraph(store), store, ledger=ledger, scopes=scopes)


# --- the fold ------------------------------------------------------------------


def test_effective_scope_narrows_along_the_chain() -> None:
    """A grants {read,write,delete}, B grants {read,write}, C grants {read}: the end holds {read}."""
    result = effective_scope([{"read", "write", "delete"}, {"read", "write"}, {"read"}])

    assert result == frozenset({"read"})


def test_an_empty_chain_is_the_wildcard_identity_not_a_grant() -> None:
    """Intersection's identity. With no hop there is nothing to narrow, which is different from
    conferring everything on an agent that was never in a chain."""
    assert effective_scope([]) == frozenset({WILDCARD})


@pytest.mark.parametrize("seed", range(30))
def test_the_closure_is_a_subset_of_every_participant(seed: int) -> None:
    """THE invariant, over random chains rather than a chosen example.

    A union anywhere in the fold lets a chain manufacture a capability nobody in it held — trust
    laundering by composition, the escalation TRST-04 exists to stop. Hand-written examples pass
    straight through an inverted fold; a subset property over generated input does not.
    """
    rng = random.Random(seed)
    universe = [f"cap{i}" for i in range(8)]
    scopes = [
        frozenset(rng.sample(universe, rng.randint(1, len(universe))))
        for _ in range(rng.randint(1, 6))
    ]

    result = effective_scope(scopes)

    for scope in scopes:
        assert result <= scope, f"the fold widened past a participant: {result} !<= {scope}"


@pytest.mark.parametrize("seed", range(10))
def test_a_wildcard_hop_never_widens_the_others(seed: int) -> None:
    """The wildcard confers everything, so it must be the identity in a fold and not a reset."""
    rng = random.Random(seed)
    narrow = frozenset(rng.sample([f"cap{i}" for i in range(8)], 3))

    assert effective_scope([narrow, ALL]) == narrow
    assert effective_scope([ALL, narrow]) == narrow


# --- the closure over real lineage --------------------------------------------


def test_the_closure_follows_the_audit_chain_and_narrows_root_to_leaf(store, audit) -> None:
    """The fold order matters: a permission narrows from the ROOT down, while `ancestors` returns
    nearest-first. Folding in walk order would compute the chain backwards, which for a symmetric
    intersection is invisible until a wildcard sits at one end."""
    a = _act(audit, "root")
    b = _act(audit, "middle", parent=a.id)
    c = _act(audit, "leaf", parent=b.id)
    scopes = _Scopes({"root": {"read", "write"}, "middle": {"read", "write"}, "leaf": {"read"}})

    closure = _engine(store, audit, scopes=scopes).closure(str(c.id))

    assert closure["agents"] == ["root", "middle", "leaf"]
    assert closure["effective_scope"] == ["read"]


def test_the_closure_carries_the_claimed_lineage_qualifier(store, audit) -> None:
    """It is built on 12e's walk, so it inherits — and must not strip — the statement that lineage is
    claimed rather than proven."""
    a = _act(audit, "root")

    closure = _engine(store, audit).closure(str(a.id))

    assert "CLAIMED, not proven" in closure["lineage"]


def test_a_cycle_in_the_chain_terminates(store, audit) -> None:
    """Inherited from 12e's bounded walk, asserted here because this module is a second caller and a
    caller can always undo a guarantee by looping itself."""
    from sqlalchemy import select

    from agentos_controlplane.store.models import AuditRecord

    a = _act(audit, "a1")
    b = _act(audit, "a2", parent=a.id)
    with store() as s:
        row = s.scalars(
            select(AuditRecord).where(AuditRecord.body["action_id"].as_string() == str(a.id))
        ).one()
        row.body = dict(row.body, parent_action_id=str(b.id))
        s.commit()

    closure = _engine(store, audit).closure(str(b.id))

    assert closure["truncated"] is True


# --- the findings --------------------------------------------------------------


def test_an_uncorroborated_lineage_edge_is_reported_as_NOT_CORROBORATED(store, audit) -> None:
    """Spec D-5, and the honest ceiling on Phase 12's gap.

    The ledger is in-process, non-persistent and FIFO-evicted by its own documentation, so an absent
    entry is routine. The finding therefore says the claim is not corroborated — it does NOT say the
    delegation did not happen. "Unverified" and "false" are different accusations and only one is
    supportable, so the wording is asserted rather than left to a future editor.
    """
    a = _act(audit, "a1")
    _act(audit, "a2", parent=a.id)  # claims a parent the empty ledger knows nothing about

    result = _engine(store, audit, ledger=DelegationLedger()).conflicts()
    lineage = [f for f in result["findings"] if f["kind"] == "unauthorized_lineage"]

    assert lineage, "a claimed edge with no recorded authority must be reported"
    detail = lineage[0]["detail"]
    assert "NOT CORROBORATED" in detail
    assert "not proof" in detail, "the finding must not overstate itself as disproof"


def test_a_corroborated_edge_produces_no_lineage_finding(store, audit) -> None:
    """Non-vacuity in the other direction: with the authority recorded, there is nothing to report,
    or the finding would fire on every healthy delegation in the fleet."""
    ledger = DelegationLedger()
    a = _act(audit, "a1")
    ledger.record(str(a.id), Authority(agent_id="a1", trust=0.5, scope=ALL, ring=0))
    _act(audit, "a2", parent=a.id)

    result = _engine(store, audit, ledger=ledger).conflicts()

    assert [f for f in result["findings"] if f["kind"] == "unauthorized_lineage"] == []


def test_divergent_paths_to_one_agent_are_flagged(store, audit) -> None:
    """Two routes conferring different effective scope means what the agent may do depends on which
    route a caller took — not a permission model anyone can reason about."""
    left = _act(audit, "wide-root")
    right = _act(audit, "narrow-root")
    _act(audit, "shared", parent=left.id)
    _act(audit, "shared", parent=right.id)
    scopes = _Scopes(
        {"wide-root": {"read", "write"}, "narrow-root": {"read"}, "shared": {"read", "write"}}
    )

    result = _engine(store, audit, scopes=scopes).conflicts()

    assert [f for f in result["findings"] if f["kind"] == "divergent_paths"]


def test_a_finding_denies_nothing(store, audit) -> None:
    """SPEC D-4. POL-11 says "flags". An engine that denied on its own authority would be a second
    enforcer beside the constitution — exactly what ECON-02 was written to avoid.

    Structural: this module must not import the pipeline's decision machinery or raise a governance
    exception, because either would be the first step toward deciding.
    """
    import inspect

    import agentos_controlplane.conflicts as mod

    src = inspect.getsource(mod)
    assert "GovernanceDenied" not in src
    assert "Outcome." not in src
    assert "raise" not in src.replace("raise the", "")


def test_the_findings_read_is_bounded(store, audit) -> None:
    """A fan-out explodes the finding count long before any depth cap is reached."""
    a = _act(audit, "root")
    for i in range(40):
        _act(audit, f"child-{i}", parent=a.id)

    result = _engine(store, audit, ledger=DelegationLedger()).conflicts(limit=5)

    assert len(result["findings"]) <= 5
    assert result["truncated"] is True


def test_no_scope_lookup_reports_structure_without_inventing_capabilities(store, audit) -> None:
    """Absent a scope source, the wildcard is what we know. Substituting the empty set would report
    every capability as lost by every chain — a fleet-wide false alarm from a missing collaborator."""
    a = _act(audit, "root")
    b = _act(audit, "leaf", parent=a.id)

    closure = _engine(store, audit).closure(str(b.id))

    assert closure["effective_scope"] == [WILDCARD]
    assert closure["agents"] == ["root", "leaf"]
