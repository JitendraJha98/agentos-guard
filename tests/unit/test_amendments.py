"""POL-10 — the Constitution as an amendable governing document.

The load-bearing test is that a PENDING amendment changes no decision. Without it the ratification
step is decorative, and an agent could rewrite the rules governing it by proposing them — which is
POL-13's shape (recommend, never grant) applied to the document itself.
"""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.amendments import PROPOSED, RATIFIED, REJECTED, AmendmentStore
from agentos_controlplane.approvals import AlreadyResolvedError
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.resources import ConstitutionError, ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import Amendment, AuditRecord, ConstitutionResource


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
def resources(store) -> ResourceStore:
    return ResourceStore(store)


@pytest.fixture
def amendments(store, resources) -> AmendmentStore:
    return AmendmentStore(store, AuditWriter(store), resources)


def _constitution(host: str = "api.example.com") -> dict:
    """A minimal valid constitution, parameterised so two proposals differ by content hash."""
    return {
        "schema_version": 1,
        "name": "test",
        "lists": {"egress_allowlist": [host]},
        "principles": [
            {
                "id": "1.1",
                "title": "Egress allowlist",
                "statement": "An agent may only call allowlisted hosts.",
                "applies_to": ["tool_call"],
                "effect": "deny",
                "when": {"field": "egress.host", "op": "not_in", "list_ref": "egress_allowlist"},
            }
        ],
    }


# --- proposal ------------------------------------------------------------------


def test_an_agent_may_propose(store, amendments) -> None:
    """POL-10 says "agents or the self-play trainer" — proposing is the half an agent is meant to do."""
    aid = asyncio.run(amendments.propose("widen egress", "we need it", "agent-1", _constitution()))

    row = amendments.get(aid)
    assert row.status == PROPOSED and row.proposed_by == "agent-1"
    assert row.ratified_by is None and row.constitution_version is None


def test_a_PENDING_amendment_produces_no_constitution_version(store, amendments) -> None:
    """THE property of this slice, at the storage layer: proposing writes no constitution.

    If a proposal took effect before ratification the review step would be decorative, and an agent
    could rewrite the rules governing it simply by asking.
    """
    asyncio.run(amendments.propose("permissive", "because", "agent-1", _constitution("evil.test")))

    with store() as s:
        assert s.scalars(select(ConstitutionResource)).all() == []


def test_an_amendment_that_does_not_compile_is_refused_at_PROPOSAL(store, amendments) -> None:
    """The error belongs in front of the proposer, who can fix it — not the ratifier, who cannot."""
    with pytest.raises(ConstitutionError):
        asyncio.run(amendments.propose("broken", "r", "agent-1", {"nonsense": True}))

    with store() as s:
        assert s.scalars(select(Amendment)).all() == [], "a refused proposal must write no row"


def test_an_unattributed_proposal_is_refused(store, amendments) -> None:
    with pytest.raises(ValueError, match="proposed_by"):
        asyncio.run(amendments.propose("t", "r", "  ", _constitution()))


def test_an_over_long_title_is_refused(store, amendments) -> None:
    """Bounded operator/agent input, like every other model in this API."""
    with pytest.raises(ValueError, match="title"):
        asyncio.run(amendments.propose("x" * 300, "r", "agent-1", _constitution()))


# --- ratification --------------------------------------------------------------


def test_ratifying_produces_a_new_constitution_version_and_records_it(store, amendments) -> None:
    aid = asyncio.run(amendments.propose("v2", "reason", "agent-1", _constitution("b.test")))

    version = asyncio.run(amendments.ratify(aid, "operator-jane", note="looks right"))

    row = amendments.get(aid)
    assert row.status == RATIFIED and row.ratified_by == "operator-jane"
    assert row.constitution_version == version
    with store() as s:
        assert [c.version for c in s.scalars(select(ConstitutionResource)).all()] == [version]


def test_the_previous_constitution_text_survives_ratification(store, amendments, resources) -> None:
    """"Versioned like a legal document" is mostly about what does NOT happen: the old text stays
    readable. POL-08 pins constitution_version on every Decision, so an audited decision is only
    explicable while the text that evaluated it still exists."""
    first, _ = resources.apply_constitution("test", _constitution("first.test"))
    aid = asyncio.run(amendments.propose("v2", "r", "agent-1", _constitution("second.test")))

    second = asyncio.run(amendments.ratify(aid, "operator-jane"))

    assert second != first.version
    assert resources.get_constitution(first.version) is not None, "the prior text must remain"


def test_ratification_requires_a_named_human(store, amendments) -> None:
    """An amendment with no ratifier named is not human-ratified, whatever the status column says —
    and "human-ratified" is the entire claim POL-10 makes about this transition."""
    aid = asyncio.run(amendments.propose("t", "r", "agent-1", _constitution("c.test")))

    with pytest.raises(ValueError, match="ratified_by"):
        asyncio.run(amendments.ratify(aid, "   "))

    assert amendments.get(aid).status == PROPOSED, "a refused ratification must not resolve it"


def test_a_resolved_amendment_cannot_be_resolved_again(store, amendments) -> None:
    aid = asyncio.run(amendments.propose("t", "r", "agent-1", _constitution("d.test")))
    asyncio.run(amendments.ratify(aid, "operator-jane"))

    with pytest.raises(AlreadyResolvedError):
        asyncio.run(amendments.ratify(aid, "operator-bob"))
    with pytest.raises(AlreadyResolvedError):
        asyncio.run(amendments.resolve_without_ratifying(aid, REJECTED, "operator-bob"))


def test_an_unknown_amendment_raises_rather_than_silently_doing_nothing(store, amendments) -> None:
    with pytest.raises(KeyError):
        asyncio.run(amendments.ratify(uuid4(), "operator-jane"))


# --- rejection -----------------------------------------------------------------


def test_a_rejected_amendment_touches_no_constitution_version(store, amendments) -> None:
    """Claiming a version for an amendment that never took effect would attribute a constitution to
    a proposal nobody accepted."""
    aid = asyncio.run(amendments.propose("no", "r", "agent-1", _constitution("e.test")))

    asyncio.run(amendments.resolve_without_ratifying(aid, REJECTED, "operator-jane", note="no"))

    row = amendments.get(aid)
    assert row.status == REJECTED and row.constitution_version is None
    with store() as s:
        assert s.scalars(select(ConstitutionResource)).all() == []


def test_an_invalid_resolution_status_is_refused(store, amendments) -> None:
    """`ratify` is the only path to RATIFIED — this method must not become a second one."""
    aid = asyncio.run(amendments.propose("t", "r", "agent-1", _constitution("f.test")))

    with pytest.raises(ValueError, match="status must be"):
        asyncio.run(amendments.resolve_without_ratifying(aid, RATIFIED, "operator-jane"))


# --- the audit trail -----------------------------------------------------------


def test_both_transitions_are_audited(store, amendments) -> None:
    aid = asyncio.run(amendments.propose("t", "r", "agent-1", _constitution("g.test")))
    asyncio.run(amendments.ratify(aid, "operator-jane"))

    with store() as s:
        kinds = [r.body.get("kind") for r in s.scalars(select(AuditRecord)).all()]
    assert "amendment_proposed" in kinds and "amendment_resolved" in kinds


def test_the_audit_body_carries_no_proposed_document(store, amendments) -> None:
    """Short identifiers only. The proposed text already has a row, can be arbitrarily large, and
    putting it in the hash chain would bloat every verification pass for no gain."""
    asyncio.run(
        amendments.propose("t", "r", "agent-1", _constitution("CANARY-HOST.example"))
    )

    with store() as s:
        blob = json.dumps([r.body for r in s.scalars(select(AuditRecord)).all()])
    assert "CANARY-HOST" not in blob


# --- history -------------------------------------------------------------------


def test_history_names_the_amendment_behind_a_ratified_version(store, amendments) -> None:
    aid = asyncio.run(amendments.propose("v2", "r", "agent-1", _constitution("h.test")))
    version = asyncio.run(amendments.ratify(aid, "operator-jane"))

    entry = next(e for e in amendments.constitution_history() if e["version"] == version)

    assert entry["amendment"]["id"] == aid
    assert entry["amendment"]["ratified_by"] == "operator-jane"
    assert entry["amendment"]["proposed_by"] == "agent-1"


def test_a_direct_operator_write_shows_no_amendment_rather_than_a_blank(store, amendments,
                                                                        resources) -> None:
    """A version with no amendment behind it was a direct write — a different act. `null` says that;
    a blank would leave a reader unable to tell "nobody ratified this" from "we lost the record"."""
    direct, _ = resources.apply_constitution("test", _constitution("direct.test"))

    entry = next(e for e in amendments.constitution_history() if e["version"] == direct.version)

    assert entry["amendment"] is None


def test_the_listing_and_history_reads_are_bounded(store, amendments) -> None:
    for i in range(12):
        asyncio.run(amendments.propose(f"t{i}", "r", "agent-1", _constitution(f"h{i}.test")))

    assert len(amendments.list_amendments(limit=5)) == 5
    assert len(amendments.constitution_history(limit=3)) <= 3


def test_the_listing_filters_by_status(store, amendments) -> None:
    keep = asyncio.run(amendments.propose("keep", "r", "agent-1", _constitution("i.test")))
    drop = asyncio.run(amendments.propose("drop", "r", "agent-1", _constitution("j.test")))
    asyncio.run(amendments.resolve_without_ratifying(drop, REJECTED, "operator-jane"))

    pending = amendments.list_amendments(status=PROPOSED)

    assert [a["id"] for a in pending] == [keep]
