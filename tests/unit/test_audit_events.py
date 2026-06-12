"""Lifecycle audit events share the ONE hash chain (6a-2).

`AuditWriter.append_event(kind, body)` writes an AuditRecord through the SAME
lock / seq / prev_hash discipline as action records — interleaving an event
between two action appends keeps the chain continuous, and the record hash
covers `kind` (so an event's kind cannot be silently rewritten). Event kinds
are allowlisted: an unknown kind raises and writes nothing.
"""

import asyncio
import hashlib

import pytest
from sqlalchemy import create_engine, func, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

EVENT_KINDS = (
    "approval_resolved",
    "approval_timed_out",
    "exception_granted",
    "review_opened",
    "enforcement_substitution",
    "side_effect",
)


@pytest.fixture
def audit_writer() -> AuditWriter:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return AuditWriter(create_session_factory(engine))


def _action() -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""},
    )


def _decision(action: AgentAction) -> Decision:
    return Decision(action_id=action.id, outcome=Outcome.allow)


def _rows(audit_writer: AuditWriter) -> list[AuditRecord]:
    with audit_writer.session_factory() as session:
        return list(session.scalars(select(AuditRecord).order_by(AuditRecord.seq)))


def test_event_chains_between_action_records(audit_writer: AuditWriter) -> None:
    """action record -> event -> action record: seq/prev_hash continuity holds."""
    a1, a2 = _action(), _action()
    asyncio.run(audit_writer.append(a1, _decision(a1)))
    event_id = asyncio.run(
        audit_writer.append_event(
            "approval_resolved",
            {"approval_id": "abc", "approved": True, "resolver": "op@example.com"},
        )
    )
    asyncio.run(audit_writer.append(a2, _decision(a2)))

    rows = _rows(audit_writer)
    assert [r.seq for r in rows] == [0, 1, 2]
    assert rows[0].prev_hash is None
    assert rows[1].prev_hash == rows[0].record_hash  # event links INTO the chain
    assert rows[2].prev_hash == rows[1].record_hash  # and the chain links back OUT
    assert rows[1].id == event_id
    assert rows[1].body["kind"] == "approval_resolved"
    assert rows[1].body["approved"] is True


def test_event_hash_covers_kind(audit_writer: AuditWriter) -> None:
    """record_hash == sha256(canonical_json(body)) and the body carries `kind` —
    rewriting the kind would break the hash (tamper-evidence covers the kind)."""
    asyncio.run(audit_writer.append_event("review_opened", {"review_id": "r1"}))
    row = _rows(audit_writer)[0]
    assert row.body["kind"] == "review_opened"
    assert (
        row.record_hash
        == hashlib.sha256(canonical_json(row.body)).hexdigest()
    )
    tampered = dict(row.body, kind="side_effect")
    assert hashlib.sha256(canonical_json(tampered)).hexdigest() != row.record_hash


@pytest.mark.parametrize("kind", EVENT_KINDS)
def test_all_lifecycle_kinds_accepted(audit_writer: AuditWriter, kind: str) -> None:
    asyncio.run(audit_writer.append_event(kind, {"ref": "x"}))
    assert _rows(audit_writer)[-1].body["kind"] == kind


@pytest.mark.parametrize("reserved", ["seq", "prev_hash", "kind"])
def test_reserved_body_key_raises_and_writes_nothing(
    audit_writer: AuditWriter, reserved: str
) -> None:
    """A body key shadowing the chain fields would silently overwrite what the
    hash is supposed to cover — rejected fail-closed, nothing written."""
    with pytest.raises(ValueError):
        asyncio.run(audit_writer.append_event("side_effect", {reserved: "shadow"}))
    with audit_writer.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AuditRecord)) == 0


def test_unknown_kind_raises_and_writes_nothing(audit_writer: AuditWriter) -> None:
    with pytest.raises(ValueError):
        asyncio.run(audit_writer.append_event("made_up_kind", {"ref": "x"}))
    with audit_writer.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AuditRecord)) == 0


def test_second_writer_on_same_store_fails_closed(audit_writer: AuditWriter) -> None:
    """One-writer-per-store discipline: a second AuditWriter's stale cached head
    collides with the UNIQUE seq constraint -> IntegrityError, never a silent
    chain fork (two records at one seq)."""
    from sqlalchemy.exc import IntegrityError

    second = AuditWriter(audit_writer.session_factory)
    asyncio.run(audit_writer.append_event("side_effect", {"ref": "a"}))  # seq 0; caches head
    asyncio.run(second.append_event("side_effect", {"ref": "b"}))        # fresh SELECT -> seq 1
    with pytest.raises(IntegrityError):  # first writer's stale cache -> seq 1 collision
        asyncio.run(audit_writer.append_event("side_effect", {"ref": "c"}))
    with audit_writer.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(AuditRecord)) == 2
