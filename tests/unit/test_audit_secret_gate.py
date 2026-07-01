"""AUD-04 last gate wired into the writer — fail-closed over the canonical body.

The secret scanner runs in BOTH `append` and `append_event` right after the body is
canonicalized and BEFORE hash/sign/INSERT. A detected secret raises `SecretLeakError` and
writes NOTHING: the row count is unchanged AND the cached chain head is not advanced (the same
fail-closed contract as RedactionError). The load-bearing FP test: a normal tool_call whose
body carries the redactor's own {len, sha256:<64hex>} digest appends fine — the digest must NOT
trip the gate.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, func, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.secret_scan import SecretLeakError
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

_AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"


@pytest.fixture
def audit_writer() -> AuditWriter:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return AuditWriter(create_session_factory(engine))


def _clean_action() -> AgentAction:
    return AgentAction(
        agent_id="a", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x", "content": "some fetched page body"},
    )


def _decision(action: AgentAction, reasons=None) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.allow,
        reasons=reasons if reasons is not None else [Reason(stage="policy", code="ok")],
    )


def _count(audit_writer: AuditWriter) -> int:
    with audit_writer.session_factory() as session:
        return session.scalar(select(func.count()).select_from(AuditRecord))


def test_secret_in_reason_rationale_raises_and_writes_nothing(audit_writer: AuditWriter) -> None:
    """A secret that slipped into a free-text reason field is caught by the last gate."""
    a = _clean_action()
    d = _decision(a, reasons=[Reason(stage="policy", code="x", rationale=f"key is {_AWS_SECRET}")])
    before = _count(audit_writer)
    with pytest.raises(SecretLeakError):
        asyncio.run(audit_writer.append(a, d))
    assert _count(audit_writer) == before  # fail-closed: no record written


def test_secret_leak_does_not_advance_cached_head(audit_writer: AuditWriter) -> None:
    """After a SecretLeakError the cached head is unchanged, so the next clean append is genesis."""
    a = _clean_action()
    leaky = _decision(a, reasons=[Reason(stage="policy", code="x", rationale=_AWS_SECRET)])
    with pytest.raises(SecretLeakError):
        asyncio.run(audit_writer.append(a, leaky))
    assert audit_writer._head is None  # head not advanced by the failed append

    clean = _clean_action()
    asyncio.run(audit_writer.append(clean, _decision(clean)))
    with audit_writer.session_factory() as session:
        rows = list(session.scalars(select(AuditRecord).order_by(AuditRecord.seq)))
    assert [r.seq for r in rows] == [0]
    assert rows[0].prev_hash is None  # genesis — the leaky append left no gap


def test_secret_in_append_event_body_raises_and_writes_nothing(audit_writer: AuditWriter) -> None:
    """append_event is gated too: a resolver note carrying a token writes no record."""
    before = _count(audit_writer)
    with pytest.raises(SecretLeakError):
        asyncio.run(
            audit_writer.append_event(
                "approval_resolved",
                {"approval_id": "abc", "note": f"used token {_AWS_SECRET} to approve"},
            )
        )
    assert _count(audit_writer) == before  # fail-closed: no record written


def test_clean_decision_appends_and_verifies(audit_writer: AuditWriter) -> None:
    """A clean decision passes the gate, is written, and its record_hash recomputes."""
    import hashlib

    a = _clean_action()
    asyncio.run(audit_writer.append(a, _decision(a)))
    with audit_writer.session_factory() as session:
        row = session.scalars(select(AuditRecord)).first()
    assert row is not None
    assert row.record_hash == hashlib.sha256(canonical_json(row.body)).hexdigest()


def test_redactor_digest_does_not_trip_the_gate(audit_writer: AuditWriter) -> None:
    """LOAD-BEARING FP test: a normal tool_call's body carries the redactor's own
    {len, sha256:<64hex>} content digest. That legitimate hex digest must NOT be mistaken
    for a secret — the record appends fine."""
    a = AgentAction(
        agent_id="a", type=ActionType.tool_call, target="http_get",
        # `content` is reduced to {len, sha256:<64hex>} in the body — the FP bait.
        payload={"url": "https://api.example.com/x", "content": "the quick brown fox " * 20},
    )
    asyncio.run(audit_writer.append(a, _decision(a)))
    with audit_writer.session_factory() as session:
        row = session.scalars(select(AuditRecord)).first()
    assert row is not None
    digest = row.body["redacted_payload"]["content"]
    assert set(digest) == {"len", "sha256"}  # the digest is present in the written body
    assert len(digest["sha256"]) == 64       # ...and is the 64-hex that must not trip
