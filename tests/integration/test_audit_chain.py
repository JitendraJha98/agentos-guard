"""AUD-01 / D-15 — hash-chained audit writer with fail-closed redaction.

Behavior (plan 01-02 Task 2):
- appending two decisions yields seq 0 then 1 (strictly monotonic); the second
  record's prev_hash == the first record's record_hash.
- the genesis record has prev_hash NULL.
- record_hash == sha256(canonical_json(body)) recomputed by the test.
- an unclassifiable payload raises and writes NO record (row count unchanged) —
  fail closed.
- a benign allowlisted payload is redacted and written; the stored body NEVER
  contains the raw secret/URL query string.

No Docker (D-14): runs against a SQLite-backed Store; schema created via
Base.metadata.create_all on the SQLite engine. Postgres concurrency /
append-only-trigger validation is deferred to Phase 4.
"""

import asyncio
import hashlib
import json

import pytest
from sqlalchemy import create_engine, func, select

from agentos_contract import AgentAction, ActionType, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter, RedactionError, canonical_json
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord


@pytest.fixture
def audit_writer() -> AuditWriter:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return AuditWriter(create_session_factory(engine))


def _action(url: str = "https://api.example.com/data", content: str = "hello") -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": url, "content": content},
    )


def _decision(action: AgentAction, outcome: Outcome = Outcome.allow) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=outcome,
        risk_score=0.1,
        trust_score=0.5,
        reasons=[Reason(stage="policy", code="egress_allowlisted", policy_id="egress.allow")],
    )


def _rows(audit_writer: AuditWriter) -> list[AuditRecord]:
    with audit_writer.session_factory() as session:
        return list(session.scalars(select(AuditRecord).order_by(AuditRecord.seq)))


def _count(audit_writer: AuditWriter) -> int:
    with audit_writer.session_factory() as session:
        return session.scalar(select(func.count()).select_from(AuditRecord))


def test_monotonic_seq_and_prev_hash_link(audit_writer: AuditWriter) -> None:
    a1 = _action()
    a2 = _action(url="https://api.example.com/other")
    asyncio.run(audit_writer.append(a1, _decision(a1)))
    asyncio.run(audit_writer.append(a2, _decision(a2)))

    rows = _rows(audit_writer)
    assert [r.seq for r in rows] == [0, 1]
    assert rows[0].prev_hash is None  # genesis
    assert rows[1].prev_hash == rows[0].record_hash  # chain link


def test_record_hash_matches_recomputed_canonical(audit_writer: AuditWriter) -> None:
    a1 = _action()
    asyncio.run(audit_writer.append(a1, _decision(a1)))
    row = _rows(audit_writer)[0]
    recomputed = hashlib.sha256(canonical_json(row.body)).hexdigest()
    assert row.record_hash == recomputed


def test_canonical_json_is_reproducible() -> None:
    obj = {"b": 1, "a": 2, "nested": {"y": 1, "x": 2}}
    out = canonical_json(obj)
    assert out == b'{"a":2,"b":1,"nested":{"x":2,"y":1}}'
    assert json.loads(out) == obj


def test_unclassifiable_payload_fails_closed(audit_writer: AuditWriter) -> None:
    bad = AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"mystery_field": "unknown shape the redactor cannot classify"},
    )
    before = _count(audit_writer)
    with pytest.raises(RedactionError):
        asyncio.run(audit_writer.append(bad, _decision(bad)))
    assert _count(audit_writer) == before  # NO record written (fail closed)


def test_redaction_does_not_leak_secret_or_url(audit_writer: AuditWriter) -> None:
    secret_url = "https://api.example.com/data?api_key=SUPER_SECRET_TOKEN_12345"
    secret_content = "the password is hunter2 and the key is SUPER_SECRET_TOKEN_12345"
    a1 = _action(url=secret_url, content=secret_content)
    asyncio.run(audit_writer.append(a1, _decision(a1)))

    stored = json.dumps(_rows(audit_writer)[0].body)
    assert "SUPER_SECRET_TOKEN_12345" not in stored
    assert "hunter2" not in stored
    assert "api_key=" not in stored
    # The redacted form should still carry the (safe) host for forensic value.
    assert "api.example.com" in stored


def test_redaction_strips_url_userinfo_credentials(audit_writer: AuditWriter) -> None:
    """CR-01: embedded `user:password@` credentials must NOT survive redaction.

    `urlsplit(...).netloc` retains userinfo and the port, so reducing a URL to
    scheme+netloc leaked `user:s3cr3t@` into the hash-covered body. The redactor
    must rebuild from `parts.hostname` (no userinfo) — never `netloc`.
    """
    credential_url = "https://user:s3cr3t@evil.example.com:8443/p?token=abc"
    a1 = _action(url=credential_url)
    asyncio.run(audit_writer.append(a1, _decision(a1)))

    stored = json.dumps(_rows(audit_writer)[0].body)
    assert "s3cr3t" not in stored  # password must be gone
    assert "user:" not in stored  # userinfo must be gone
    assert "token=abc" not in stored  # query string must be gone
    # Host (and port) are safe forensic data and should survive.
    assert "evil.example.com" in stored
    assert "8443" in stored
