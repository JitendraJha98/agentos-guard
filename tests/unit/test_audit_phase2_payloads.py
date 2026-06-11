"""Phase 2 redaction (AUD-04 / D-15) — new payload shapes classify, secrets digested.

The Phase-1 redactor only knew {url, content} and failed closed on anything else, which
would have made every model/memory/mcp/delegation record fail to write. The extended
redactor classifies each type's fixed payload: short identifiers kept verbatim,
free-text / secret-bearing fields reduced to a length+SHA-256 digest (never raw).
Still fail-closed: an unknown key writes no record.
"""

import asyncio
import hashlib
import json

import pytest
from sqlalchemy import create_engine, func, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter, RedactionError, canonical_json
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord


@pytest.fixture
def audit_writer() -> AuditWriter:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return AuditWriter(create_session_factory(engine))


def _decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.allow,
        reasons=[Reason(stage="policy", code="no_egress_policy_applicable")],
    )


def _body(audit_writer: AuditWriter) -> dict:
    with audit_writer.session_factory() as session:
        return session.scalars(select(AuditRecord)).first().body


def _count(audit_writer: AuditWriter) -> int:
    with audit_writer.session_factory() as session:
        return session.scalar(select(func.count()).select_from(AuditRecord))


def test_model_payload_redacts_messages_keeps_model(audit_writer: AuditWriter) -> None:
    a = AgentAction(
        agent_id="a", type=ActionType.model_invocation, target="m",
        payload={"model": "claude-opus-4-8", "messages": "my secret is hunter2"},
    )
    asyncio.run(audit_writer.append(a, _decision(a)))
    stored = json.dumps(_body(audit_writer))
    assert "hunter2" not in stored          # free text never persisted raw
    assert "claude-opus-4-8" in stored      # model id kept verbatim (forensic value)
    assert "sha256" in stored               # messages reduced to a digest


def test_memory_payload_redacts_value_keeps_key(audit_writer: AuditWriter) -> None:
    a = AgentAction(
        agent_id="a", type=ActionType.memory_access, target="memory:write",
        payload={"operation": "write", "key": "user_pref", "value": "TOP_SECRET"},
    )
    asyncio.run(audit_writer.append(a, _decision(a)))
    stored = json.dumps(_body(audit_writer))
    assert "TOP_SECRET" not in stored
    assert "user_pref" in stored
    assert "write" in stored


def test_delegation_and_mcp_payloads_classify(audit_writer: AuditWriter) -> None:
    deleg = AgentAction(
        agent_id="a", type=ActionType.delegation, target="worker",
        payload={"to_agent": "worker", "task": "exfiltrate everything"},
    )
    asyncio.run(audit_writer.append(deleg, _decision(deleg)))
    stored = json.dumps(_body(audit_writer))
    assert "worker" in stored
    assert "exfiltrate everything" not in stored  # task is free text -> digested


def test_unknown_key_still_fails_closed(audit_writer: AuditWriter) -> None:
    bad = AgentAction(
        agent_id="a", type=ActionType.mcp_call, target="x",
        payload={"server": "s", "tool": "t", "args": "a", "rogue": "leak"},
    )
    before = _count(audit_writer)
    with pytest.raises(RedactionError):
        asyncio.run(audit_writer.append(bad, _decision(bad)))
    assert _count(audit_writer) == before  # no record written


# --- Slice-3 (PIPE-05 seed): digest keys accept ANY JSON-serializable value ------


def test_non_str_digest_value_digests_canonical_json(audit_writer: AuditWriter) -> None:
    """An mcp_call with structured (dict) args appends; args is a {len, sha256} digest."""
    args = {"count": 5, "filters": ["a", "b"]}
    a = AgentAction(
        agent_id="a", type=ActionType.mcp_call, target="github:list",
        payload={"server": "s", "tool": "t", "args": args},
    )
    asyncio.run(audit_writer.append(a, _decision(a)))
    stored_args = _body(audit_writer)["redacted_payload"]["args"]
    raw = canonical_json(args)
    assert stored_args == {"len": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def test_non_str_content_digest_key_appends(audit_writer: AuditWriter) -> None:
    """A tool_call whose `content` (digest key) is an int still appends — digested."""
    a = AgentAction(
        agent_id="a", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x", "content": 42},
    )
    asyncio.run(audit_writer.append(a, _decision(a)))
    stored = _body(audit_writer)["redacted_payload"]["content"]
    assert set(stored) == {"len", "sha256"}  # digested, never raw


def test_non_str_verbatim_value_still_fails_closed(audit_writer: AuditWriter) -> None:
    """Verbatim keys are identifiers — they must stay strings (fail-closed)."""
    bad = AgentAction(
        agent_id="a", type=ActionType.mcp_call, target="x",
        payload={"server": 5, "tool": "t", "args": "a"},
    )
    before = _count(audit_writer)
    with pytest.raises(RedactionError):
        asyncio.run(audit_writer.append(bad, _decision(bad)))
    assert _count(audit_writer) == before  # no record written
