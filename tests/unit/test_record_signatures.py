"""Per-record EdDSA audit signatures + canonicalization pin — AUD-08 (Slice 4a).

Each AuditRecord carries a detached Ed25519 signature over
SIG_DOMAIN + canonical_json(body) — the SAME canonical bytes that are hashed
into record_hash. The signature proves the control plane authored the decision,
verifiable on a single record independent of the chain links. The signing key is
the control-plane keypair already held in IdentityEngine; the private key never
leaves the engine. Domain separation prevents an audit signature from being
replayed as an agent JWT (the same key signs both).
"""

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from agentos_controlplane.identity_engine import IdentityEngine


def _engine() -> IdentityEngine:
    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)


# --- Task 1: IdentityEngine.sign_record + public_key_id ---------------------


def test_sign_record_roundtrips_with_public_key():
    eng = _engine()
    data = b"agentos-guard/audit-record/v1\x00{\"seq\":0}"
    sig = eng.sign_record(data)
    assert isinstance(sig, bytes) and len(sig) == 64
    pub = load_pem_public_key(eng.public_key_pem.encode())
    pub.verify(sig, data)  # raises InvalidSignature on failure


def test_signature_is_message_bound():
    eng = _engine()
    sig = eng.sign_record(b"message-A")
    pub = load_pem_public_key(eng.public_key_pem.encode())
    with pytest.raises(InvalidSignature):
        pub.verify(sig, b"message-B")


def test_public_key_id_stable_16_hex():
    eng = _engine()
    kid = eng.public_key_id
    assert kid == eng.public_key_id and len(kid) == 16 and all(
        c in "0123456789abcdef" for c in kid
    )


# --- Task 2: AuditRecord signature + signing_key_id columns (both nullable) --


def _store():
    from sqlalchemy import create_engine

    from agentos_controlplane.store.engine import create_all, create_session_factory

    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def test_audit_record_persists_signature_columns():
    from agentos_controlplane.store.models import AuditRecord

    sf = _store()
    with sf() as session:
        rec = AuditRecord(
            seq=0,
            prev_hash=None,
            record_hash="deadbeef",
            body={"seq": 0},
            signature="ab" * 64,
            signing_key_id="0123456789abcdef",
        )
        session.add(rec)
        session.commit()
        loaded = session.get(AuditRecord, rec.id)
        assert loaded.signature == "ab" * 64
        assert loaded.signing_key_id == "0123456789abcdef"


def test_audit_record_signature_columns_nullable():
    from agentos_controlplane.store.models import AuditRecord

    sf = _store()
    with sf() as session:
        rec = AuditRecord(seq=0, prev_hash=None, record_hash="deadbeef", body={"seq": 0})
        session.add(rec)
        session.commit()
        loaded = session.get(AuditRecord, rec.id)
        assert loaded.signature is None
        assert loaded.signing_key_id is None


# --- Task 3: AuditWriter signs each record + verify_record_signature ---------


def _action():
    from agentos_contract import ActionType, AgentAction

    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": "hello"},
    )


def _decision(action):
    from agentos_contract import Decision, Outcome

    return Decision(action_id=action.id, outcome=Outcome.allow)


def _rows(writer):
    from sqlalchemy import select

    from agentos_controlplane.store.models import AuditRecord

    with writer.session_factory() as session:
        return list(session.scalars(select(AuditRecord).order_by(AuditRecord.seq)))


def test_append_signs_record_and_verifies():
    import asyncio

    from agentos_controlplane.audit import (
        AuditWriter,
        canonical_json,
        verify_record_signature,
    )

    eng = _engine()
    writer = AuditWriter(_store(), signer=eng)
    a = _action()
    asyncio.run(writer.append(a, _decision(a)))
    (row,) = _rows(writer)
    assert row.signature is not None
    assert row.signing_key_id == eng.public_key_id
    assert verify_record_signature(
        eng.public_key_pem, bytes.fromhex(row.signature), canonical_json(row.body)
    )


def test_tampered_body_fails_verification():
    import asyncio

    from agentos_controlplane.audit import (
        AuditWriter,
        canonical_json,
        verify_record_signature,
    )

    eng = _engine()
    writer = AuditWriter(_store(), signer=eng)
    a = _action()
    asyncio.run(writer.append(a, _decision(a)))
    (row,) = _rows(writer)
    tampered = dict(row.body)
    tampered["outcome"] = "deny"  # flip the decision
    assert not verify_record_signature(
        eng.public_key_pem, bytes.fromhex(row.signature), canonical_json(tampered)
    )


def test_domain_prefix_is_load_bearing():
    """A signature over the domain-prefixed body must NOT verify against the bare body."""
    import asyncio

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    from agentos_controlplane.audit import AuditWriter, canonical_json

    eng = _engine()
    writer = AuditWriter(_store(), signer=eng)
    a = _action()
    asyncio.run(writer.append(a, _decision(a)))
    (row,) = _rows(writer)
    pub = load_pem_public_key(eng.public_key_pem.encode())
    with pytest.raises(InvalidSignature):
        pub.verify(bytes.fromhex(row.signature), canonical_json(row.body))  # no SIG_DOMAIN


def test_append_event_is_signed():
    import asyncio

    from agentos_controlplane.audit import (
        AuditWriter,
        canonical_json,
        verify_record_signature,
    )

    eng = _engine()
    writer = AuditWriter(_store(), signer=eng)
    asyncio.run(
        writer.append_event("approval_resolved", {"approval_id": "abc", "status": "approved"})
    )
    (row,) = _rows(writer)
    assert row.signature is not None
    assert row.signing_key_id == eng.public_key_id
    assert verify_record_signature(
        eng.public_key_pem, bytes.fromhex(row.signature), canonical_json(row.body)
    )


def test_no_signer_leaves_signature_null():
    import asyncio

    from agentos_controlplane.audit import AuditWriter

    writer = AuditWriter(_store())  # no signer -> backward compat
    a = _action()
    asyncio.run(writer.append(a, _decision(a)))
    (row,) = _rows(writer)
    assert row.signature is None
    assert row.signing_key_id is None
