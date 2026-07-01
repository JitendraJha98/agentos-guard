"""AUD-05 — chain-verifier tamper-class matrix (Slice 4b).

Builds a real SIGNED chain via AuditWriter over an IdentityEngine, then mutates
the DB DIRECTLY (UPDATE/DELETE — simulating an attacker WITHOUT the private key)
and proves each tamper class is caught at the RIGHT check:
  body edit                 -> record_hash
  deleted middle row        -> seq_continuity
  edit + recompute its hash -> prev_hash_linkage on the NEXT row
  corrupted signature       -> signature
  seq column != body.seq    -> seq_continuity (renumber/reorder class)
The verifier re-derives everything from rows + pubkey only; no trusted derived field.
"""

import asyncio
import hashlib

from sqlalchemy import create_engine, select, update

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord


def _signed_chain():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    sign = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    w = AuditWriter(sf, signer=sign)
    for _ in range(3):
        a = AgentAction(
            agent_id="a",
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com"},
        )
        d = Decision(action_id=a.id, outcome=Outcome.allow)
        asyncio.run(w.append(a, d))
    asyncio.run(
        w.append_event(
            "approval_resolved", {"approval_id": "x", "resolver": "op", "approved": True}
        )
    )
    return sf, sign.public_key_pem


def _row(sf, seq):
    with sf() as s:
        return s.scalars(select(AuditRecord).where(AuditRecord.seq == seq)).one()


def test_clean_signed_chain_verifies():
    sf, pub = _signed_chain()
    r = verify_chain(sf, public_key_pem=pub)
    assert r.ok and r.records_checked == 4


def test_body_edit_caught_at_record_hash():
    sf, pub = _signed_chain()
    with sf() as s:  # attacker edits a body field, leaves record_hash
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body)
        body["outcome"] = "deny"
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(body=body))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 1 and r.violation.check == "record_hash"


def test_body_seq_disagreeing_with_column_caught_at_body_column_agreement():
    # Directly exercise step 3 (body<->column agreement): tamper body.seq while leaving
    # the seq COLUMN, so seq_continuity passes and the body/column check fires first.
    sf, pub = _signed_chain()
    with sf() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 2)).one()
        body = dict(row.body)
        body["seq"] = 99
        s.execute(update(AuditRecord).where(AuditRecord.seq == 2).values(body=body))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 2 and r.violation.check == "body_column_agreement"


def test_deleted_middle_row_caught_at_seq_continuity():
    sf, pub = _signed_chain()
    with sf() as s:
        s.execute(AuditRecord.__table__.delete().where(AuditRecord.seq == 1))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.check == "seq_continuity"


def test_edit_plus_rehash_breaks_next_prev_hash():
    # Isolates the HASH-LINK defense: an attacker who edits seq 1's body AND recomputes
    # its record_hash defeats the record_hash check on seq 1, but cannot fix seq 2's
    # prev_hash (it still points at seq 1's ORIGINAL hash) -> caught on the NEXT row.
    # Verified WITHOUT a pubkey so the signature step (which would otherwise fire FIRST
    # on the edited+unre-signable seq 1) is skipped — proving the link check stands alone.
    sf, _pub = _signed_chain()
    with sf() as s:  # edit seq 1 AND recompute its record_hash; leave seq 2's prev_hash
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body)
        body["outcome"] = "deny"
        new_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        s.execute(
            update(AuditRecord)
            .where(AuditRecord.seq == 1)
            .values(body=body, record_hash=new_hash)
        )
        s.commit()
    r = verify_chain(sf)
    assert not r.ok and r.violation.seq == 2 and r.violation.check == "prev_hash_linkage"


def test_edit_plus_rehash_on_signed_chain_caught_at_signature():
    # On a SIGNED chain the SAME edit+rehash is caught one step EARLIER: the attacker
    # has no private key, so seq 1's signature no longer verifies over its new body.
    # First-violation correctly reports seq 1 / signature (before reaching seq 2's link).
    sf, pub = _signed_chain()
    with sf() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body)
        body["outcome"] = "deny"
        new_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        s.execute(
            update(AuditRecord)
            .where(AuditRecord.seq == 1)
            .values(body=body, record_hash=new_hash)
        )
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 1 and r.violation.check == "signature"


def test_corrupted_signature_caught_at_signature_step():
    sf, pub = _signed_chain()
    with sf() as s:  # flip a hex char of seq 2's signature (body untouched)
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 2)).one()
        sig = row.signature
        flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
        s.execute(update(AuditRecord).where(AuditRecord.seq == 2).values(signature=flipped))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 2 and r.violation.check == "signature"


def test_body_column_disagreement_caught():
    sf, pub = _signed_chain()
    with sf() as s:  # change the seq COLUMN but not body.seq
        s.execute(update(AuditRecord).where(AuditRecord.seq == 2).values(seq=99))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok  # caught at seq_continuity (99 != expected 2) — reorder/renumber class


def test_unsigned_chain_still_hash_verifies_without_pubkey():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    w = AuditWriter(sf)  # no signer
    a = AgentAction(
        agent_id="a",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com"},
    )
    asyncio.run(w.append(a, Decision(action_id=a.id, outcome=Outcome.allow)))
    assert verify_chain(sf).ok  # hash chain verifies; signature step skipped (unsigned, no pubkey)


def test_non_hex_signature_caught_as_violation_not_crash():
    # An attacker who can write the DB corrupts a signature column with non-hex bytes.
    # bytes.fromhex would raise ValueError; the verifier must instead return its defined
    # 'signature' violation (the 'return the FIRST violation' contract), never a traceback.
    sf, pub = _signed_chain()
    with sf() as s:
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(signature="zznothex"))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 1 and r.violation.check == "signature"


def test_odd_length_hex_signature_caught_as_violation_not_crash():
    # Odd-length hex ('abc') also raises ValueError in bytes.fromhex -> same contract.
    sf, pub = _signed_chain()
    with sf() as s:
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(signature="abc"))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 1 and r.violation.check == "signature"


def test_signatures_checked_counts_verified_signatures():
    # The strongest defense (signatures) must be observable: a clean signed chain checked
    # WITH the pubkey reports one signature check per row.
    sf, pub = _signed_chain()
    r = verify_chain(sf, public_key_pem=pub)
    assert r.ok and r.records_checked == 4 and r.signatures_checked == 4


def test_signatures_checked_zero_when_pubkey_absent():
    # Verifying a signed chain WITHOUT the key skips step 6 entirely — signatures_checked is 0,
    # the operator-facing signal that the full-rewrite defense did not run.
    sf, _pub = _signed_chain()
    r = verify_chain(sf)
    assert r.ok and r.records_checked == 4 and r.signatures_checked == 0


def test_signatures_checked_zero_when_all_rows_unsigned():
    # Pubkey present but every row unsigned -> step 6 skipped on every row -> 0 checks.
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    w = AuditWriter(sf)  # no signer -> signature IS NULL on every row
    a = AgentAction(
        agent_id="a",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com"},
    )
    asyncio.run(w.append(a, Decision(action_id=a.id, outcome=Outcome.allow)))
    fake_pub = IdentityEngine(
        is_registered=lambda s: True, load_trust=lambda s: 0.5
    ).public_key_pem
    r = verify_chain(sf, public_key_pem=fake_pub)
    assert r.ok and r.records_checked == 1 and r.signatures_checked == 0


def test_decision_record_missing_required_key_caught():
    # AUD-02/03: drop a required decision key (no rehash needed — completeness is step 3b,
    # before record_hash); the verifier flags decision_completeness at that seq.
    sf, pub = _signed_chain()
    with sf() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body)
        del body["policy_version"]
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(body=body))
        s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 1 and r.violation.check == "decision_completeness"


def test_event_record_is_exempt_from_decision_completeness():
    # The append_event record (seq 3, carries 'kind') lacks action_id/outcome but must NOT be
    # flagged — the clean signed chain (which includes that event) verifies cleanly.
    sf, pub = _signed_chain()
    with sf() as s:
        ev = s.scalars(select(AuditRecord).where(AuditRecord.seq == 3)).one()
        assert "kind" in ev.body and "outcome" not in ev.body  # it IS an event record
    assert verify_chain(sf, public_key_pem=pub).ok


def test_decision_body_carries_aud02_aud03_linkage():
    # AUD-02 (action -> decision -> fired principle -> outcome) + AUD-03 (exact versions) are
    # persisted in the hash-covered body of a real decision record.
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    eng = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    w = AuditWriter(sf, signer=eng)
    a = AgentAction(
        agent_id="agent-7",
        type=ActionType.tool_call,
        target="drop_table",
        payload={"url": "https://attacker.example"},
    )
    d = Decision(
        action_id=a.id,
        outcome=Outcome.deny,
        reasons=[
            Reason(
                stage="policy",
                code="constitution_principle_fired",
                principle_ref="1.1",
                rationale="egress not allowlisted",
            )
        ],
        constitution_version="sha256:abc",
        policy_version="sha256:def",
    )
    asyncio.run(w.append(a, d))
    body = _row(sf, 0).body
    assert body["action_id"] == str(a.id) and body["agent_id"] == "agent-7"   # AUD-02 link
    assert body["outcome"] == "deny"                                          # AUD-02 outcome
    assert any(r.get("principle_ref") == "1.1" for r in body["reasons"])       # AUD-02 fired principle
    assert body["constitution_version"] == "sha256:abc"                       # AUD-03 version
    assert body["policy_version"] == "sha256:def"
    assert verify_chain(sf, public_key_pem=eng.public_key_pem).ok
