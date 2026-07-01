"""AUD-05 — the verifier validates checkpoint anchors + detects truncation (Slice 4c).

These prove the checkpoint catches the one tamper class Slice 4b alone CANNOT: a FULL
CONSISTENT REWRITE where the attacker (with DB write but NO control-plane private key... or
WITH it, since the local anchor shares the key — see below) recomputes every record_hash and
re-links prev_hash so the chain is INTERNALLY valid. The checkpoint binds the OLD head hash to
an external proof; the rewritten head no longer matches -> checkpoint_mismatch.

Offline + deterministic via LocalEd25519Anchor. NOTE: LocalEd25519Anchor is durability-only
(same key as the chain), so to model the rewrite we deliberately do NOT re-anchor — we keep the
OLD checkpoint, which is exactly what an after-the-fact rewrite of already-checkpointed history
leaves behind. (Against the real Rfc3161Anchor the attacker cannot re-anchor at all, since they
lack the TSA key — the honest external-authority case.)
"""

import asyncio
import hashlib

from sqlalchemy import create_engine, select, update

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import SIG_DOMAIN, AuditWriter, canonical_json
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.checkpoint import (
    CheckpointService,
    LocalEd25519Anchor,
)
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, ChainCheckpoint


def _signed_chain(n=3):
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    sign = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    w = AuditWriter(sf, signer=sign)
    for _ in range(n):
        a = AgentAction(
            agent_id="a",
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com"},
        )
        asyncio.run(w.append(a, Decision(action_id=a.id, outcome=Outcome.allow)))
    return sf, sign


def _checkpoint(sf, sign):
    return CheckpointService(sf, LocalEd25519Anchor(sign)).checkpoint()


def test_clean_chain_with_checkpoint_verifies():
    sf, sign = _signed_chain(3)
    _checkpoint(sf, sign)
    r = verify_chain(sf, public_key_pem=sign.public_key_pem)
    assert r.ok and r.records_checked == 3
    assert r.checkpoints_checked == 1 and r.skipped_checkpoints == 0


def test_full_consistent_rewrite_caught_by_checkpoint_mismatch():
    # THE 4c-only defense. Rewrite seq 1's body AND recompute ALL downstream hashes + prev_hash
    # links so the chain is INTERNALLY valid end-to-end (steps 3/4/5 would all pass). We re-sign
    # too (the local anchor shares the key, modelling the worst case: a fully consistent, signed
    # rewrite). Slice 4b passes this. The OLD checkpoint binds the ORIGINAL head hash -> mismatch.
    sf, sign = _signed_chain(3)
    _checkpoint(sf, sign)  # binds the ORIGINAL seq-2 head

    with sf() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()
        prev = None
        for row in rows:
            body = dict(row.body)
            if row.seq == 1:
                body["outcome"] = "deny"  # the rewrite
            body["prev_hash"] = prev
            canonical = canonical_json(body)
            new_hash = hashlib.sha256(canonical).hexdigest()
            new_sig = sign.sign_record(SIG_DOMAIN + canonical).hex()
            s.execute(
                update(AuditRecord)
                .where(AuditRecord.seq == row.seq)
                .values(body=body, record_hash=new_hash, prev_hash=prev, signature=new_sig)
            )
            prev = new_hash
        s.commit()

    # Sanity: the rewritten chain is internally consistent — 4b's per-row checks ALL pass.
    # Only the checkpoint catches it.
    r = verify_chain(sf, public_key_pem=sign.public_key_pem)
    assert not r.ok
    assert r.violation.check == "checkpoint_mismatch"
    assert r.violation.seq == 2  # the checkpointed head seq


def test_truncation_below_checkpoint_caught():
    # Delete the checkpointed head (and tail) so the chain is shorter than a checkpointed seq.
    sf, sign = _signed_chain(3)
    _checkpoint(sf, sign)  # checkpoints seq 2
    with sf() as s:
        s.execute(AuditRecord.__table__.delete().where(AuditRecord.seq == 2))
        s.commit()
    r = verify_chain(sf, public_key_pem=sign.public_key_pem)
    assert not r.ok and r.violation.check == "checkpoint_truncation" and r.violation.seq == 2


def test_corrupted_checkpoint_proof_caught():
    sf, sign = _signed_chain(3)
    cp = _checkpoint(sf, sign)
    with sf() as s:
        s.execute(
            update(ChainCheckpoint)
            .where(ChainCheckpoint.id == cp.id)
            .values(proof=b"\x00" * len(cp.proof))
        )
        s.commit()
    r = verify_chain(sf, public_key_pem=sign.public_key_pem)
    assert not r.ok and r.violation.check == "checkpoint_proof" and r.violation.seq == 2


def _self_signed_root_pem():
    """A throwaway valid self-signed cert PEM so the rfc3161 verify path reaches the DER
    decode rather than failing to load the root. The garbage proof never authenticates."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-root")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1))
        .not_valid_after(datetime.datetime(2030, 1, 1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)


def test_malformed_rfc3161_proof_caught_as_checkpoint_proof_not_crash():
    # An insider corrupts an rfc3161_v1 checkpoint's stored DER proof with garbage. The DER
    # decode raises ValueError (ASN.1 parse error), NOT VerificationError — the verifier must
    # turn it into a clean 'checkpoint_proof' violation (mirroring the 4b malformed-hex fix),
    # not crash with an uncaught traceback. End-to-end through verify_chain with --tsa-root.
    sf, sign = _signed_chain(3)
    cp = _checkpoint(sf, sign)  # checkpoints seq 2
    with sf() as s:
        s.execute(
            update(ChainCheckpoint)
            .where(ChainCheckpoint.id == cp.id)
            .values(anchor_kind="rfc3161_v1", proof=b"garbage")
        )
        s.commit()
    r = verify_chain(
        sf, public_key_pem=sign.public_key_pem, tsa_root_pem=_self_signed_root_pem()
    )
    assert not r.ok and r.violation.check == "checkpoint_proof" and r.violation.seq == 2


def test_checkpoint_skipped_when_pubkey_absent_not_a_false_fail():
    # A local_ed25519_v1 checkpoint needs the control-plane pubkey to verify. Without it the
    # verifier must SKIP it (surfaced as a skip count), NOT crash and NOT false-fail.
    sf, sign = _signed_chain(3)
    _checkpoint(sf, sign)
    r = verify_chain(sf)  # no pubkey -> per-row sig step skipped AND checkpoint skipped
    assert r.ok and r.records_checked == 3
    assert r.skipped_checkpoints == 1 and r.checkpoints_checked == 0
