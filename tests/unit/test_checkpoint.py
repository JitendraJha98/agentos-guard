"""AUD-05 checkpoint primitives + LocalEd25519Anchor + ChainCheckpoint model.

The offline core: checkpoint_message reuses the pinned canonical_json so a verifier
reproduces the anchored bytes byte-identically; LocalEd25519Anchor signs them with the
control-plane key (durability-only — proves the mechanism + powers deterministic tests);
verify_checkpoint_proof round-trips, catches tamper / wrong-domain, and SKIPS (raises
CheckpointVerifyUnavailable) when the verification material is absent.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.checkpoint import (
    CHECKPOINT_DOMAIN,
    CheckpointService,
    CheckpointVerifyUnavailable,
    LocalEd25519Anchor,
    checkpoint_message,
    verify_checkpoint_proof,
)
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import ChainCheckpoint


def _engine():
    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)


def _signed_chain(n=3):
    """Build a real signed chain of `n` records; return (session_factory, IdentityEngine)."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    sign = _engine()
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


def test_checkpoint_message_reuses_canonical_json():
    # The anchored bytes ARE the pinned canonical_json of {seq, record_hash}, so an
    # independent verifier reproduces them exactly (the canonicalization-pin invariant).
    msg = checkpoint_message(7, "abc123")
    assert msg == canonical_json({"record_hash": "abc123", "seq": 7})


def test_local_anchor_round_trips_through_verify():
    eng = _engine()
    anchor = LocalEd25519Anchor(eng)
    msg = checkpoint_message(3, "deadbeef")
    proof = anchor.anchor(msg)
    assert anchor.kind == "local_ed25519_v1"
    assert verify_checkpoint_proof(
        "local_ed25519_v1", proof, msg, public_key_pem=eng.public_key_pem
    ) is True


def test_local_anchor_tampered_message_fails():
    eng = _engine()
    proof = LocalEd25519Anchor(eng).anchor(checkpoint_message(3, "deadbeef"))
    # Verify the SAME proof against a DIFFERENT message -> invalid signature -> False.
    tampered = checkpoint_message(3, "cafebabe")
    assert verify_checkpoint_proof(
        "local_ed25519_v1", proof, tampered, public_key_pem=eng.public_key_pem
    ) is False


def test_local_anchor_wrong_domain_fails():
    # The anchor signs CHECKPOINT_DOMAIN + message. A raw Ed25519 sig over the message
    # WITHOUT the domain prefix must not verify (domain separation from audit-record sigs).
    eng = _engine()
    msg = checkpoint_message(3, "deadbeef")
    no_domain_sig = eng.sign_record(msg)  # signs `msg` directly, NOT CHECKPOINT_DOMAIN + msg
    assert verify_checkpoint_proof(
        "local_ed25519_v1", no_domain_sig, msg, public_key_pem=eng.public_key_pem
    ) is False
    # Sanity: it WOULD verify if the prefix were included (the domain is exactly the difference).
    domain_sig = eng.sign_record(CHECKPOINT_DOMAIN + msg)
    assert verify_checkpoint_proof(
        "local_ed25519_v1", domain_sig, msg, public_key_pem=eng.public_key_pem
    ) is True


def test_missing_pubkey_raises_verify_unavailable():
    eng = _engine()
    proof = LocalEd25519Anchor(eng).anchor(checkpoint_message(3, "deadbeef"))
    with pytest.raises(CheckpointVerifyUnavailable):
        verify_checkpoint_proof(
            "local_ed25519_v1", proof, checkpoint_message(3, "deadbeef"), public_key_pem=None
        )


def test_unknown_kind_raises_verify_unavailable():
    with pytest.raises(CheckpointVerifyUnavailable):
        verify_checkpoint_proof("not_a_kind", b"x", b"y", public_key_pem="pem")


def _self_signed_root_pem():
    """A throwaway self-signed cert PEM — valid x509 so the rfc3161 path reaches the DER
    decode (not the load_pem_x509_certificate). The garbage proof never authenticates against
    it; this only exercises the malformed-DER decode branch."""
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


@pytest.mark.parametrize("proof", [b"garbage", b"", b"\x30\x82\x01"], ids=["garbage", "empty", "truncated"])
def test_rfc3161_malformed_proof_returns_false_not_crash(proof):
    # A malformed/truncated/garbage DER token makes decode_timestamp_response raise ValueError
    # (ASN.1 parse error) — which is NOT a VerificationError. The verifier must turn that into a
    # clean False (a defined 'checkpoint_proof' violation), mirroring the 4b malformed-hex fix,
    # never an uncaught crash.
    assert (
        verify_checkpoint_proof(
            "rfc3161_v1", proof, checkpoint_message(1, "abc"), tsa_root_pem=_self_signed_root_pem()
        )
        is False
    )


def test_chain_checkpoint_row_round_trips_on_sqlite():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    with sf() as s:
        s.add(
            ChainCheckpoint(
                seq=5,
                record_hash="abc",
                anchor_kind="local_ed25519_v1",
                proof=b"\x00\x01\x02",
                tsa_url=None,
            )
        )
        s.commit()
    with sf() as s:
        row = s.scalars(select(ChainCheckpoint)).one()
        assert row.seq == 5
        assert row.record_hash == "abc"
        assert row.anchor_kind == "local_ed25519_v1"
        assert row.proof == b"\x00\x01\x02"
        assert row.tsa_url is None
        assert row.id is not None
        assert row.created_at is not None


def test_checkpoint_service_anchors_the_head():
    sf, sign = _signed_chain(3)
    row = CheckpointService(sf, LocalEd25519Anchor(sign)).checkpoint()
    # The checkpoint binds the CURRENT head (seq 2 on a 3-record chain).
    head = sf().scalars(select(ChainCheckpoint).order_by(ChainCheckpoint.seq.desc())).first()
    assert head is not None
    assert row.seq == 2
    assert row.anchor_kind == "local_ed25519_v1"
    assert row.tsa_url is None
    # The stored proof verifies over the head's checkpoint_message.
    msg = checkpoint_message(row.seq, row.record_hash)
    assert verify_checkpoint_proof(
        "local_ed25519_v1", row.proof, msg, public_key_pem=sign.public_key_pem
    ) is True


def test_checkpoint_service_binds_actual_head_record_hash():
    # The bound record_hash equals the actual head row's record_hash (not a stale/wrong one).
    sf, sign = _signed_chain(3)
    from agentos_controlplane.store.models import AuditRecord

    with sf() as s:
        head = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).first()
        head_seq, head_hash = head.seq, head.record_hash
    row = CheckpointService(sf, LocalEd25519Anchor(sign)).checkpoint()
    assert row.seq == head_seq and row.record_hash == head_hash


def test_checkpoint_empty_chain_raises():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    with pytest.raises(ValueError):
        CheckpointService(sf, LocalEd25519Anchor(_engine())).checkpoint()
