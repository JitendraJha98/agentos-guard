"""AUD-05 checkpoint primitives + LocalEd25519Anchor + ChainCheckpoint model.

The offline core: checkpoint_message reuses the pinned canonical_json so a verifier
reproduces the anchored bytes byte-identically; LocalEd25519Anchor signs them with the
control-plane key (durability-only — proves the mechanism + powers deterministic tests);
verify_checkpoint_proof round-trips, catches tamper / wrong-domain, and SKIPS (raises
CheckpointVerifyUnavailable) when the verification material is absent.
"""

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import canonical_json
from agentos_controlplane.checkpoint import (
    CHECKPOINT_DOMAIN,
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
