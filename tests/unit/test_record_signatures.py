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
