"""AUD-05 — LIVE RFC-3161 timestamp + OFFLINE token verification (Slice 4c).

Network-gated and OPT-IN: skips cleanly unless AGENTOS_RFC3161_LIVE is set, so the default
suite stays offline. Records a real token against a public TSA and verifies it OFFLINE in the
SAME run — no long-term fixture (a stored token would eventually hit the TSA-cert-expiry
caveat). Any network / cert error -> skip, never a hard failure.

The OFFLINE core (checkpoint_message, LocalEd25519Anchor, the verifier's checkpoint validation
+ truncation) is covered deterministically in tests/unit/test_checkpoint.py and
tests/unit/test_audit_verify_checkpoints.py via LocalEd25519Anchor — those need no network. This
test exercises only the real external-authority path (Rfc3161Anchor + offline token verify).
"""

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("AGENTOS_RFC3161_LIVE"),
    reason="set AGENTOS_RFC3161_LIVE=1 to run the live RFC-3161 timestamp test (network)",
)

TSA_URL = "http://timestamp.digicert.com"


def _certifi_roots():
    import certifi
    from cryptography import x509

    pem = open(certifi.where(), "rb").read()
    return x509.load_pem_x509_certificates(pem)


def _root_pem_that_verifies(token: bytes, message: bytes):
    """Find the certifi root under which the live token verifies offline. Returns its PEM or
    None (then the test skips — a transient trust-store/issuer gap is not a code failure)."""
    import hashlib

    from cryptography.hazmat.primitives.serialization import Encoding
    from rfc3161_client import VerificationError, VerifierBuilder, decode_timestamp_response

    ts_response = decode_timestamp_response(token)
    digest = hashlib.sha256(message).digest()
    for root in _certifi_roots():
        verifier = VerifierBuilder().add_root_certificate(root).build()
        try:
            if verifier.verify(ts_response, digest):
                return root.public_bytes(Encoding.PEM)
        except VerificationError:
            continue
    return None


def test_live_timestamp_record_then_verify_offline():
    from agentos_controlplane.checkpoint import (
        Rfc3161Anchor,
        checkpoint_message,
        verify_checkpoint_proof,
    )

    message = checkpoint_message(42, "live-rfc3161-head-hash")
    try:
        token = Rfc3161Anchor(tsa_url=TSA_URL).anchor(message)
    except Exception as exc:  # network down / TSA error -> skip, not fail
        pytest.skip(f"could not obtain a live RFC-3161 token: {type(exc).__name__}: {exc}")

    root_pem = _root_pem_that_verifies(token, message)
    if root_pem is None:
        pytest.skip("no certifi root verified the live token (issuer/trust-store gap)")

    # Real external-authority proof verifies OFFLINE under the pinned root...
    assert (
        verify_checkpoint_proof("rfc3161_v1", token, message, tsa_root_pem=root_pem) is True
    )
    # ...and a TAMPERED message (different bound head) does NOT — the unforgeability property.
    tampered = checkpoint_message(42, "tampered-head-hash")
    assert (
        verify_checkpoint_proof("rfc3161_v1", token, tampered, tsa_root_pem=root_pem) is False
    )
