"""IDN-03 — X.509 agent certificates binding identity to keys.

A certificate is only worth the checks a verifier actually performs, so every
rejection path gets its own test: forged issuer, tampered body, wrong subject,
expired, not-yet-valid, and revoked. The positive test alone would pass against
an implementation that verifies nothing.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentos_controlplane.certificates import (
    AGENT_URI_PREFIX,
    CertificateAuthority,
    agent_id_from_certificate,
)


@pytest.fixture()
def ca() -> CertificateAuthority:
    return CertificateAuthority()


@pytest.fixture()
def agent_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _pub(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


# ------------------------------------------------------------------- issuance


def test_issued_certificate_binds_the_agent_id_to_its_key(ca, agent_key):
    """The whole point of IDN-03: identity <-> key, asserted by the CA."""
    pem = ca.issue("agent-1", _pub(agent_key))
    cert = x509.load_pem_x509_certificate(pem.encode())

    assert agent_id_from_certificate(cert) == "agent-1"
    # The certified key is the AGENT's key, not the CA's.
    assert cert.public_key().public_bytes_raw() == agent_key.public_key().public_bytes_raw()


def test_certificate_carries_a_uri_san_for_the_agent(ca, agent_key):
    """A URI SAN (not just a CN) is what SPIFFE-style workload identity builds on later."""
    cert = x509.load_pem_x509_certificate(ca.issue("agent-1", _pub(agent_key)).encode())
    uris = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [f"{AGENT_URI_PREFIX}agent-1"]


def test_serials_are_unique_per_issuance(ca, agent_key):
    a = x509.load_pem_x509_certificate(ca.issue("a", _pub(agent_key)).encode())
    b = x509.load_pem_x509_certificate(ca.issue("b", _pub(agent_key)).encode())
    assert a.serial_number != b.serial_number


def test_agent_certificate_is_not_a_ca(ca, agent_key):
    """An agent cert that could sign other certs would let any agent mint identities."""
    cert = x509.load_pem_x509_certificate(ca.issue("agent-1", _pub(agent_key)).encode())
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False


def test_ca_certificate_is_self_signed_and_is_a_ca(ca):
    root = x509.load_pem_x509_certificate(ca.ca_certificate_pem.encode())
    assert root.issuer == root.subject
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True


# --------------------------------------------------------------- verification


def test_verify_accepts_a_genuine_certificate(ca, agent_key):
    v = ca.verify(ca.issue("agent-1", _pub(agent_key)), expected_agent_id="agent-1")
    assert v.ok
    assert v.agent_id == "agent-1"


def test_verify_rejects_a_certificate_from_a_different_ca(ca, agent_key):
    """The core trust check: only OUR CA's signature makes a cert ours."""
    rogue = CertificateAuthority()
    v = ca.verify(rogue.issue("agent-1", _pub(agent_key)), expected_agent_id="agent-1")
    assert not v.ok
    assert "signature" in v.detail.lower() or "issuer" in v.detail.lower()


def test_verify_rejects_a_tampered_certificate(ca, agent_key):
    pem = ca.issue("agent-1", _pub(agent_key))
    # Flip a byte in the middle of the base64 body.
    lines = pem.strip().splitlines()
    body = lines[len(lines) // 2]
    lines[len(lines) // 2] = ("B" if body[0] != "B" else "C") + body[1:]
    assert not ca.verify("\n".join(lines), expected_agent_id="agent-1").ok


def test_verify_rejects_a_subject_mismatch(ca, agent_key):
    """A valid cert for agent-2 must not authenticate agent-1 (confused deputy)."""
    v = ca.verify(ca.issue("agent-2", _pub(agent_key)), expected_agent_id="agent-1")
    assert not v.ok
    assert "agent" in v.detail.lower()


def test_verify_rejects_an_expired_certificate(ca, agent_key):
    pem = ca.issue("agent-1", _pub(agent_key), ttl=timedelta(days=1))
    future = datetime.now(timezone.utc) + timedelta(days=2)
    v = ca.verify(pem, expected_agent_id="agent-1", now=future)
    assert not v.ok
    assert "expired" in v.detail.lower()


def test_verify_rejects_a_not_yet_valid_certificate(ca, agent_key):
    pem = ca.issue("agent-1", _pub(agent_key))
    past = datetime.now(timezone.utc) - timedelta(days=2)
    v = ca.verify(pem, expected_agent_id="agent-1", now=past)
    assert not v.ok
    assert "not yet valid" in v.detail.lower()


def test_verify_rejects_a_revoked_certificate(ca, agent_key):
    """Revocation is the reason certs beat bare keys — it must actually be checked."""
    pem = ca.issue("agent-1", _pub(agent_key))
    serial = x509.load_pem_x509_certificate(pem.encode()).serial_number

    v = ca.verify(pem, expected_agent_id="agent-1", is_revoked=lambda s: s == serial)
    assert not v.ok
    assert "revoked" in v.detail.lower()


def test_verify_rejects_garbage_without_raising(ca):
    """A malformed cert is a verdict, never an exception into the hot path."""
    for junk in ("", "not a certificate", "-----BEGIN CERTIFICATE-----\nxx\n-----END CERTIFICATE-----"):
        assert not ca.verify(junk, expected_agent_id="a").ok


def test_verify_without_an_expected_id_still_authenticates_the_chain(ca, agent_key):
    v = ca.verify(ca.issue("agent-9", _pub(agent_key)))
    assert v.ok and v.agent_id == "agent-9"
