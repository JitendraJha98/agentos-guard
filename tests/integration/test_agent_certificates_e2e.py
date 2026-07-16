"""IDN-03 end-to-end: enrollment issues a real certificate; revocation kills it.

Drives the full path — Registry + CertificateAuthority + the CRL table — rather
than the CA in isolation, because the properties that matter are about what the
control plane persists (and refuses to persist).
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from sqlalchemy import create_engine

from agentos_controlplane.certificates import CertificateAuthority
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import Agent


@pytest.fixture()
def wired():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    return sf, Registry(sf, certificate_authority=CertificateAuthority())


def test_enrollment_issues_a_verifiable_certificate(wired):
    sf, registry = wired
    enrollment = registry.enroll("agent-1")

    assert enrollment.certificate_pem is not None
    assert registry.verify_certificate(enrollment.certificate_pem, "agent-1").ok


def test_the_control_plane_never_stores_the_agents_private_key(wired):
    """If the CA held the private key the certificate would prove nothing about who acted."""
    sf, registry = wired
    enrollment = registry.enroll("agent-1")

    with sf() as s:
        row = s.get(Agent, "agent-1")
    stored = " ".join(str(v) for v in vars(row).values() if v is not None)
    assert "PRIVATE KEY" not in stored
    assert enrollment.private_key_pem is not None, "the agent must receive its own key once"


def test_the_stored_public_key_is_the_agents_not_the_control_planes(wired):
    """Regression lock: through Phase 6 every row held the SAME control-plane key."""
    sf, registry = wired
    a = registry.enroll("agent-a")
    b = registry.enroll("agent-b")

    with sf() as s:
        key_a = s.get(Agent, "agent-a").public_key
        key_b = s.get(Agent, "agent-b").public_key

    assert key_a != key_b, "agents share a public key: the binding certifies nothing"
    assert key_a != registry.identity.public_key_pem


def test_certificate_binds_the_key_the_agent_actually_holds(wired):
    """The private key handed to the agent must match the certified public key."""
    sf, registry = wired
    enrollment = registry.enroll("agent-1")

    private = serialization.load_pem_private_key(
        enrollment.private_key_pem.encode(), password=None
    )
    cert = x509.load_pem_x509_certificate(enrollment.certificate_pem.encode())
    assert (
        cert.public_key().public_bytes_raw() == private.public_key().public_bytes_raw()
    ), "the certificate certifies a key the agent does not hold"


def test_revocation_invalidates_a_previously_valid_certificate(wired):
    sf, registry = wired
    enrollment = registry.enroll("agent-1")
    assert registry.verify_certificate(enrollment.certificate_pem, "agent-1").ok

    registry.revoke_certificate("agent-1", reason="key compromise")

    verdict = registry.verify_certificate(enrollment.certificate_pem, "agent-1")
    assert not verdict.ok
    assert "revoked" in verdict.detail.lower()


def test_revocation_is_idempotent(wired):
    sf, registry = wired
    registry.enroll("agent-1")
    first = registry.revoke_certificate("agent-1")
    second = registry.revoke_certificate("agent-1")
    assert first == second


def test_revoking_an_unknown_agent_is_a_no_op(wired):
    sf, registry = wired
    assert registry.revoke_certificate("ghost") is None


def test_re_enrollment_rotates_the_keypair_and_certificate(wired):
    sf, registry = wired
    first = registry.enroll("agent-1")
    second = registry.enroll("agent-1")

    assert first.certificate_pem != second.certificate_pem
    assert first.private_key_pem != second.private_key_pem
    assert registry.verify_certificate(second.certificate_pem, "agent-1").ok


def test_re_enrollment_does_not_silently_revoke_the_old_certificate(wired):
    """Auto-revoking on re-enroll would let a shared-token holder knock a healthy
    agent's live certificate out by simply re-enrolling its id."""
    sf, registry = wired
    first = registry.enroll("agent-1")
    registry.enroll("agent-1")
    assert not registry.is_revoked(
        x509.load_pem_x509_certificate(first.certificate_pem.encode()).serial_number
    )


def test_one_agents_certificate_cannot_authenticate_another(wired):
    sf, registry = wired
    victim = registry.enroll("victim")
    registry.enroll("attacker")
    assert not registry.verify_certificate(victim.certificate_pem, "attacker").ok


def test_registry_without_a_ca_is_unchanged(wired):
    """None default: Phase-6 deployments keep working with no certificates at all."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    registry = Registry(create_session_factory(engine))

    enrollment = registry.enroll("plain")
    assert enrollment.token
    assert enrollment.certificate_pem is None
    with pytest.raises(RuntimeError):
        registry.verify_certificate("whatever", "plain")


def test_register_still_returns_just_the_token(wired):
    """Backward compatibility: every pre-Phase-7 caller uses register() -> str."""
    sf, registry = wired
    token = registry.register("agent-1")
    assert isinstance(token, str)
    assert registry.identity.verify(token, "agent-1").ok
