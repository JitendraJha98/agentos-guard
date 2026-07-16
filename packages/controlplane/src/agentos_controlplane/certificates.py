"""IDN-03 — X.509 agent certificates binding identity to keys.

Phase 1 identity is a bearer JWT signed by ONE control-plane keypair. That
authenticates the control plane, not the agent: every agent's `Agent.public_key`
row holds the *control plane's* key, so nothing binds an agent id to key material
the agent actually holds. Anyone with the token is the agent.

This module closes that. The control plane becomes a small CA; each agent gets
its own Ed25519 keypair and an X.509 certificate in which the CA attests
`agent-id <-> this public key`. The binding is now a signed, expiring,
revocable artifact that a third party can verify offline against the CA cert —
no shared secret, no control-plane round trip.

Design notes:

* **Ed25519 throughout**, matching the existing identity/audit-signing keys
  (`identity_engine`, AUD-08) — one curve, one set of primitives to review.
* **URI SAN, not just a CN.** The subject is carried as
  `agentos://agent/<agent_id>` in a SubjectAlternativeName URI. CNs are legacy
  and ambiguous; a URI SAN is what SPIFFE-style workload identity (IDN-04,
  Phase 14) extends, so the shape is right the first time.
* **Agent certs are explicitly `CA: false`** with `digital_signature` key usage.
  A leaf that could sign other leaves would let any agent mint identities.
* **`verify` returns a verdict, never raises.** It sits on the identity path; a
  malformed certificate must be a deny, not a 500 (the same discipline
  `IdentityEngine.verify` follows).
* **Revocation is injected** (`is_revoked`), not baked in, so the store owns the
  CRL and this module stays pure. A cert that cannot be revoked is barely better
  than the bearer token it replaces, so the check is not optional plumbing —
  it is the reason to prefer certificates at all.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.x509.oid import NameOID

# The agent identity URI namespace carried in the certificate's SAN. Deliberately
# shaped like a SPIFFE ID (scheme://authority/path) so IDN-04's SPIFFE/SVID work
# is a change of scheme, not a change of model.
AGENT_URI_PREFIX = "agentos://agent/"

ISSUER_CN = "agentos-guard-ca"
# 90 days: long enough that rotation is not a daily operational burden, short
# enough that a lost revocation still self-heals within a quarter.
DEFAULT_CERT_TTL = timedelta(days=90)
CA_TTL = timedelta(days=3650)
# Tolerance for clock skew between the issuing control plane and a verifier.
CLOCK_SKEW = timedelta(minutes=5)


@dataclass(frozen=True)
class CertificateVerdict:
    """The outcome of verifying a certificate. Mirrors `IdentityResult`'s shape."""

    ok: bool
    detail: str = ""
    agent_id: str | None = None
    serial: int | None = None


def agent_id_from_certificate(cert: x509.Certificate) -> str | None:
    """Extract the agent id from the certificate's URI SAN, or None if absent.

    Reads the SAN ONLY — never the CN. A cert whose CN and SAN disagree must not
    be resolvable two ways; the SAN is the authority.
    """
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return None
    for uri in san.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith(AGENT_URI_PREFIX):
            return uri[len(AGENT_URI_PREFIX) :]
    return None


class CertificateAuthority:
    """The control plane's CA: issues and verifies agent certificates (IDN-03).

    The CA key defaults to a fresh Ed25519 keypair. Deployments that need the CA
    to survive a restart (any real one) MUST pass a persisted `private_key` — an
    ephemeral CA invalidates every certificate it ever issued on restart.
    """

    def __init__(
        self,
        private_key: Ed25519PrivateKey | None = None,
        *,
        default_ttl: timedelta = DEFAULT_CERT_TTL,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._key = private_key or Ed25519PrivateKey.generate()
        self._default_ttl = default_ttl
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._ca_cert = self._build_ca_certificate()

    # ------------------------------------------------------------------ the CA

    def _build_ca_certificate(self) -> x509.Certificate:
        now = self._now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ISSUER_CN)])
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)  # self-signed root
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + CA_TTL)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            # Ed25519 carries its own hash; the algorithm MUST be None.
            .sign(self._key, algorithm=None)
        )

    @property
    def ca_certificate_pem(self) -> str:
        """The CA's self-signed root, for verifiers to pin. Public — safe to publish."""
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # ------------------------------------------------------------------ issue

    def issue(
        self, agent_id: str, public_key_pem: str, *, ttl: timedelta | None = None
    ) -> str:
        """Issue a certificate binding `agent_id` to `public_key_pem`. Returns PEM.

        `public_key_pem` is the AGENT's own public key — the control plane never
        sees the matching private key, which is what makes the binding meaningful.
        """
        if not agent_id:
            raise ValueError("agent_id must be non-empty")
        key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"agent key must be Ed25519, got {type(key).__name__}")

        now = self._now()
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key)
            # 20 random bytes, per CA/Browser-Forum practice: unguessable serials
            # stop an attacker from predicting (and pre-revoking) a future issuance.
            .serial_number(int.from_bytes(secrets.token_bytes(20), "big") >> 1 or 1)
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + (ttl or self._default_ttl))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.UniformResourceIdentifier(f"{AGENT_URI_PREFIX}{agent_id}")]
                ),
                critical=False,
            )
            # A leaf that could sign other leaves would let any agent mint identities.
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, algorithm=None)
        ).public_bytes(serialization.Encoding.PEM).decode()

    # ----------------------------------------------------------------- verify

    def verify(
        self,
        certificate_pem: str,
        *,
        expected_agent_id: str | None = None,
        now: datetime | None = None,
        is_revoked: Callable[[int], bool] | None = None,
    ) -> CertificateVerdict:
        """Verify a certificate against this CA. Returns a verdict; never raises.

        Checks, in order — each one is a distinct forgery this rejects:
          1. parses as X.509;
          2. issued by THIS CA (signature over the TBS bytes);
          3. inside its validity window (skew-tolerant);
          4. carries an agent id, matching `expected_agent_id` when given;
          5. not revoked.
        """
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
        except Exception as exc:
            return CertificateVerdict(False, f"malformed certificate: {type(exc).__name__}")

        try:
            self._key.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        except InvalidSignature:
            return CertificateVerdict(False, "bad signature: not issued by this CA")
        except Exception as exc:
            return CertificateVerdict(False, f"signature check failed: {type(exc).__name__}")

        at = now or self._now()
        # `*_utc` accessors: the naive properties are deprecated and would compare
        # a naive datetime against our aware one and raise.
        if at < cert.not_valid_before_utc - CLOCK_SKEW:
            return CertificateVerdict(False, f"certificate not yet valid (nbf {cert.not_valid_before_utc})")
        if at > cert.not_valid_after_utc:
            return CertificateVerdict(False, f"certificate expired at {cert.not_valid_after_utc}")

        agent_id = agent_id_from_certificate(cert)
        if agent_id is None:
            return CertificateVerdict(False, "certificate carries no agent URI SAN")
        if expected_agent_id is not None and agent_id != expected_agent_id:
            return CertificateVerdict(
                False, f"certificate agent {agent_id!r} does not match claimed {expected_agent_id!r}"
            )

        if is_revoked is not None and is_revoked(cert.serial_number):
            return CertificateVerdict(False, "certificate is revoked", agent_id, cert.serial_number)

        return CertificateVerdict(True, "certificate verified", agent_id, cert.serial_number)


def generate_agent_keypair() -> tuple[str, str]:
    """A fresh Ed25519 keypair for an agent: `(private_pem, public_pem)`.

    Returned to the CALLER, not stored: the control plane must never retain an
    agent's private key, or the certificate binding proves nothing about who acted.
    """
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem
