"""Agent self-registration + trust load — IDN-01 / TRST-01 / TRST-03 / IDN-03.

`register` persists an `Agent` row and returns the issued EdDSA token (the seam
the SDK presents on every action). `is_registered` / `load_trust` are the
registry-lookup callables the identity engine verifies against.

IDN-03: when a `CertificateAuthority` is wired, registration also mints the agent
its own Ed25519 keypair and a CA-issued X.509 certificate binding
`agent_id <-> public_key`, returning the private key to the agent (never storing it).
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.certificates import CertificateAuthority, generate_agent_keypair
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.models import Agent, RevokedCertificate, TrustProfile

DEFAULT_TRUST_SCORE = 0.5  # TRST-01 seed for a new agent; TRST-03 reputation grades it from there.


@dataclass(frozen=True)
class Enrollment:
    """What an agent receives at registration (IDN-01 + IDN-03).

    `private_key_pem` is the agent's own key and is returned exactly ONCE, at
    enrollment — the control plane does not store it. That is the entire point of
    the certificate binding: if the control plane held the private key, the
    certificate would prove nothing about who actually acted.
    """

    agent_id: str
    token: str
    certificate_pem: str | None = None
    private_key_pem: str | None = None
    ca_certificate_pem: str | None = None


class Registry:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        identity: IdentityEngine | None = None,
        inventory: InventoryStore | None = None,
        certificate_authority: CertificateAuthority | None = None,
    ) -> None:
        self._session_factory = session_factory
        # Wire the engine's registry-lookup seam to this registry's own methods.
        self.identity = identity or IdentityEngine(
            is_registered=self.is_registered, load_trust=self.load_trust
        )
        self._inventory = inventory  # optional InventoryStore (DISC-01)
        # IDN-03: optional CA. None default -> no certificates are issued and
        # registration behaves exactly as it did through Phase 6.
        self._ca = certificate_authority

    def register(
        self,
        agent_id: str,
        trust_score: float | None = None,
        manifest: dict | None = None,
    ) -> str:
        """Persist the Agent row and return the issued identity token (IDN-01).

        A NEW agent is seeded with the supplied `trust_score` or DEFAULT_TRUST_SCORE. Trust is NOT
        caller-authoritative: the public registration endpoint never supplies it (the server-side
        default applies), and trust is graded only via the gated PUT /trust-profiles operator route.

        Re-register is idempotent w.r.t. trust: re-enrolling an existing agent_id rotates the identity
        token but does NOT reset the row's trust_score unless an explicit trust_score is supplied — so a
        shared-token holder cannot raise/lower another agent's reputation by re-enrolling it.

        DISC-01: an optional registration `manifest` ({tools,prompts,memories}) declares authoritative
        inventory rows when an InventoryStore is wired. Both args are optional, so register(agent_id) /
        register(agent_id, trust_score) stay backward compatible.

        Returns the token only; `enroll()` returns the full Enrollment (IDN-03 certificate + key).
        """
        return self.enroll(agent_id, trust_score=trust_score, manifest=manifest).token

    def enroll(
        self,
        agent_id: str,
        *,
        trust_score: float | None = None,
        manifest: dict | None = None,
    ) -> Enrollment:
        """Register `agent_id` and return its full Enrollment (IDN-01 + IDN-03).

        With a CA wired, this mints the agent a fresh Ed25519 keypair and a
        certificate binding `agent_id <-> public_key`. The private key is returned
        here and NOWHERE else — the control plane stores only the public half.

        Re-enrolling an existing agent ROTATES its keypair and certificate. The
        previous certificate is deliberately NOT auto-revoked: revocation is an
        operator decision (`revoke_certificate`), and silently revoking on
        re-registration would let anyone holding the shared enrollment token knock a
        healthy agent's live certificate out from under it by re-enrolling its id.
        """
        cert_pem = private_pem = public_pem = None
        serial = None
        if self._ca is not None:
            private_pem, public_pem = generate_agent_keypair()
            cert_pem = self._ca.issue(agent_id, public_pem)
            from cryptography import x509

            serial = str(x509.load_pem_x509_certificate(cert_pem.encode()).serial_number)

        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            if agent is None:
                agent = Agent(
                    agent_id=agent_id,
                    trust_score=trust_score if trust_score is not None else DEFAULT_TRUST_SCORE,
                    public_key=public_pem,
                    certificate=cert_pem,
                    cert_serial=serial,
                )
                session.add(agent)
            else:
                if trust_score is not None:
                    agent.trust_score = trust_score
                if cert_pem is not None:  # rotation on re-enrollment
                    agent.public_key, agent.certificate, agent.cert_serial = (
                        public_pem, cert_pem, serial,
                    )
            session.commit()

        token = self.identity.issue_token(agent_id)
        if manifest is not None and self._inventory is not None:
            self._inventory.declare(
                agent_id,
                tools=manifest.get("tools", []),
                prompts=manifest.get("prompts", []),
                memories=manifest.get("memories", []),
            )
        return Enrollment(
            agent_id=agent_id,
            token=token,
            certificate_pem=cert_pem,
            private_key_pem=private_pem,
            ca_certificate_pem=self._ca.ca_certificate_pem if self._ca else None,
        )

    # ---- IDN-03 certificate lifecycle ----

    def certificate_for(self, agent_id: str) -> str | None:
        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            return agent.certificate if agent is not None else None

    def revoke_certificate(self, agent_id: str, *, reason: str = "") -> str | None:
        """Revoke `agent_id`'s current certificate. Returns the revoked serial, or None.

        Idempotent: revoking an already-revoked serial is a no-op, not an error.
        """
        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            if agent is None or agent.cert_serial is None:
                return None
            serial = agent.cert_serial
            if session.get(RevokedCertificate, serial) is None:
                session.add(
                    RevokedCertificate(serial=serial, agent_id=agent_id, reason=reason)
                )
                session.commit()
            return serial

    def is_revoked(self, serial: int | str) -> bool:
        """The CRL check the CertificateAuthority's `is_revoked` seam consumes."""
        with self._session_factory() as session:
            return session.get(RevokedCertificate, str(serial)) is not None

    def verify_certificate(self, certificate_pem: str, agent_id: str | None = None):
        """Verify a presented certificate against the CA, honouring the CRL (IDN-03)."""
        if self._ca is None:
            raise RuntimeError("no CertificateAuthority is wired into this Registry")
        return self._ca.verify(
            certificate_pem, expected_agent_id=agent_id, is_revoked=self.is_revoked
        )

    def is_registered(self, agent_id: str) -> bool:
        with self._session_factory() as session:
            return session.get(Agent, agent_id) is not None

    def load_trust(self, agent_id: str) -> float:
        """The 0-1 score the graduated-response stage consumes (TRST-01 seed, TRST-03 derived).

        Resolution order, most-authoritative first:

          1. the agent's `TrustProfile` — where BOTH the gated operator route
             (PUT /trust-profiles) and the TRST-03 reputation reconciler write;
          2. the `Agent` row's seed `trust_score`, for an agent with no profile yet;
          3. 0.0 for an unknown agent — fail closed, no benefit of the doubt.

        Step 1 is load-bearing, not a nicety: before Phase 7 this method read only
        the `Agent` seed, so an operator grading an agent down through the only
        route documented for it changed the dashboard and nothing else — the
        pipeline kept scoring the agent at its seed trust. Reputation (TRST-03)
        reaches graduated response through exactly this path, so it must resolve
        the profile first. Regression-locked in tests/unit/test_reputation.py.
        """
        with self._session_factory() as session:
            profile = session.get(TrustProfile, agent_id)
            if profile is not None:
                return profile.trust_score
            agent = session.get(Agent, agent_id)
            return agent.trust_score if agent is not None else 0.0
