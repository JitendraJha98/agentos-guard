"""SEC-10 / OWASP-ASI07 — inter-agent authentication + agent-card verification.

ASI07 is the trust-the-caller gap: agent A delegates to "B", and B is taken at
its word — no check that B is who it claims, that its key is still valid, or that
it is even a registered agent. A hijacked or spoofed delegate then acts with the
delegation's authority.

An **agent card** is the verifiable self-description a peer presents — its
identity, its live certificate, and the capabilities it claims (the A2A
"agent card" idea). This module verifies that card against the control plane on
every delegation, so authority only ever flows to a peer the CA still vouches for.

Verification is layered on the Phase-7 pieces rather than reinventing them:
  * IDN-01 registration — the peer must be a known agent;
  * IDN-03 certificate  — its cert must verify against the CA and not be revoked
    (this is where a compromised/rotated-out peer is caught);
  * the claimed capabilities must not exceed its authored scope (TRST-04) — a
    card cannot grant its holder more than the control plane already recorded.

Pure verdict object, never raises — it sits on the delegation path, so an
unverifiable card is a deny, not a 500 (same discipline as identity/cert verify).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class AgentCard:
    """A peer's verifiable self-description, presented on delegation."""

    agent_id: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    certificate_pem: str | None = None


@dataclass(frozen=True)
class CardVerdict:
    """The outcome of verifying an agent card. Mirrors CertificateVerdict/IdentityResult."""

    ok: bool
    detail: str = ""
    agent_id: str | None = None


class AgentCardVerifier:
    """Verifies a delegatee's agent card against the control plane (SEC-10).

    Injected with the registry's own bound methods so it stays decoupled from the
    persistence layer, matching how `IdentityEngine` takes `is_registered`/
    `load_trust`. When no CA is wired (certificates disabled), certificate
    verification is SKIPPED rather than failing closed — a deployment that has not
    adopted IDN-03 still gets registration + scope checks, and does not have every
    delegation denied for lacking a cert it never issued.
    """

    def __init__(self, registry, scope_lookup=None) -> None:
        self._registry = registry
        # Optional ScopeLookup (the ResourceStore). None -> the capability-vs-scope
        # check is skipped (every agent treated as wildcard), which is correct for a
        # deployment that has not authored per-agent scopes.
        self._scope = scope_lookup

    def card_for(self, action) -> AgentCard:
        """Build the DELEGATEE's agent card from a delegation action.

        The delegatee is the action's `target` (INT-05: `agent_id` is the delegator,
        `target`/`payload.to_agent` is the peer). A delegation MAY present the peer's
        own card in `payload.agent_card` — capabilities it claims and, optionally, a
        certificate; otherwise the card is built from the peer's registered
        certificate. Either way `verify` checks it against the CA, so a forged
        presented cert cannot pass.
        """
        payload = action.payload or {}
        to_agent = str(payload.get("to_agent") or action.target or "")
        presented = payload.get("agent_card") or {}
        return AgentCard(
            agent_id=to_agent,
            capabilities=frozenset(presented.get("capabilities", [])),
            certificate_pem=presented.get("certificate_pem"),
        )

    def verify(self, card: AgentCard) -> CardVerdict:
        agent_id = card.agent_id
        if not agent_id:
            return CardVerdict(False, "agent card carries no agent_id")

        # IDN-01: the peer must be a registered agent — never delegate to an unknown id.
        if not self._registry.is_registered(agent_id):
            return CardVerdict(False, f"delegatee {agent_id!r} is not a registered agent", agent_id)

        # IDN-03: verify the presented certificate against the CA + CRL, when certs are in use.
        ca = getattr(self._registry, "_ca", None)
        if ca is not None:
            presented = card.certificate_pem or self._registry.certificate_for(agent_id)
            if presented is None:
                return CardVerdict(False, f"delegatee {agent_id!r} has no certificate to verify", agent_id)
            cert_verdict = self._registry.verify_certificate(presented, agent_id)
            if not cert_verdict.ok:
                return CardVerdict(False, f"certificate check failed: {cert_verdict.detail}", agent_id)

        # TRST-04: a card cannot claim more than the control plane authored for the agent.
        # The wildcard scope confers everything, so it satisfies any claim.
        if self._scope is not None:
            authored = self._scope.scope_for(agent_id)
            if "*" not in authored:
                over = card.capabilities - authored
                if over:
                    return CardVerdict(
                        False,
                        f"agent card claims capabilities beyond authored scope: {sorted(over)}",
                        agent_id,
                    )

        return CardVerdict(True, "agent card verified", agent_id)
