"""Agent self-registration + trust load — IDN-01 / TRST-01 seed.

`register` persists an `Agent` row and returns the issued EdDSA token (the seam
the SDK presents on every action). `is_registered` / `load_trust` are the
registry-lookup callables the identity engine verifies against.
"""

from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.models import Agent

DEFAULT_TRUST_SCORE = 0.5  # TRST-01 seed; the full reputation engine is Phase 7.


class Registry:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        identity: IdentityEngine | None = None,
        inventory: InventoryStore | None = None,
    ) -> None:
        self._session_factory = session_factory
        # Wire the engine's registry-lookup seam to this registry's own methods.
        self.identity = identity or IdentityEngine(
            is_registered=self.is_registered, load_trust=self.load_trust
        )
        self._inventory = inventory  # optional InventoryStore (DISC-01)

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
        """
        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            if agent is None:
                agent = Agent(
                    agent_id=agent_id,
                    trust_score=trust_score if trust_score is not None else DEFAULT_TRUST_SCORE,
                    public_key=self.identity.public_key_pem,
                )
                session.add(agent)
            elif trust_score is not None:
                agent.trust_score = trust_score
            session.commit()
        token = self.identity.issue_token(agent_id)
        if manifest is not None and self._inventory is not None:
            self._inventory.declare(
                agent_id,
                tools=manifest.get("tools", []),
                prompts=manifest.get("prompts", []),
                memories=manifest.get("memories", []),
            )
        return token

    def is_registered(self, agent_id: str) -> bool:
        with self._session_factory() as session:
            return session.get(Agent, agent_id) is not None

    def load_trust(self, agent_id: str) -> float:
        """TRST-01 seed — the 0-1 score the graduated-response stage consumes."""
        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            return agent.trust_score if agent is not None else 0.0
