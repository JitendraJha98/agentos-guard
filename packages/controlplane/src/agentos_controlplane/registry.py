"""Agent self-registration + trust load — IDN-01 / TRST-01 seed.

`register` persists an `Agent` row and returns the issued EdDSA token (the seam
the SDK presents on every action). `is_registered` / `load_trust` are the
registry-lookup callables the identity engine verifies against.
"""

from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.models import Agent

DEFAULT_TRUST_SCORE = 0.5  # TRST-01 seed; the full reputation engine is Phase 7.


class Registry:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        identity: IdentityEngine | None = None,
    ) -> None:
        self._session_factory = session_factory
        # Wire the engine's registry-lookup seam to this registry's own methods.
        self.identity = identity or IdentityEngine(
            is_registered=self.is_registered, load_trust=self.load_trust
        )

    def register(self, agent_id: str, trust_score: float = DEFAULT_TRUST_SCORE) -> str:
        """Persist the Agent row and return the issued identity token (IDN-01)."""
        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            if agent is None:
                agent = Agent(
                    agent_id=agent_id,
                    trust_score=trust_score,
                    public_key=self.identity.public_key_pem,
                )
                session.add(agent)
            else:
                agent.trust_score = trust_score
            session.commit()
        return self.identity.issue_token(agent_id)

    def is_registered(self, agent_id: str) -> bool:
        with self._session_factory() as session:
            return session.get(Agent, agent_id) is not None

    def load_trust(self, agent_id: str) -> float:
        """TRST-01 seed — the 0-1 score the graduated-response stage consumes."""
        with self._session_factory() as session:
            agent = session.get(Agent, agent_id)
            return agent.trust_score if agent is not None else 0.0
