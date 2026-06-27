"""Registry.register trust semantics (TRST-01 / privilege review fixes).

register() seeds DEFAULT_TRUST_SCORE on a NEW agent and is idempotent w.r.t. trust on RE-register:
re-registering an existing agent_id rotates the identity token but must NOT silently reset the row's
trust_score (an arbitrary shared-token holder must not be able to raise/lower an agent's reputation by
re-enrolling it). An explicitly-supplied trust_score still updates the row (the gated operator path).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.registry import DEFAULT_TRUST_SCORE, Registry
from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def test_register_new_agent_seeds_default_trust(store) -> None:
    registry = Registry(store)
    registry.register("a")
    assert registry.load_trust("a") == DEFAULT_TRUST_SCORE


def test_reregister_does_not_reset_trust(store) -> None:
    """A re-enrollment must not silently reset an existing agent's trust to the default."""
    registry = Registry(store)
    registry.register("a")
    # operator raises trust out of band (the gated trust-profile path mirrors this row mutation)
    with store() as session:
        from agentos_controlplane.store.models import Agent

        session.get(Agent, "a").trust_score = 0.9
        session.commit()

    # a bare re-register (no explicit trust) must leave the elevated trust intact
    registry.register("a")
    assert registry.load_trust("a") == 0.9


def test_reregister_rotates_identity_token(store) -> None:
    """Re-register is still allowed to rotate the identity token (documented behavior)."""
    registry = Registry(store)
    first = registry.register("a")
    second = registry.register("a")
    assert first and second  # both non-empty tokens issued


def test_explicit_trust_score_still_updates(store) -> None:
    """An explicitly supplied trust_score (the gated operator path) still updates the row."""
    registry = Registry(store)
    registry.register("a")
    registry.register("a", trust_score=0.2)
    assert registry.load_trust("a") == 0.2
