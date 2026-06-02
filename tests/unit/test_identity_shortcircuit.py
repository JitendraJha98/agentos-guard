"""IdentityStage — pipeline stage 1 wrapper over the EdDSA identity engine.

Behavior (plan 01-05 Task 1, IDN-02 / TRST-01):
  - a valid registered token -> ok=True with the agent's loaded trust_score.
  - a forged / tampered token -> ok=False (terminal deny upstream).
  - a None / missing token -> ok=False.
  - a sub/claimed-agent mismatch -> ok=False.
  - an unregistered (validly-signed) agent -> ok=False.

IdentityStage.verify(action) delegates to identity_engine.verify(action.identity_token,
action.agent_id), so the pipeline stage sees only the AgentAction. The engine itself is
exercised in tests/unit/test_identity.py; here we prove the stage wraps it correctly and
extracts the token/agent_id from the action (TRST-01: the trust_score is surfaced).

No Docker (D-14): the registry runs against an in-memory SQLite engine.
"""

from __future__ import annotations

import base64
import json

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.identity import IdentityStage


@pytest.fixture
def registry() -> Registry:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return Registry(create_session_factory(engine))


def _action(agent_id: str, token: str | None) -> AgentAction:
    return AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/data"},
        identity_token=token,
    )


def _tamper(token: str) -> str:
    """Mutate the JWT payload so the signature no longer verifies."""
    header, payload, signature = token.split(".")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    claims = json.loads(raw)
    claims["sub"] = claims["sub"] + "-forged"
    mutated = (
        base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{mutated}.{signature}"


def test_valid_registered_token_ok_with_trust(registry: Registry) -> None:
    token = registry.register("agent-1", trust_score=0.7)
    stage = IdentityStage(registry.identity)
    result = stage.verify(_action("agent-1", token))
    assert result.ok is True
    assert result.trust_score == 0.7  # TRST-01: the loaded trust feeds graduated


def test_forged_token_short_circuits(registry: Registry) -> None:
    token = registry.register("agent-1")
    stage = IdentityStage(registry.identity)
    result = stage.verify(_action("agent-1", _tamper(token)))
    assert result.ok is False


def test_missing_token_rejected(registry: Registry) -> None:
    registry.register("agent-1")
    stage = IdentityStage(registry.identity)
    result = stage.verify(_action("agent-1", None))
    assert result.ok is False
    assert "missing" in result.detail.lower()


def test_sub_claimed_mismatch_rejected(registry: Registry) -> None:
    token = registry.register("agent-1")
    registry.register("agent-2")
    stage = IdentityStage(registry.identity)
    # token is for agent-1 but the action claims agent-2.
    result = stage.verify(_action("agent-2", token))
    assert result.ok is False


def test_unregistered_agent_rejected(registry: Registry) -> None:
    stage = IdentityStage(registry.identity)
    ghost_token = registry.identity.issue_token("ghost-agent")
    result = stage.verify(_action("ghost-agent", ghost_token))
    assert result.ok is False
