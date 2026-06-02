"""IDN-01/IDN-02 — EdDSA identity engine + agent registry.

Behavior (plan 01-02 Task 1):
- register("agent-1") then verify(issue_token("agent-1"), "agent-1") -> ok=True
  with the registered trust_score.
- verify(None, "agent-1") -> ok=False, detail mentions the missing token.
- verify(token_for_agent_1, "agent-2") -> ok=False (sub/claimed mismatch).
- a tampered token (flipped payload byte) -> ok=False (InvalidTokenError terminal).
- a token signed with a DIFFERENT key -> ok=False (signature mismatch).
- an unregistered but validly-signed agent_id -> ok=False (not registered).

No Docker (D-14): the registry runs against an in-memory SQLite engine.
"""

import base64
import json

import pytest
from sqlalchemy import create_engine

from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def registry() -> Registry:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return Registry(create_session_factory(engine))


def _flip_payload_byte(token: str) -> str:
    """Return a token whose JWT payload segment is tampered (one bit flipped)."""
    header, payload, signature = token.split(".")
    raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    claims = json.loads(raw)
    claims["sub"] = claims["sub"] + "-tampered"  # mutate payload; signature now stale
    mutated = base64.urlsafe_b64encode(
        json.dumps(claims, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{mutated}.{signature}"


def test_register_then_verify_ok(registry: Registry) -> None:
    token = registry.register("agent-1", trust_score=0.7)
    result = registry.identity.verify(token, "agent-1")
    assert result.ok is True
    assert result.trust_score == 0.7


def test_verify_missing_token(registry: Registry) -> None:
    result = registry.identity.verify(None, "agent-1")
    assert result.ok is False
    assert "missing" in result.detail.lower()


def test_verify_sub_claimed_mismatch(registry: Registry) -> None:
    token = registry.register("agent-1")
    registry.register("agent-2")
    result = registry.identity.verify(token, "agent-2")
    assert result.ok is False


def test_verify_tampered_token(registry: Registry) -> None:
    token = registry.register("agent-1")
    tampered = _flip_payload_byte(token)
    result = registry.identity.verify(tampered, "agent-1")
    assert result.ok is False


def test_verify_wrong_key(registry: Registry) -> None:
    registry.register("agent-1")
    # A second, independent engine has a different keypair; its token must NOT
    # verify against the registry's engine (signature mismatch).
    other_engine = IdentityEngine(
        is_registered=registry.is_registered, load_trust=registry.load_trust
    )
    foreign_token = other_engine.issue_token("agent-1")
    result = registry.identity.verify(foreign_token, "agent-1")
    assert result.ok is False


def test_verify_unregistered_agent(registry: Registry) -> None:
    # Validly-signed by the registry's engine, but never registered.
    token = registry.identity.issue_token("ghost-agent")
    result = registry.identity.verify(token, "ghost-agent")
    assert result.ok is False
    assert "registered" in result.detail.lower() or "unknown" in result.detail.lower()
