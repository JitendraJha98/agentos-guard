"""SEC-10 / ASI07 — inter-agent auth + agent-card verification on delegation.

Covers both the verifier in isolation (every rejection path) and the delegation
path through the real pipeline (an unverifiable peer is denied before authority
flows to it).
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_contract.policy_io import ConstitutionResult
from agentos_controlplane.agent_card import AgentCard, AgentCardVerifier
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.certificates import CertificateAuthority
from agentos_controlplane.registry import Registry
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.delegation import DelegationLedger, DelegationResolver
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline


class _AllowAllPolicy:
    constitution_version = "c-v1"
    policy_version = "p-v1"

    def evaluate(self, _input: dict) -> ConstitutionResult:
        return ConstitutionResult(matched=(), no_match=True)


@pytest.fixture()
def cp():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    registry = Registry(sf, certificate_authority=CertificateAuthority())
    resources = ResourceStore(sf)
    verifier = AgentCardVerifier(registry, scope_lookup=resources)
    return sf, registry, resources, verifier


# --------------------------------------------------------------- verifier unit


def test_verify_accepts_a_registered_agent_with_a_valid_certificate(cp):
    sf, registry, resources, verifier = cp
    registry.enroll("peer")
    assert verifier.verify(AgentCard("peer")).ok


def test_verify_rejects_an_unregistered_peer(cp):
    sf, registry, resources, verifier = cp
    v = verifier.verify(AgentCard("ghost"))
    assert not v.ok and "not a registered agent" in v.detail


def test_verify_rejects_a_peer_whose_certificate_is_revoked(cp):
    sf, registry, resources, verifier = cp
    registry.enroll("peer")
    registry.revoke_certificate("peer", reason="compromised")
    v = verifier.verify(AgentCard("peer"))
    assert not v.ok and "certificate" in v.detail.lower()


def test_verify_rejects_a_card_claiming_capabilities_beyond_authored_scope(cp):
    sf, registry, resources, verifier = cp
    registry.enroll("peer")
    resources.put_trust_profile("peer", trust_score=0.5, band=None, expected_version=None, scope=["read"])
    v = verifier.verify(AgentCard("peer", capabilities=frozenset({"read", "db.drop"})))
    assert not v.ok and "beyond authored scope" in v.detail


def test_verify_accepts_a_card_within_authored_scope(cp):
    sf, registry, resources, verifier = cp
    registry.enroll("peer")
    resources.put_trust_profile("peer", trust_score=0.5, band=None, expected_version=None, scope=["read", "write"])
    assert verifier.verify(AgentCard("peer", capabilities=frozenset({"read"}))).ok


def test_verify_rejects_a_forged_certificate_from_another_ca(cp):
    sf, registry, resources, verifier = cp
    registry.enroll("peer")
    rogue = CertificateAuthority()
    from agentos_controlplane.certificates import generate_agent_keypair

    _, pub = generate_agent_keypair()
    forged = rogue.issue("peer", pub)
    v = verifier.verify(AgentCard("peer", certificate_pem=forged))
    assert not v.ok


# --------------------------------------------------------- through the pipeline


def _wire(cp) -> Pipeline:
    sf, registry, resources, verifier = cp
    return Pipeline(
        identity=IdentityStage(registry.identity),
        policy=_AllowAllPolicy(),
        scorers=[],
        audit=AuditWriter(sf),
        thresholds=GraduatedThresholds(),
        posture=PostureMap(),
        delegation=DelegationResolver(resources, ledger=DelegationLedger()),
        card_verifier=verifier,
    )


def _delegation(delegator: str, token: str, to_agent: str) -> AgentAction:
    return AgentAction(
        agent_id=delegator,
        type=ActionType.delegation,
        target=to_agent,
        payload={"to_agent": to_agent, "task": "do the thing"},
        identity_token=token,
    )


def test_delegation_to_a_verified_peer_is_allowed(cp):
    sf, registry, resources, verifier = cp
    a_token = registry.enroll("a").token
    registry.enroll("b")
    decision = asyncio.run(_wire(cp).evaluate(_delegation("a", a_token, "b")))
    assert decision.outcome == Outcome.allow
    assert any(r.code == "agent_card_verified" for r in decision.reasons)


def test_delegation_to_an_unregistered_peer_is_denied(cp):
    sf, registry, resources, verifier = cp
    a_token = registry.enroll("a").token
    decision = asyncio.run(_wire(cp).evaluate(_delegation("a", a_token, "ghost")))
    assert decision.outcome == Outcome.deny
    assert any(r.code == "agent_card_unverified" for r in decision.reasons)


def test_delegation_to_a_revoked_peer_is_denied(cp):
    sf, registry, resources, verifier = cp
    a_token = registry.enroll("a").token
    registry.enroll("b")
    registry.revoke_certificate("b", reason="compromised")
    decision = asyncio.run(_wire(cp).evaluate(_delegation("a", a_token, "b")))
    assert decision.outcome == Outcome.deny
    assert any(r.code == "agent_card_unverified" for r in decision.reasons)


def test_a_denied_delegation_is_audited(cp):
    sf, registry, resources, verifier = cp
    a_token = registry.enroll("a").token
    decision = asyncio.run(_wire(cp).evaluate(_delegation("a", a_token, "ghost")))
    assert decision.evidence_ref is not None


def test_non_delegation_actions_skip_card_verification(cp):
    """A tool call has no peer to verify — the SEC-10 stage must not touch it."""
    sf, registry, resources, verifier = cp
    token = registry.enroll("a").token
    action = AgentAction(
        agent_id="a", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""}, identity_token=token,
    )
    decision = asyncio.run(_wire(cp).evaluate(action))
    assert decision.outcome == Outcome.allow
    assert not any(r.code.startswith("agent_card") for r in decision.reasons)
