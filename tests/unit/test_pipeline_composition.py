"""Composition coverage — a dormant seam is never silent.

`Pipeline` takes twelve OPTIONAL collaborators, and each one left `None` is a stage that
never runs. That is deliberate (every default is backward-compatible), but the failure
directions are NOT symmetric, which is what makes silence dangerous:

  * an unwired ENFORCEMENT seam (sandbox / consensus / approval, in `enforce.py`) fails
    CLOSED — the action is denied;
  * an unwired DETECTION seam (here) fails OPEN — the stage is skipped and the action
    proceeds unchecked.

`kill_switch` is the sharpest case: the stage-0 lookup is the ONLY place kill state is
consulted on the hot path (nothing in the SDK or the gateway checks it independently), so
an operator who forgets that seam gets a fleet whose emergency stop (RUN-01/02) records a
kill and enforces nothing — with every test still green. These tests hold the line on the
composition-time analogue of INT-06's `verify_coverage()`: dormancy stays visible.

Real production collaborators are used wherever one is cheap to construct, because the
point is proving the twelve genuinely COMPOSE — not re-testing behaviour each seam already
owns elsewhere. The policy engine is stubbed so this file needs no OPA toolchain.
"""
from __future__ import annotations

import asyncio
import logging

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction, ConstitutionResult
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.budget import BudgetLedger
from agentos_controlplane.circuit_breaker import CircuitBreakerStore
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.mcp_gateway import MCPGateway
from agentos_controlplane.privilege import PrivilegeRingStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.shadow import ShadowAgentStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.delegation import DelegationResolver
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.interpreter.stub import StubInterpreter
from agentos_pipeline.intent_similarity import IntentSimilarityClassifier
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_pipeline.sequence import SequenceCorrelator

AGENT_ID = "composition-agent"

# The twelve optional seams, by the names `dormant_seams` reports. Spelled out rather than
# derived from the signature so that ADDING a seam without deciding how it is reported
# fails here instead of silently shrinking the guarantee.
ALL_SEAMS = frozenset({
    "interpreter", "exceptions", "correlator", "kill_switch", "delegation", "card_verifier",
    "mcp_quarantine", "intent_classifier", "privilege", "breaker", "shadow", "budget",
})


class StubPolicy:
    """A no-match policy engine: the floor becomes the class posture (PIPE-05)."""

    def evaluate(self, input: dict) -> ConstitutionResult:
        return ConstitutionResult(matched=(), no_match=True)


class StubExceptions:
    def active_for(self, agent_id: str, refs: tuple[str, ...]) -> dict:
        return {}


class StubScope:
    def scope_for(self, agent_id: str) -> frozenset[str]:
        return frozenset({"http_get"})


class StubCardVerifier:
    def card_for(self, action: AgentAction) -> object:
        return object()

    def verify(self, card: object) -> object:
        return type("V", (), {"ok": True, "detail": "stub"})()


def _store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _fully_wired() -> tuple[Pipeline, str]:
    """Every optional seam wired — real collaborators where construction is cheap."""
    sf = _store()
    registry = Registry(sf)
    token = registry.register(AGENT_ID)
    audit = AuditWriter(sf, signer=registry.identity)
    privilege = PrivilegeRingStore(sf, audit)
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=StubPolicy(),
        scorers=[PromptInjectionScorer()],
        audit=audit,
        posture=PostureMap(),
        interpreter=StubInterpreter(),
        exceptions=StubExceptions(),
        correlator=SequenceCorrelator(),
        kill_switch=KillSwitchStore(sf, audit),
        delegation=DelegationResolver(StubScope()),
        card_verifier=StubCardVerifier(),
        mcp_quarantine=MCPGateway(),
        intent_classifier=IntentSimilarityClassifier([]),
        privilege=privilege,
        breaker=CircuitBreakerStore(sf, audit),
        shadow=ShadowAgentStore(sf, audit),
        budget=BudgetLedger(sf),
    )
    return pipeline, token


def _minimally_wired(**seams) -> Pipeline:
    sf = _store()
    registry = Registry(sf)
    registry.register(AGENT_ID)
    return Pipeline(
        identity=IdentityStage(registry.identity),
        policy=StubPolicy(),
        scorers=[PromptInjectionScorer()],
        audit=AuditWriter(sf, signer=registry.identity),
        posture=PostureMap(),
        **seams,
    )


def test_every_optional_seam_composes_and_reports_no_dormancy() -> None:
    # The finding this closes: no test wired more than 9 of the 12 seams, so "they all
    # compose" was an assumption. Constructing all twelve together is the proof.
    pipeline, _ = _fully_wired()
    assert pipeline.dormant_seams == frozenset()


def test_a_fully_wired_pipeline_still_evaluates_an_action() -> None:
    # Composition that constructs but cannot decide would be a worse trap than dormancy.
    pipeline, token = _fully_wired()
    action = AgentAction(
        agent_id=AGENT_ID, type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/data", "content": ""},
        identity_token=token,
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is not None and decision.reasons


def test_dormant_seams_names_exactly_what_was_left_unwired() -> None:
    assert _minimally_wired().dormant_seams == ALL_SEAMS


def test_wiring_one_seam_removes_exactly_it_from_the_dormant_set() -> None:
    sf = _store()
    registry = Registry(sf)
    registry.register(AGENT_ID)
    audit = AuditWriter(sf, signer=registry.identity)
    pipeline = _minimally_wired(kill_switch=KillSwitchStore(sf, audit))
    assert pipeline.dormant_seams == ALL_SEAMS - {"kill_switch"}


def test_sequences_alone_activate_the_correlator_seam() -> None:
    # The one derived seam: `sequences` without a `correlator` builds the default, so the
    # correlator must report LIVE — dormancy has to describe what actually runs.
    pipeline = _minimally_wired(sequences=[{"name": "s", "steps": ["a", "b"]}])
    assert "correlator" not in pipeline.dormant_seams


def test_construction_warns_and_names_a_dormant_kill_switch(caplog) -> None:
    # Silence is the defect being fixed; the warning must name the seam, not just count.
    with caplog.at_level(logging.WARNING, logger="agentos_pipeline.runner"):
        _minimally_wired()
    assert "kill_switch" in caplog.text and "DORMANT" in caplog.text


def test_a_fully_wired_pipeline_warns_about_nothing(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="agentos_pipeline.runner"):
        _fully_wired()
    assert "DORMANT" not in caplog.text


@pytest.mark.parametrize("seam", sorted(ALL_SEAMS))
def test_no_seam_is_silently_untracked(seam: str) -> None:
    # Guards the ALL_SEAMS list itself: every name it claims must really be reported when
    # unwired, so a renamed constructor argument cannot quietly drop out of the report.
    assert seam in _minimally_wired().dormant_seams
