"""TRST-03 end-to-end: real audit history -> derived reputation -> graduated band.

The unit tests score synthetic signals. This drives the real path: actions are
audited through the real `AuditWriter`, `ReputationEngine` replays that log, and
`Registry.load_trust` — the exact call the pipeline's identity stage makes — must
return the derived score.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import DEFAULT_TRUST_SCORE, Registry
from agentos_controlplane.reputation import ReputationEngine, UnknownAgentError
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.graduated import GraduatedThresholds, graduated_response


@pytest.fixture()
def wired():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    return sf, Registry(sf), AuditWriter(sf), ReputationEngine(sf)


def _action(agent_id: str) -> AgentAction:
    return AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""},
    )


async def _audit(writer: AuditWriter, agent_id: str, *outcomes: Outcome) -> None:
    for o in outcomes:
        action = _action(agent_id)
        decision = Decision(
            action_id=action.id, outcome=o, risk_score=0.0, trust_score=0.5, reasons=[]
        )
        await writer.append(action, decision)


def test_clean_agent_earns_trust_above_its_seed(wired):
    sf, registry, writer, reputation = wired
    registry.register("clean")
    asyncio.run(_audit(writer, "clean", *([Outcome.allow] * 12)))

    result = reputation.refresh("clean")

    assert result.score > DEFAULT_TRUST_SCORE
    assert registry.load_trust("clean") == pytest.approx(result.score)


def test_offending_agent_is_demoted_and_the_pipeline_sees_it(wired):
    """The requirement's actual verb: reputation FEEDS the graduated band."""
    sf, registry, writer, reputation = wired
    registry.register("bad")
    asyncio.run(_audit(writer, "bad", Outcome.deny, Outcome.deny, Outcome.allow))

    result = reputation.refresh("bad")
    assert result.score < 0.2

    # The score reaches graduated response through load_trust...
    trust = registry.load_trust("bad")
    assert trust == pytest.approx(result.score)

    # ...and demoted trust actually tightens the outcome (TRST-02 hardening band):
    # the same mid-risk action that a trusted agent gets sandboxed for now needs a human.
    t = GraduatedThresholds()
    assert graduated_response(Outcome.allow, 0.5, DEFAULT_TRUST_SCORE, t) == Outcome.sandbox
    assert graduated_response(Outcome.allow, 0.5, trust, t) == Outcome.require_approval


def test_reputation_is_per_agent_not_global(wired):
    """One agent's violations must not contaminate another's score."""
    sf, registry, writer, reputation = wired
    registry.register("good")
    registry.register("evil")
    asyncio.run(_audit(writer, "good", *([Outcome.allow] * 10)))
    asyncio.run(_audit(writer, "evil", *([Outcome.deny] * 5)))

    reputation.refresh_all()

    assert registry.load_trust("good") > DEFAULT_TRUST_SCORE
    assert registry.load_trust("evil") < 0.2


def test_agent_with_no_history_keeps_its_seed(wired):
    sf, registry, writer, reputation = wired
    registry.register("fresh", trust_score=0.42)
    assert reputation.refresh("fresh").score == pytest.approx(0.42)
    assert registry.load_trust("fresh") == pytest.approx(0.42)


def test_refresh_preserves_an_operator_configured_band(wired):
    """Reputation owns the score, not the operator's band config."""
    sf, registry, writer, reputation = wired
    registry.register("banded")
    ResourceStore(sf).put_trust_profile(
        "banded", trust_score=0.5, band={"trust_harden_at": 0.3}, expected_version=None
    )
    asyncio.run(_audit(writer, "banded", Outcome.deny))

    reputation.refresh("banded")

    profile = ResourceStore(sf).get_trust_profile("banded")
    assert profile.band == {"trust_harden_at": 0.3}, "reconciler clobbered operator band config"
    assert profile.trust_score < 0.3


def test_refresh_rejects_an_unregistered_agent(wired):
    sf, registry, writer, reputation = wired
    with pytest.raises(UnknownAgentError):
        reputation.refresh("ghost")


def test_lifecycle_event_records_are_not_scored_as_actions(wired):
    """`append_event` rows carry no agent_id/outcome and must not skew reputation."""
    sf, registry, writer, reputation = wired
    registry.register("a1")
    asyncio.run(writer.append_event("approval_resolved", {"approval_id": "x", "status": "approved"}))

    assert reputation.refresh("a1").score == pytest.approx(DEFAULT_TRUST_SCORE)
