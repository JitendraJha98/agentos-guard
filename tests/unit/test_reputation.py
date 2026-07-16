"""TRST-03 — longitudinal reputation derived from violation/approval history.

The properties that matter (and why):

  * no history -> the seed (no evidence must not manufacture an opinion);
  * clean history climbs, violations sink;
  * RECENCY: an old violation weighs less than a fresh one (time heals);
  * ANTI-FARMING (Pitfall 10, the invariant `graduated.py` already defends in its
    trust band): no volume of compliant calls may dilute a recent violation. This
    is asserted explicitly at 1000:1 — the exact shape of a trust-farming attack.
  * the score reaches the graduated-response band through `load_trust`.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentos_contract import Outcome
from agentos_controlplane.registry import DEFAULT_TRUST_SCORE, Registry
from agentos_controlplane.reputation import (
    HALF_LIFE_S,
    ReputationScorer,
    ReputationSignal,
)
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.models import Base

DAY = 86400.0


@pytest.fixture()
def sf():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _sig(outcome: Outcome, age_s: float = 0.0) -> ReputationSignal:
    return ReputationSignal(kind="audit", label=outcome.value, age_s=age_s)


def _approval(status: str, age_s: float = 0.0) -> ReputationSignal:
    return ReputationSignal(kind="approval", label=status, age_s=age_s)


# ---------------------------------------------------------------- scoring core


def test_no_history_returns_the_seed_not_an_invented_score():
    """No evidence must not manufacture an opinion — fall back to the seed."""
    assert ReputationScorer().score([], seed=DEFAULT_TRUST_SCORE) == DEFAULT_TRUST_SCORE
    assert ReputationScorer().score([], seed=0.9) == 0.9


def test_clean_history_climbs_above_the_seed():
    score = ReputationScorer().score([_sig(Outcome.allow) for _ in range(10)])
    assert score > DEFAULT_TRUST_SCORE


def test_violations_sink_the_score():
    score = ReputationScorer().score([_sig(Outcome.deny) for _ in range(3)])
    assert score < 0.1


def test_human_denied_approval_is_the_strongest_negative_signal():
    """A human judging an action bad outweighs a machine deny."""
    human = ReputationScorer().score([_approval("denied")])
    machine = ReputationScorer().score([_sig(Outcome.deny)])
    assert human < machine


def test_human_approved_action_is_a_positive_signal():
    vouched = ReputationScorer().score([_approval("approved") for _ in range(5)])
    assert vouched > DEFAULT_TRUST_SCORE


def test_score_is_always_bounded_0_1():
    for signals in (
        [_sig(Outcome.allow)] * 5000,
        [_sig(Outcome.deny)] * 5000,
        [_approval("denied")] * 100 + [_sig(Outcome.allow)] * 100,
    ):
        score = ReputationScorer().score(signals)
        assert 0.0 <= score <= 1.0


# ------------------------------------------------------------------- longitudinal


def test_recency_a_fresh_violation_hurts_more_than_an_old_one():
    """The 'longitudinal' in TRST-03: time-decayed, so recent conduct dominates."""
    fresh = ReputationScorer().score([_sig(Outcome.deny, age_s=0.0)])
    old = ReputationScorer().score([_sig(Outcome.deny, age_s=10 * HALF_LIFE_S)])
    assert fresh < old


def test_a_violation_heals_back_toward_clean_after_enough_half_lives():
    """Time heals: an ancient deny among clean traffic must not pin the agent down."""
    signals = [_sig(Outcome.deny, age_s=20 * HALF_LIFE_S)] + [
        _sig(Outcome.allow, age_s=i * 60.0) for i in range(20)
    ]
    assert ReputationScorer().score(signals) > DEFAULT_TRUST_SCORE


# ------------------------------------------------------------- anti-farming (P10)


def test_trust_farming_is_structurally_impossible():
    """Pitfall 10. 1000 compliant calls must NOT wash out one fresh violation.

    This is the property that separates a reputation engine from a success-rate
    counter: good behaviour is diluted by volume, a violation is not.
    """
    farmed = ReputationScorer().score(
        [_sig(Outcome.deny, age_s=0.0)] + [_sig(Outcome.allow, age_s=1.0)] * 1000
    )
    assert farmed <= 0.25, f"farming worked: 1000 allows lifted a fresh deny to {farmed}"


def test_more_violations_monotonically_lower_the_ceiling():
    scorer = ReputationScorer()
    scores = [scorer.score([_sig(Outcome.deny)] * n) for n in (1, 2, 4, 8)]
    assert scores == sorted(scores, reverse=True)


# ------------------------------------------------- feeds the graduated band (the point)


def test_reputation_reaches_the_pipeline_through_load_trust(sf):
    """TRST-03's actual requirement: the derived score FEEDS graduated response.

    Regression lock for the Phase-5 disconnect: the operator-facing trust route wrote
    `trust_profile` while `load_trust` read `agent.trust_score`, so a graded agent kept
    its seed trust in the pipeline.
    """
    registry, resources = Registry(sf), ResourceStore(sf)
    registry.register("a1")
    assert registry.load_trust("a1") == DEFAULT_TRUST_SCORE

    resources.put_trust_profile("a1", trust_score=0.05, band=None, expected_version=None)
    assert registry.load_trust("a1") == 0.05, "graded trust must reach the pipeline"


def test_load_trust_falls_back_to_the_agent_seed_when_no_profile_exists(sf):
    registry = Registry(sf)
    registry.register("a2", trust_score=0.7)
    assert registry.load_trust("a2") == 0.7


def test_unknown_agent_is_zero_trust(sf):
    """Fail-closed: an unregistered agent gets no benefit of the doubt."""
    assert Registry(sf).load_trust("ghost") == 0.0
