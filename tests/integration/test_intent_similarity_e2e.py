"""SEC-14 through the pipeline: ambiguity-gated, advisory, never a floor override."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_contract.policy_io import ConstitutionResult
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.intent_similarity import ForbiddenExemplar, IntentSimilarityClassifier
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline

EXEMPLARS = [
    ForbiddenExemplar("DATA_DESTRUCTION", "permanently delete every customer record from the database"),
]


class _AllowAllPolicy:
    constitution_version = "c"
    policy_version = "p"

    def evaluate(self, _input: dict) -> ConstitutionResult:
        return ConstitutionResult(matched=(), no_match=True)


def _wire(classifier=None) -> tuple[Pipeline, Registry]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    registry = Registry(sf)
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=_AllowAllPolicy(),
        scorers=[],
        audit=AuditWriter(sf),
        thresholds=GraduatedThresholds(),
        posture=PostureMap(),
        intent_classifier=classifier,
    )
    return pipeline, registry


def _tool(token: str, target: str, content: str = "") -> AgentAction:
    return AgentAction(
        agent_id="a1", type=ActionType.tool_call, target=target,
        payload={"url": "https://api.example.com/x", "content": content}, identity_token=token,
    )


def test_untagged_action_near_a_forbidden_exemplar_is_flagged_advisorily():
    clf = IntentSimilarityClassifier(EXEMPLARS, threshold=0.5)
    pipeline, registry = _wire(clf)
    token = registry.register("a1")

    # target "fetch_thing" is NOT a deterministic destruction/rename tag (ambiguous),
    # but the content paraphrases the forbidden exemplar.
    decision = asyncio.run(
        pipeline.evaluate(_tool(token, "fetch_thing", "permanently delete all customer records now"))
    )

    assert decision.inferred_intent == "DATA_DESTRUCTION"
    assert any(r.code == "forbidden_intent_similarity" for r in decision.reasons)
    # Advisory: risk raised, but with an allow-all policy floor the probabilistic
    # signal alone sandboxes at most — it never forces a hard deny.
    assert decision.outcome in (Outcome.sandbox, Outcome.allow)
    assert decision.risk_score >= 0.5


def test_classifier_does_not_run_when_the_deterministic_tag_is_present():
    """SEC-14 runs ONLY on ambiguity — a deterministically-tagged action skips it,
    keeping the exact tag rather than a probabilistic one."""
    clf = IntentSimilarityClassifier(EXEMPLARS, threshold=0.01)  # would match anything
    pipeline, registry = _wire(clf)
    token = registry.register("a1")

    # "drop_table" IS a deterministic DATA_DESTRUCTION tag.
    decision = asyncio.run(pipeline.evaluate(_tool(token, "drop_table")))

    assert decision.inferred_intent == "DATA_DESTRUCTION"
    assert not any(r.code == "forbidden_intent_similarity" for r in decision.reasons)


def test_unrelated_untagged_action_is_not_flagged():
    clf = IntentSimilarityClassifier(EXEMPLARS, threshold=0.6)
    pipeline, registry = _wire(clf)
    token = registry.register("a1")

    decision = asyncio.run(pipeline.evaluate(_tool(token, "fetch_thing", "summarize the report")))
    assert decision.inferred_intent is None
    assert not any(r.code == "forbidden_intent_similarity" for r in decision.reasons)


def test_pipeline_without_a_classifier_is_unchanged():
    pipeline, registry = _wire(None)
    token = registry.register("a1")
    decision = asyncio.run(pipeline.evaluate(_tool(token, "fetch_thing", "delete all records")))
    assert not any(r.code == "forbidden_intent_similarity" for r in decision.reasons)


def test_similarity_never_overrides_a_deterministic_policy_deny():
    """Advisory invariant: a matched similarity must not relax a policy deny."""

    class _DenyPolicy:
        constitution_version = "c"
        policy_version = "p"

        def evaluate(self, _input: dict) -> ConstitutionResult:
            from agentos_contract.policy_io import MatchedPrinciple

            return ConstitutionResult(matched=(MatchedPrinciple(principle_ref="1.1", effect="deny"),), no_match=False)

    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    registry = Registry(sf)
    token = registry.register("a1")
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=_DenyPolicy(),
        scorers=[],
        audit=AuditWriter(sf),
        thresholds=GraduatedThresholds(),
        posture=PostureMap(),
        intent_classifier=IntentSimilarityClassifier(EXEMPLARS, threshold=0.5),
    )
    decision = asyncio.run(pipeline.evaluate(_tool(token, "fetch_thing", "delete all customer records")))
    assert decision.outcome == Outcome.deny
