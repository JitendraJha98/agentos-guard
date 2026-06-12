"""SEC-13 end-to-end: sequence matches fire the compiled constitution floor.

Principle 3.5 (kind: sequence, [RESOURCE_RENAME, DATA_DESTRUCTION] -> deny) is a
REAL deterministic floor: the correlator's match feeds input.sequence.matched_refs,
the compiled membership rule fires, and citation + remediation flow through the
ordinary matched-principle machinery.
"""

import asyncio

import pytest

from _opa import find_opa
from agentos_contract import ActionContext, ActionType, AgentAction, Outcome

pytestmark = pytest.mark.skipif(find_opa() is None, reason="no OPA binary")

ALLOWED = "https://api.example.com/db"


def _act(wired, target, conversation="wedge-conv"):
    return AgentAction(
        agent_id=wired.agent_id,
        type=ActionType.tool_call,
        target=target,
        payload={"url": ALLOWED},
        context=ActionContext(conversation_id=conversation),
        identity_token=wired.token,
    )


def test_rename_then_drop_denied_citing_3_5_with_remediation(pipeline_with_principle):
    w = pipeline_with_principle
    first = asyncio.run(w.pipeline.evaluate(_act(w, "rename_table")))
    assert first.outcome is Outcome.allow            # individually permitted
    second = asyncio.run(w.pipeline.evaluate(_act(w, "drop_table")))
    assert second.outcome is Outcome.deny            # the SEQUENCE is forbidden
    refs = {r.principle_ref for r in second.reasons if r.stage == "policy"}
    assert "3.5" in refs
    assert any("temporary exception" in hint for hint in second.remediation)


def test_drop_first_in_fresh_conversation_does_not_fire_3_5(pipeline_with_principle):
    w = pipeline_with_principle
    d = asyncio.run(w.pipeline.evaluate(_act(w, "drop_table", conversation="fresh")))
    refs = {r.principle_ref for r in d.reasons if r.stage == "policy"}
    assert "3.5" not in refs
    # 2.1 (destructive intent -> require_approval) still governs the single action.
    assert "2.1" in refs and d.outcome is Outcome.require_approval


def test_unwired_pipeline_unchanged(pipeline_without_principle):
    # The no-egress fixture is wired WITHOUT sequences: no correlator, no 3.5.
    w = pipeline_without_principle
    asyncio.run(w.pipeline.evaluate(_act(w, "rename_table")))
    d = asyncio.run(w.pipeline.evaluate(_act(w, "drop_table")))
    refs = {r.principle_ref for r in d.reasons if r.stage == "policy"}
    assert "3.5" not in refs
