"""TEST-09 — campaign-style multi-step attacks.

Single-shot probes cannot reach the SEC-13 correlator at all: each step of a campaign passes on
its own merits, and only the SEQUENCE is the attack. So this file proves two different things.
The stub half pins the runner's contract (one shared conversation, stop at the first block, the
blocking STEP recorded). The governed half runs `rename_then_drop` against the REAL pipeline and
shows it is refused by the sequence rule — without that, the corpus would be multi-step in shape
and adversarial in nothing.

Deterministic: no LLM, no network — a fixed corpus over stubs plus the pure-CPU pipeline.
"""

from __future__ import annotations

import asyncio

import pytest

from agentos_contract import AgentAction, Decision, Outcome
from agentos_sdk.redteam import CAMPAIGNS, campaigns, run_campaign


class _Seam:
    """A stub `evaluate` seam that ALSO exposes the handler `run_campaign` must never reach.

    `handler` raises if awaited: spec D-1 says validation asks the guard what it *would* decide
    and never executes the payload, so an execution path appearing here has to fail loudly rather
    than quietly perform the exfiltration it was checking for.
    """

    def __init__(self, *outcomes: Outcome) -> None:
        self._outcomes = outcomes
        self.seen: list[AgentAction] = []

    async def __call__(self, action: AgentAction) -> Decision:
        self.seen.append(action)
        outcome = self._outcomes[min(len(self.seen) - 1, len(self._outcomes) - 1)]
        return Decision(action_id=action.id, outcome=outcome)

    async def handler(self, *args, **kwargs):
        raise AssertionError("run_campaign executed an attack payload (spec D-1 violated)")


@pytest.fixture
def allow_everything() -> _Seam:
    return _Seam(Outcome.allow)


@pytest.fixture
def recording_evaluate() -> _Seam:
    return _Seam(Outcome.allow)


@pytest.fixture
def blocking_at_step_0() -> _Seam:
    return _Seam(Outcome.deny)


@pytest.fixture
def blocking_at_step_1() -> _Seam:
    return _Seam(Outcome.allow, Outcome.deny)


# --- the runner's contract, over stubs ------------------------------------------------------


def test_every_step_shares_one_conversation_id(recording_evaluate: _Seam) -> None:
    """The correlator windows on conversation_id. Without a shared one the campaign silently
    degrades into N single-shot probes that merely run in order — it would pass for the wrong
    reason and prove nothing about SEC-13."""
    asyncio.run(run_campaign(recording_evaluate, "rename_then_drop", agent_id="a1", token="t"))

    ids = {a.context.conversation_id for a in recording_evaluate.seen}
    assert len(ids) == 1 and next(iter(ids))


def test_separate_runs_do_not_share_a_conversation_id(recording_evaluate: _Seam) -> None:
    """The window is per-conversation and has no TTL, so a reused id would leave one run's
    rename lying in the window for the next run's delete — a later campaign would 'catch' a
    sequence its own steps never formed."""
    asyncio.run(run_campaign(recording_evaluate, "rename_then_drop", agent_id="a1", token="t"))
    first = recording_evaluate.seen[0].context.conversation_id
    recording_evaluate.seen.clear()
    asyncio.run(run_campaign(recording_evaluate, "rename_then_drop", agent_id="a1", token="t"))

    assert recording_evaluate.seen[0].context.conversation_id != first


def test_the_campaign_stops_at_the_first_block(blocking_at_step_0: _Seam) -> None:
    """A real attacker whose step was refused does not get to run the next one. Continuing would
    score a sequence that could not have happened — so the later steps are never evaluated."""
    result = asyncio.run(
        run_campaign(blocking_at_step_0, "recon_then_exfil", agent_id="a1", token="t")
    )

    assert result.blocked_at_step == 0
    assert result.steps_run == 1
    assert len(blocking_at_step_0.seen) == 1, "the step after the block was still evaluated"
    assert result.outcomes == ("deny",)


def test_steps_before_the_block_are_run_and_counted(blocking_at_step_1: _Seam) -> None:
    result = asyncio.run(
        run_campaign(blocking_at_step_1, "recon_then_exfil", agent_id="a1", token="t")
    )

    assert result.blocked_at_step == 1 and result.steps_run == 2
    assert result.outcomes == ("allow", "deny")


def test_the_step_it_was_blocked_at_is_recorded_not_just_that_it_was(
    blocking_at_step_1: _Seam,
) -> None:
    """THE property of this slice. Blocked-at-step-1 (opening move caught) and blocked-at-the-last
    step (every hostile action before it permitted) are both "blocked", and only one is good news."""
    result = asyncio.run(
        run_campaign(blocking_at_step_1, "recon_then_exfil", agent_id="a1", token="t")
    )

    assert result.blocked is True
    assert result.steps_permitted == 1, "one hostile step was permitted before the stop"


def test_an_unblocked_campaign_reports_no_blocking_step(allow_everything: _Seam) -> None:
    result = asyncio.run(
        run_campaign(allow_everything, "rename_then_drop", agent_id="a1", token="t")
    )

    assert result.blocked_at_step is None and result.blocked is False
    assert result.steps_permitted == result.steps_run == len(CAMPAIGNS["rename_then_drop"].steps)


def test_the_campaign_id_and_wiring_travel_with_the_result(allow_everything: _Seam) -> None:
    result = asyncio.run(
        run_campaign(allow_everything, "rename_then_drop", agent_id="agent-x", token="tok-y")
    )

    assert result.campaign_id == "rename_then_drop"
    for action, step in zip(allow_everything.seen, CAMPAIGNS["rename_then_drop"].steps):
        assert action.agent_id == "agent-x"
        assert action.identity_token == "tok-y"
        assert action.type is step.action_type
        assert action.target == step.target
        assert action.payload == step.payload


def test_nothing_executes_an_attack(allow_everything: _Seam) -> None:
    """Spec D-1. `run_campaign` takes an `evaluate` seam and must never reach a handler — the
    seam's `handler` raises if awaited, and the signature carries no execution parameter it
    could be handed one through."""
    import inspect

    asyncio.run(run_campaign(allow_everything, "rename_then_drop", agent_id="a1", token="t"))

    assert list(inspect.signature(run_campaign).parameters) == [
        "evaluate",
        "campaign",
        "agent_id",
        "token",
    ]


def test_an_unknown_campaign_is_refused(allow_everything: _Seam) -> None:
    with pytest.raises(KeyError):
        asyncio.run(run_campaign(allow_everything, "no-such-campaign", agent_id="a1", token="t"))


def test_campaigns_lists_the_shipped_corpus() -> None:
    assert campaigns() == sorted(CAMPAIGNS)


@pytest.mark.parametrize("name", sorted(CAMPAIGNS))
def test_every_shipped_campaign_has_at_least_two_steps(name: str) -> None:
    """A one-step campaign is a single-shot probe wearing a different name, and would let the
    suite claim multi-step coverage it does not have."""
    assert len(CAMPAIGNS[name].steps) >= 2


# --- the governed half: the corpus vs the REAL pipeline ---------------------------------------


def _capturing(wired):
    """Wrap the real `evaluate` seam so the test can read the Decision `run_campaign` scored."""
    decisions: list[Decision] = []

    async def evaluate(action: AgentAction) -> Decision:
        decision = await wired.pipeline.evaluate(action)
        decisions.append(decision)
        return decision

    return evaluate, decisions


def test_rename_then_drop_is_blocked_by_the_sequence_rule(pipeline_with_principle) -> None:
    """The point of the slice (SEC-13). The rename is permitted — it is a benign chore on its own
    merits — and the delete that follows it in the SAME conversation is denied by principle 3.5.
    No single-shot probe can reach that code path, so without this the corpus would be multi-step
    in shape and prove nothing about the correlator."""
    wired = pipeline_with_principle
    evaluate, decisions = _capturing(wired)

    result = asyncio.run(
        run_campaign(evaluate, "rename_then_drop", agent_id=wired.agent_id, token=wired.token)
    )

    assert result.blocked_at_step == 1, "the opening rename must be genuinely permitted"
    assert result.outcomes == ("allow", "deny")
    assert any(
        r.stage == "policy" and r.principle_ref == "3.5" for r in decisions[-1].reasons
    ), f"not blocked by the sequence rule: {[(r.stage, r.principle_ref) for r in decisions[-1].reasons]}"


def test_the_drop_alone_does_not_fire_the_sequence_rule(pipeline_with_principle) -> None:
    """Proof-of-life for the test above (the D-04 pattern): the delete in its OWN conversation
    still trips 2.1's destructive-intent floor, but 3.5 does NOT fire and the outcome is only
    `require_approval`. So the deny above is attributable to the PRECEDING rename — the sequence —
    and not to the delete being independently forbidden."""
    wired = pipeline_with_principle
    drop = CAMPAIGNS["rename_then_drop"].steps[-1]
    action = AgentAction(
        agent_id=wired.agent_id,
        type=drop.action_type,
        target=drop.target,
        payload=drop.payload,
        identity_token=wired.token,
    )

    decision = asyncio.run(wired.pipeline.evaluate(action))

    assert not any(r.principle_ref == "3.5" for r in decision.reasons)
    assert decision.outcome is Outcome.require_approval


def test_recon_then_exfil_permits_the_recon_and_stops_the_exfil(pipeline_with_principle) -> None:
    """The second campaign shape: step 1 targets an ALLOWLISTED host so the egress floor cannot
    fire and the recon is genuinely permitted. `steps_permitted == 1` is the honest score — one
    hostile step got through before the guard stopped the sequence."""
    wired = pipeline_with_principle

    result = asyncio.run(
        run_campaign(
            wired.pipeline.evaluate, "recon_then_exfil", agent_id=wired.agent_id, token=wired.token
        )
    )

    assert result.blocked is True
    assert result.blocked_at_step == 1 and result.steps_permitted == 1
