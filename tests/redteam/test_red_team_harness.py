"""Unit tests for the SDK red-team adapter (SDK-03 / TEST-01) — the corpus + the
ASR arithmetic over a STUB evaluator.

These tests pin the deterministic contract of `agentos_sdk.redteam` WITHOUT the real
pipeline: a stub `async evaluate(action) -> Decision` with a fixed outcome lets us
assert exactly how `run_suite` builds each AgentAction, scores blocked/not-blocked
against `BLOCKING_OUTCOMES`, and computes `attack_success_rate`. The suites-vs-the-real
-governed-pipeline proof (ASR 0) lives in test_red_team_suites.py.
"""

import asyncio

import pytest

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_sdk import (
    BLOCKING_OUTCOMES,
    Attack,
    AttackResult,
    Results,
    run_suite,
    suites,
)
from agentos_sdk.redteam import SUITES


def _stub(outcome: Outcome, sink: list | None = None):
    """An async `evaluate(action) -> Decision` seam returning a FIXED outcome.

    Deterministic, no LLM/network — exactly the structural seam `run_suite` calls.
    If `sink` is given, every received AgentAction is appended for inspection.
    """

    async def evaluate(action: AgentAction) -> Decision:
        if sink is not None:
            sink.append(action)
        return Decision(action_id=action.id, outcome=outcome)

    return evaluate


def test_suites_lists_the_four_curated_suites() -> None:
    assert suites() == ["exfiltration", "jailbreak", "prompt_injection", "tool_misuse"]


def test_blocking_outcomes_is_the_documented_set() -> None:
    # The action does not run UNCHANGED under any of these; everything else lets it proceed.
    assert BLOCKING_OUTCOMES == frozenset(
        {
            Outcome.deny,
            Outcome.sandbox,
            Outcome.require_approval,
            Outcome.require_consensus,
        }
    )


@pytest.mark.parametrize("suite", suites())
def test_every_suite_has_at_least_two_attacks(suite: str) -> None:
    assert len(SUITES[suite]) >= 2


@pytest.mark.parametrize("suite", suites())
def test_deny_stub_blocks_every_attack_asr_zero(suite: str) -> None:
    results = asyncio.run(run_suite(_stub(Outcome.deny), suite, agent_id="a", token="t"))
    assert results.total == len(SUITES[suite])
    assert all(r.blocked for r in results.results)
    assert results.attack_success_rate == 0.0


@pytest.mark.parametrize("suite", suites())
def test_allow_stub_blocks_nothing_asr_one(suite: str) -> None:
    results = asyncio.run(run_suite(_stub(Outcome.allow), suite, agent_id="a", token="t"))
    assert not any(r.blocked for r in results.results)
    assert results.attack_success_rate == 1.0


@pytest.mark.parametrize(
    "outcome, blocked",
    [
        (Outcome.deny, True),
        (Outcome.sandbox, True),
        (Outcome.require_approval, True),
        (Outcome.require_consensus, True),
        (Outcome.allow, False),
        (Outcome.warn, False),
        (Outcome.temporary_exception, False),
        (Outcome.governance_review, False),
    ],
)
def test_outcome_classification_matches_blocking_set(outcome: Outcome, blocked: bool) -> None:
    results = asyncio.run(run_suite(_stub(outcome), "exfiltration", agent_id="a", token="t"))
    assert all(r.blocked is blocked for r in results.results)
    # ASR is the fraction NOT blocked: 0.0 when every attack is blocked, else 1.0 here.
    assert results.attack_success_rate == (0.0 if blocked else 1.0)


def test_run_suite_builds_actions_from_the_attack_and_wiring() -> None:
    sink: list[AgentAction] = []
    asyncio.run(run_suite(_stub(Outcome.deny, sink), "jailbreak", agent_id="agent-x", token="tok-y"))
    corpus = SUITES["jailbreak"]
    assert len(sink) == len(corpus)
    for action, atk in zip(sink, corpus):
        assert isinstance(action, AgentAction)
        assert action.agent_id == "agent-x"
        assert action.identity_token == "tok-y"
        assert action.type is atk.action_type
        assert action.target == atk.target
        assert action.payload == atk.payload


def test_attack_result_carries_id_suite_and_outcome_string() -> None:
    results = asyncio.run(run_suite(_stub(Outcome.deny), "exfiltration", agent_id="a", token="t"))
    first = results.results[0]
    assert isinstance(first, AttackResult)
    assert first.suite == "exfiltration"
    assert first.attack_id == SUITES["exfiltration"][0].id
    assert first.outcome == "deny"
    assert first.blocked is True


def test_unknown_suite_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        asyncio.run(run_suite(_stub(Outcome.deny), "nope", agent_id="a", token="t"))


def test_empty_results_has_zero_asr() -> None:
    # The vacuous case must not divide by zero (0/0 -> 0.0, no attack slipped).
    empty = Results(())
    assert empty.total == 0
    assert empty.attack_success_rate == 0.0


def test_attack_and_results_are_frozen() -> None:
    atk = SUITES["exfiltration"][0]
    assert isinstance(atk, Attack)
    with pytest.raises(Exception):
        atk.id = "mutated"  # frozen dataclass -> FrozenInstanceError
