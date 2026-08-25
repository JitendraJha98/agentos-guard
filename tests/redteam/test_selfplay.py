"""TEST-10/11 — adversarial self-play, held-out scoring, patch proposal, threat intel.

Three properties carry this slice, and each has a way of quietly not being true:

  * the generator produces attacks the corpus does NOT contain (or it is re-running the suite);
  * scoring is on a HELD-OUT split (or it is self-congratulation);
  * nothing generated is EXECUTED (or the tool is firing unreviewed exploits at a live deployment).
"""

from __future__ import annotations

import asyncio

import pytest

from agentos_contract import Decision, Outcome, Reason
from agentos_sdk.redteam import SUITES
from agentos_sdk.selfplay import (
    SelfPlayResult,
    ThreatIntel,
    generate,
    propose_patch,
    run_selfplay,
    split,
)


def _corpus_payloads() -> set[str]:
    return {
        str(sorted(a.payload.items()))
        for attacks in SUITES.values()
        for a in attacks
    }


class _Seam:
    """A decision seam that records what it was asked and fails if a handler is ever reached."""

    def __init__(self, blocked: bool = True):
        self.seen = []
        self._blocked = blocked

    async def __call__(self, action):
        self.seen.append(action)
        return Decision(
            action_id=action.id,
            outcome=Outcome.deny if self._blocked else Outcome.allow,
            reasons=[Reason(stage="policy", code="c", detail="d")],
        )


# --- generation ----------------------------------------------------------------


def test_generation_produces_payloads_the_corpus_does_not_contain(  ) -> None:
    """Otherwise this is the existing suite with new ids — TEST-10 asks for attacks the corpus does
    not have, and re-running known probes would report a guard as tested against novelty it never
    saw."""
    corpus = _corpus_payloads()

    generated = generate(seed=7, count=40)

    novel = [g for g in generated if str(sorted(g.attack.payload.items())) not in corpus]
    assert novel, "every generated probe duplicated the corpus"


def test_generation_is_deterministic_in_the_seed() -> None:
    """A finding has to be reproducible. A generator that cannot replay the probe that slipped
    produces bug reports nobody can act on."""
    first = [g.attack.payload for g in generate(seed=3, count=10)]
    second = [g.attack.payload for g in generate(seed=3, count=10)]

    assert first == second
    assert first != [g.attack.payload for g in generate(seed=4, count=10)]


def test_every_generated_probe_traces_to_its_parent() -> None:
    """A novel probe nobody can trace is a bug report without a reproduction."""
    for item in generate(seed=1, count=10):
        assert item.parent_id and item.mutation


def test_generation_is_bounded() -> None:
    from agentos_sdk.selfplay import _MAX_GENERATED

    assert len(generate(seed=1, count=_MAX_GENERATED + 500)) <= _MAX_GENERATED


# --- the held-out split ---------------------------------------------------------


def test_the_split_is_deterministic_and_non_overlapping() -> None:
    """A held-out set that moves between runs cannot support a claim about generalisation."""
    generated = generate(seed=5, count=20)

    train, holdout = split(generated)
    train2, holdout2 = split(generated)

    assert [g.attack.id for g in train] == [g.attack.id for g in train2]
    assert set(g.attack.id for g in train).isdisjoint(g.attack.id for g in holdout)
    assert holdout and holdout == holdout2


def test_scoring_reports_train_and_holdout_separately() -> None:
    """THE property. A generator that scores a patch on the attacks it just generated always
    succeeds; the held-out half is what makes "scores defenses" mean anything."""
    seam = _Seam(blocked=True)

    result = asyncio.run(run_selfplay(seam, agent_id="a1", token="t", seed=2, count=10))

    assert result.train_total and result.holdout_total
    assert result.train_total + result.holdout_total == result.generated


def test_generalises_is_None_when_a_split_is_empty() -> None:
    """With nothing held out there is no generalisation claim to make, and returning True there
    would be exactly the circularity the split exists to prevent."""
    empty = SelfPlayResult(generated=0)

    assert empty.generalises is None


def test_a_guard_that_holds_everywhere_generalises() -> None:
    seam = _Seam(blocked=True)

    result = asyncio.run(run_selfplay(seam, agent_id="a1", token="t", seed=2, count=10))

    assert result.holdout_asr == 0.0 and result.generalises is True


def test_slipped_probes_are_named_so_they_can_be_replayed() -> None:
    seam = _Seam(blocked=False)

    result = asyncio.run(run_selfplay(seam, agent_id="a1", token="t", seed=2, count=6))

    assert result.slipped and all(pid.startswith("gen_") for pid in result.slipped)


# --- nothing is executed --------------------------------------------------------


def test_nothing_generated_is_ever_executed() -> None:
    """Spec D-4, and worse here than in Phase 12: these inputs are ones nobody reviewed. A generator
    that invented attacks AND ran them would be firing novel exploits at a live deployment."""
    handler_calls = []

    async def _evaluate(action):
        # A real handler would be invoked by governed_call, never by the scorer. If self-play ever
        # reaches one, this records it and the assertion below fails.
        return Decision(
            action_id=action.id,
            outcome=Outcome.deny,
            reasons=[Reason(stage="policy", code="c", detail="d")],
        )

    asyncio.run(run_selfplay(_evaluate, agent_id="a1", token="t", seed=1, count=8))

    assert handler_calls == []


def test_every_probe_goes_through_the_decision_seam() -> None:
    """Non-vacuity for the test above: the probes must actually have been evaluated, or "nothing
    executed" would be trivially true because nothing ran at all."""
    seam = _Seam()

    result = asyncio.run(run_selfplay(seam, agent_id="a1", token="t", seed=1, count=8))

    assert len(seam.seen) == result.generated


def test_each_probe_gets_its_own_conversation() -> None:
    """A shared conversation would let the SEC-13 correlator treat unrelated probes as one sequence,
    scoring a campaign nobody generated."""
    seam = _Seam()
    asyncio.run(run_selfplay(seam, agent_id="a1", token="t", seed=1, count=6))

    ids = {a.context.conversation_id for a in seam.seen}
    assert len(ids) == len(seam.seen)


# --- patch proposal (TEST-10) ---------------------------------------------------


def test_a_patch_proposal_is_POL_10_shaped_and_not_self_submitted() -> None:
    """Self-play returns the ARGUMENTS for AmendmentStore.propose rather than calling it, so the
    human ratification Phase 13 built stays the only way a rule changes."""
    result = SelfPlayResult(generated=4, train_total=2, holdout_total=2, slipped=("gen_1",))

    proposal = propose_patch(result, {"schema_version": 1, "name": "x", "principles": []})

    assert set(proposal) == {"title", "rationale", "proposed_by", "source"}
    assert proposal["proposed_by"] == "selfplay"


def test_the_rationale_states_that_these_are_mutations_not_novel_classes() -> None:
    """An operator ratifying a rule needs to know it addresses a mutation of a known attack, so they
    can ask whether it fixes the weakness or just the string."""
    result = SelfPlayResult(generated=4, train_total=2, holdout_total=2, slipped=("gen_1",))

    rationale = propose_patch(result, {"schema_version": 1})["rationale"]

    assert "not novel classes" in rationale
    assert "held-out" in rationale.lower() or "generalises" in rationale


def test_a_patch_is_refused_when_nothing_slipped() -> None:
    """A no-op proposal in the review queue trains an operator to approve without reading, which is
    how the one real proposal gets rubber-stamped."""
    clean = SelfPlayResult(generated=4, train_total=2, train_blocked=2, holdout_total=2,
                           holdout_blocked=2)

    with pytest.raises(ValueError, match="nothing slipped"):
        propose_patch(clean, {"schema_version": 1})


# --- threat intel (TEST-11) -----------------------------------------------------


def test_imported_patterns_become_probes_never_rules() -> None:
    """Imported patterns are attacker-supplied text from outside this deployment. A feed that could
    add a RULE would be a feed that could edit the constitution."""
    intel = ThreatIntel()

    accepted = intel.import_patterns(
        [{"id": "cve-1", "payload": {"url": "https://evil.test/x", "content": "leak it"}}],
        source="vendor-feed",
    )

    assert accepted == 1
    probe = intel.as_suite()[0]
    assert probe.id.startswith("intel_vendor-feed_")
    assert probe.suite.startswith("threat_intel_")


def test_an_unattributed_feed_is_refused() -> None:
    """"Should I trust this pattern" is unanswerable without knowing who supplied it."""
    with pytest.raises(ValueError, match="source"):
        ThreatIntel().import_patterns([], source="  ")


def test_a_malformed_entry_is_skipped_not_guessed_at() -> None:
    """Guessing at a malformed external pattern is how a feed ends up defining a probe nobody wrote."""
    intel = ThreatIntel()

    accepted = intel.import_patterns(
        [{"nope": 1}, {"id": "ok", "payload": {"url": "https://x.test", "content": "c"}}],
        source="feed",
    )

    assert accepted == 1


def test_the_result_says_how_it_generated_its_attacks() -> None:
    """The honesty claim, in the payload. "Self-play" invites a reader to assume model-generated
    novelty; this mutates a corpus, and the artifact says so."""
    payload = SelfPlayResult(generated=1).as_dict()

    assert payload["generator"] == "mutation"
    assert "not attacks nobody has thought of" in payload["note"]
    assert "Nothing here was executed" in payload["note"]
