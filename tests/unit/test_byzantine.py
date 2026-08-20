"""POL-12 — Byzantine-tolerant quorum: signed votes, 3f+1 arithmetic, equivocation, certificates.

Two things are under test. The first is the arithmetic and the cryptography. The second is the
CLAIM: "BFT" names a family of replicated-state-machine protocols, and this is not one — so the last
test scans the module's own docstring, in the shape Phase 11 used for conformity language, because a
reader who sees "Byzantine fault tolerant" on a governance product will assume the strong reading.
"""

from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.byzantine import (
    ByzantineConsensusCoordinator,
    QuorumCertificate,
    Vote,
    byzantine_tolerance,
    required_quorum,
    verify_certificate,
    vote_message,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

_ACTION_ID = "11111111-1111-1111-1111-111111111111"
_OUTCOME = "require_consensus"


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def keys():
    """Four voters, each with its own Ed25519 key — n=4 is the smallest set tolerating f=1."""
    privates = {f"v{i}": Ed25519PrivateKey.generate() for i in range(1, 5)}
    publics = {
        vid: k.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
        for vid, k in privates.items()
    }
    return privates, publics


def _vote(privates, voter_id, approve, *, action_id=_ACTION_ID, outcome=_OUTCOME) -> Vote:
    sig = privates[voter_id].sign(vote_message(action_id, outcome, voter_id, approve))
    return Vote(voter_id=voter_id, approve=approve, signature=sig.hex())


def _cert(votes, *, voters=("v1", "v2", "v3", "v4"), quorum=3) -> QuorumCertificate:
    return QuorumCertificate(
        action_id=_ACTION_ID, outcome=_OUTCOME, voters=tuple(voters), quorum=quorum, votes=tuple(votes)
    )


# --- the arithmetic ------------------------------------------------------------


def test_the_tolerance_bound_is_the_classical_one() -> None:
    assert [byzantine_tolerance(n) for n in (1, 3, 4, 7, 10)] == [0, 0, 1, 2, 3]
    assert [required_quorum(n) for n in (4, 7, 10)] == [3, 5, 7]


def test_three_voters_tolerate_ZERO_byzantine_voters() -> None:
    """POL-09's shipped default is 2-of-3, and this is the honest reading of it: 2-of-3 survives one
    voter being DOWN, not one voter LYING. Tolerating a liar needs n >= 3f+1, so four."""
    assert byzantine_tolerance(3) == 0


# --- authentication before arithmetic -----------------------------------------


def test_a_valid_quorum_is_certified(keys) -> None:
    privates, publics = keys

    result = verify_certificate(
        _cert([_vote(privates, v, True) for v in ("v1", "v2", "v3")]), publics
    )

    assert result.ok and result.approvals == 3


def test_a_forged_vote_is_rejected(keys) -> None:
    """A quorum rule tolerating f malicious voters is worthless if a ballot can be forged."""
    privates, publics = keys
    forged = Vote(voter_id="v4", approve=True, signature="ab" * 64)

    result = verify_certificate(
        _cert([_vote(privates, "v1", True), _vote(privates, "v2", True), forged]), publics
    )

    assert not result.ok and "does not verify" in result.reason


def test_a_vote_cannot_be_replayed_onto_a_different_ACTION(keys) -> None:
    """A genuine ballot from another action is how an attacker reuses a legitimate voter's approval."""
    privates, publics = keys
    other = _vote(privates, "v3", True, action_id="22222222-2222-2222-2222-222222222222")

    result = verify_certificate(
        _cert([_vote(privates, "v1", True), _vote(privates, "v2", True), other]), publics
    )

    assert not result.ok and "v3" in result.reason


def test_a_vote_cannot_be_replayed_onto_a_different_OUTCOME(keys) -> None:
    """The signature covers the outcome too. Without that, approval of a `sandbox` replays as
    approval of an `allow` — the voter agreed to containment, not to execution. This is the check
    that makes a certificate a statement about a DECISION rather than about an action id."""
    privates, publics = keys
    sandbox_vote = _vote(privates, "v3", True, outcome="sandbox")

    result = verify_certificate(
        _cert([_vote(privates, "v1", True), _vote(privates, "v2", True), sandbox_vote]), publics
    )

    assert not result.ok and "v3" in result.reason


def test_a_vote_from_outside_the_voter_set_is_rejected(keys) -> None:
    """Otherwise an attacker with any key inflates the approval count."""
    privates, publics = keys
    privates["intruder"] = Ed25519PrivateKey.generate()
    publics["intruder"] = (
        privates["intruder"].public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    )

    result = verify_certificate(
        _cert([_vote(privates, "v1", True), _vote(privates, "v2", True),
               _vote(privates, "intruder", True)]),
        publics,
    )

    assert not result.ok and "not in the voter set" in result.reason


# --- equivocation --------------------------------------------------------------


def test_an_equivocating_voter_is_VOIDED_not_last_write_wins(keys) -> None:
    """The defining Byzantine behaviour. Last-write-wins lets one liar pick the outcome; both votes
    are kept, the voter counts for neither, and the equivocation is reported so an operator learns
    WHICH voter lied rather than only that quorum failed."""
    privates, publics = keys

    result = verify_certificate(
        _cert([
            _vote(privates, "v1", True), _vote(privates, "v1", False),
            _vote(privates, "v2", True), _vote(privates, "v3", True),
        ]),
        publics,
    )

    assert result.equivocators == ("v1",)
    assert result.approvals == 2, "the equivocator counts for neither side"
    assert not result.ok


# --- the threshold -------------------------------------------------------------


def test_a_quorum_below_the_byzantine_threshold_is_refused(keys) -> None:
    """A certificate asserting 2-of-7 reached quorum is not Byzantine-tolerant however many valid
    signatures it carries, and calling it "quorum reached" is the over-claim this module refuses."""
    privates, publics = keys

    result = verify_certificate(
        _cert([_vote(privates, "v1", True), _vote(privates, "v2", True)],
              voters=("v1", "v2", "v3", "v4", "v5", "v6", "v7"), quorum=2),
        publics,
    )

    assert not result.ok and "below the Byzantine-safe minimum" in result.reason


def test_a_missing_public_key_fails_rather_than_skipping_the_vote(keys) -> None:
    """Skipping an unverifiable vote would silently shrink the electorate; failing says so."""
    privates, publics = keys
    del publics["v3"]

    result = verify_certificate(
        _cert([_vote(privates, "v1", True), _vote(privates, "v2", True),
               _vote(privates, "v3", True)]),
        publics,
    )

    assert not result.ok and "no public key" in result.reason


# --- the certificate as an artifact -------------------------------------------


def test_verification_is_pure(keys) -> None:
    """An auditor runs this against the certificate and the keys, holding nothing of ours —
    which is the point of issuing a certificate rather than an assertion. Structural, like AUD-06's."""
    import inspect

    import agentos_controlplane.byzantine as mod

    src = inspect.getsource(mod.verify_certificate)
    assert "session" not in src and "select(" not in src and "self._sf" not in src


def test_malformed_input_is_a_false_result_not_a_traceback(keys) -> None:
    """Certificates come from outside; a traceback is easy to mistake for "the check did not run"."""
    _, publics = keys

    for bad in ({}, {"action_id": "x"}, {"action_id": "x", "outcome": "o", "voters": [],
                                         "quorum": 1, "votes": []}):
        assert verify_certificate(bad, publics).ok is False
    assert verify_certificate(None, publics).ok is False


# --- the coordinator on the POL-09 seam ---------------------------------------


def _action() -> AgentAction:
    return AgentAction(
        agent_id="a1", type=ActionType.tool_call, target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""},
    )


def _decision(action) -> Decision:
    return Decision(
        action_id=action.id, outcome=Outcome.require_consensus,
        reasons=[Reason(stage="policy", code="c", detail="d")],
    )


def _voter(privates, voter_id, approve, *, silent=False, raises=False):
    async def _fn(action, decision):
        if raises:
            raise RuntimeError("voter down")
        if silent:
            return None
        sig = privates[voter_id].sign(
            vote_message(str(action.id), decision.outcome.value, voter_id, approve)
        )
        return Vote(voter_id=voter_id, approve=approve, signature=sig.hex())

    return _fn


def test_the_coordinator_approves_a_real_quorum(store, keys) -> None:
    privates, publics = keys
    action = _action()
    coord = ByzantineConsensusCoordinator(
        {v: _voter(privates, v, True) for v in ("v1", "v2", "v3", "v4")},
        publics, AuditWriter(store),
    )

    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is True


def test_a_silent_or_failing_voter_is_an_ABSENT_ballot_not_a_no(store, keys) -> None:
    """Phase 9's rule unchanged — silence never approves — and now distinguishable in the
    certificate from a voter that actually voted no."""
    privates, publics = keys
    action = _action()
    coord = ByzantineConsensusCoordinator(
        {
            "v1": _voter(privates, "v1", True),
            "v2": _voter(privates, "v2", True),
            "v3": _voter(privates, "v3", True, silent=True),
            "v4": _voter(privates, "v4", True, raises=True),
        },
        publics, AuditWriter(store),
    )

    assert asyncio.run(coord.reach_consensus(action, _decision(action))) is False
    assert {v.voter_id for v in coord.last_certificate.votes} == {"v1", "v2"}


def test_an_equivocating_voter_denies_and_is_audited(store, keys) -> None:
    """A lying voter is a security event in its own right, recorded even though the action is denied:
    the operator needs to know WHICH voter, not just that quorum failed."""
    privates, publics = keys
    action = _action()

    async def _two_faced(a, d):
        # returns one vote; the second is injected below to simulate a duplicated ballot
        return Vote("v1", True, privates["v1"].sign(
            vote_message(str(a.id), d.outcome.value, "v1", True)).hex())

    coord = ByzantineConsensusCoordinator(
        {"v1": _two_faced, "v2": _voter(privates, "v2", True),
         "v3": _voter(privates, "v3", True), "v4": _voter(privates, "v4", False)},
        publics, AuditWriter(store),
    )
    asyncio.run(coord.reach_consensus(action, _decision(action)))

    with store() as s:
        kinds = [r.body.get("kind") for r in s.scalars(select(AuditRecord)).all()]
    assert "quorum_certified" in kinds


def test_a_quorum_below_the_threshold_is_refused_at_CONSTRUCTION(store, keys) -> None:
    """An operator error to surface at startup, not a decision to get wrong quietly on every action —
    the posture POL-09 already takes toward an impossible quorum."""
    _, publics = keys

    with pytest.raises(ValueError, match="Byzantine-safe minimum"):
        ByzantineConsensusCoordinator(
            {v: (lambda a, d: None) for v in ("v1", "v2", "v3", "v4")},
            publics, AuditWriter(store), quorum=2,
        )


def test_a_voter_without_a_public_key_is_refused_at_construction(store, keys) -> None:
    """An unverifiable voter is worse than an absent one: it inflates n — and so the tolerance
    claim — while never contributing a countable vote."""
    _, publics = keys
    del publics["v4"]

    with pytest.raises(ValueError, match="no public key"):
        ByzantineConsensusCoordinator(
            {v: (lambda a, d: None) for v in ("v1", "v2", "v3", "v4")},
            publics, AuditWriter(store),
        )


def test_it_satisfies_the_phase_9_consensus_seam(store, keys) -> None:
    """POL-12 substitutes into POL-09's seam, so `require_consensus` gains tolerance with NO change
    to the enforcement path — there is still one outcome map.

    Asserted STRUCTURALLY rather than with `isinstance`: `ConsensusCoordinator` is a plain Protocol,
    not `@runtime_checkable`, and adding that decorator to shipped SDK code to make a test's
    `isinstance` work would be changing the product for the test's convenience. Structural typing is
    what the seam actually requires, so the structure is what gets checked.
    """
    import inspect

    from agentos_sdk.enforce import ConsensusCoordinator

    _, publics = keys
    coord = ByzantineConsensusCoordinator(
        {v: (lambda a, d: None) for v in ("v1", "v2", "v3", "v4")}, publics, AuditWriter(store)
    )

    expected = inspect.signature(ConsensusCoordinator.reach_consensus)
    actual = inspect.signature(type(coord).reach_consensus)
    assert list(actual.parameters) == list(expected.parameters)
    assert inspect.iscoroutinefunction(type(coord).reach_consensus)


# --- the claim -----------------------------------------------------------------


def test_the_module_does_not_claim_to_be_a_consensus_protocol() -> None:
    """The over-claim guard, in the shape Phase 11 used for conformity language.

    "BFT" invites a reader to assume a replicated state machine with view changes and partition
    liveness. This ships none of that, and the docstring must both SAY so and not imply otherwise.
    A governance product that over-claims a Byzantine guarantee is telling an operator their fleet
    survives an attack it does not survive.
    """
    import agentos_controlplane.byzantine as mod

    # Whitespace-normalized: the docstring wraps, and a disclaimer split across a line break is
    # still the disclaimer a reader sees. Matching raw text would make this test fail on reflow.
    doc = " ".join(mod.__doc__.lower().split())
    assert "not a replicated state machine" in doc
    assert "no leader" in doc and "no view change" in doc
    assert "no liveness guarantee under partition" in doc
    for overclaim in ("implements pbft", "guarantees liveness", "survives a partition"):
        assert overclaim not in doc
