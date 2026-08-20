# Phase 13 · Slice 13c — Byzantine-Tolerant Quorum with Signed Certificates (POL-12) — Plan

**Goal (POL-12 as scoped):** Back `require_consensus` with the Byzantine-tolerant properties that are
real at this scale — **signed votes**, **3f+1 quorum arithmetic**, **equivocation detection**, and a
**quorum certificate a third party can verify offline**.

## Read this before writing any of it

The requirement says "BFT consensus backs multi-agent agreement for `require_consensus` at scale."
The spec's scope-honesty section decided what that can mean here, and the decision is binding on the
prose as much as the code:

**BFT names a family of replicated-state-machine protocols** — PBFT, Tendermint, HotStuff — with view
changes, leader election, and 3f+1 replicas exchanging authenticated messages over a network. This
project has no network consensus layer, no multi-node test harness, and no Docker on the development
machine (D-14). A PBFT written under those conditions would compile, pass single-process tests, and
have never survived a partition. The name would promise a guarantee nothing verified.

**So this slice ships Byzantine-tolerant AGREEMENT ARITHMETIC WITH AUTHENTICATED, NON-REPUDIABLE
VOTES, and says so.** Not a consensus protocol. No leader, no view change, no liveness guarantee
under partition. That sentence goes in the module docstring, in the API route docstring, and in the
requirement's close-out line — and a test asserts the module does not claim otherwise, in the same
shape as Phase 11's conformity-language scan.

## What Byzantine tolerance actually buys, in order

1. **Authentication first.** A quorum rule tolerating f malicious voters is worthless if a ballot can
   be forged, attributed to a voter who never cast it, or replayed from one action onto another. Votes
   are signed over the tuple `(action_id, decision_outcome, voter_id, approve)` using the Ed25519
   machinery IDN-01/AUD-08 already ship. A signature over the outcome as well as the action matters:
   without it a voter's approval of a `sandbox` could be replayed as approval of an `allow`.
2. **3f+1 arithmetic.** To tolerate `f` Byzantine voters you need `n >= 3f+1` and a quorum of
   `2f+1`. Phase 9 shipped a configurable `quorum` with no relationship to a fault model; this adds
   `byzantine_tolerance(n) -> f` and refuses a configuration whose quorum is below `2f+1` for its own
   claimed `f`, at construction — the same posture POL-09 already takes toward an impossible quorum.
3. **Equivocation.** One voter, two different votes on one action, is the defining Byzantine
   behaviour. Last-write-wins silently lets it decide the outcome. Both votes are retained, the voter
   is **voided** for that action (neither vote counts), and the equivocation is a finding.
4. **A certificate.** The signed votes themselves, so a third party re-derives the decision without
   trusting us — the same spirit as AUD-06's inclusion proofs, and the reason `verify_certificate` is
   a pure function.

## File structure
- Create `.../agentos_controlplane/byzantine.py` — `Vote`, `QuorumCertificate`,
  `byzantine_tolerance`, `verify_certificate`, `ByzantineConsensusCoordinator`.
- Modify `.../audit.py` — `EVENT_KINDS += "quorum_certified"`, `"voter_equivocated"`.
- Tests: `tests/unit/test_byzantine.py`.

No migration: the certificate rides the existing audit chain.

---

### Task 1: the pure core — tolerance, votes, certificate verification

```python
def byzantine_tolerance(voters: int) -> int:
    """How many Byzantine voters a set of `voters` can tolerate: floor((n-1)/3).

    The classical bound. With n = 3f+1 a quorum of 2f+1 guarantees any two quorums intersect in at
    least one honest voter, which is what stops two contradictory decisions from both looking
    legitimate. Below n=4 the answer is 0 — a 3-voter set tolerates no Byzantine member, which is
    worth returning honestly rather than rounding up, because POL-09's shipped default is 2-of-3.
    """


def required_quorum(voters: int) -> int:
    """2f+1 for the f this many voters can tolerate."""
```

`verify_certificate(certificate, public_keys) -> CertificateResult` — **pure**, no DB, no I/O, so an
auditor runs it against the certificate alone. Returns `ok`, `approvals`, `equivocators`, and a
`reason` when it fails. Checks, in order: every signature verifies under its voter's key; no voter
appears twice with different votes (equivocation → that voter voided); the approval count meets the
stated quorum; and the stated quorum meets `required_quorum` for the voter set.

- [ ] Failing tests:

```python
def test_the_tolerance_bound_is_the_classical_one() -> None:
    assert [byzantine_tolerance(n) for n in (1, 3, 4, 7, 10)] == [0, 0, 1, 2, 3]
    assert [required_quorum(n) for n in (4, 7, 10)] == [3, 5, 7]


def test_three_voters_tolerate_ZERO_byzantine_voters() -> None:
    """POL-09's shipped default is 2-of-3, and it is worth being honest that this tolerates no
    malicious voter — 2-of-3 survives one voter being DOWN, not one voter LYING."""
    assert byzantine_tolerance(3) == 0


def test_a_forged_vote_is_rejected(keys) -> None:
    """Authentication before arithmetic: a quorum rule is worthless if ballots can be forged."""


def test_a_vote_cannot_be_replayed_onto_a_different_action(keys) -> None:
    """The signature covers action_id, so a genuine approval of one action is not an approval of
    another — which is how an attacker would reuse a legitimate voter's ballot."""


def test_a_vote_cannot_be_replayed_onto_a_different_OUTCOME(keys) -> None:
    """It covers the outcome too. Without that, approval of a `sandbox` replays as approval of an
    `allow` — the voter agreed to containment, not to execution."""


def test_an_equivocating_voter_is_voided_not_last_write_wins(keys) -> None:
    """The defining Byzantine behaviour. Last-write-wins lets one lying voter pick the outcome; both
    votes are kept, the voter counts for neither, and the equivocation is reported."""
    cert = _certificate(votes=[_yes("v1"), _no("v1"), _yes("v2"), _yes("v3")], quorum=3)

    result = verify_certificate(cert, keys)

    assert "v1" in result.equivocators
    assert result.approvals == 2 and result.ok is False


def test_a_quorum_below_the_byzantine_threshold_is_refused(keys) -> None:
    """A certificate claiming 2-of-7 met quorum is not Byzantine-tolerant however many signatures it
    carries, and saying "quorum reached" over it would be the over-claim this slice exists to avoid."""


def test_verification_is_pure(keys) -> None:
    """An auditor runs this against the certificate alone. Structural, like AUD-06's:
    no session, no import of the store."""
    import inspect

    import agentos_controlplane.byzantine as mod

    src = inspect.getsource(mod.verify_certificate)
    assert "session" not in src and "select(" not in src


def test_malformed_input_is_a_false_result_not_a_traceback(keys) -> None:
    """Certificates come from outside; a traceback is easy to mistake for "the check did not run"."""


def test_the_module_does_not_claim_to_be_a_consensus_protocol() -> None:
    """The over-claim guard, in the shape Phase 11 used for conformity language.

    "BFT" invites a reader to assume a replicated state machine with view changes and partition
    liveness. This ships none of that, and the docstring must not imply it — a customer reading
    "Byzantine fault tolerant" on a governance product will assume the strong reading.
    """
    import agentos_controlplane.byzantine as mod

    doc = mod.__doc__.lower()
    assert "not a replicated state machine" in doc
    assert "no leader" in doc and "no view change" in doc
    for overclaim in ("implements pbft", "consensus protocol that", "guarantees liveness"):
        assert overclaim not in doc
```

- [ ] Implement. Run → passes.
- [ ] Commit `feat(controlplane): Byzantine quorum arithmetic + offline-verifiable certificates (POL-12)`.

---

### Task 2: the coordinator + full gate

`ByzantineConsensusCoordinator` satisfies the SAME `ConsensusCoordinator` protocol Phase 9's
`governed_call` already consumes, so `require_consensus` gains Byzantine tolerance with **no change to
the enforcement path** — the POL-09 seam was built for exactly this substitution.

It collects signed votes, builds a certificate, audits `quorum_certified` (and `voter_equivocated`
when it happens, because a lying voter is a security event and not merely a failed vote), and returns
`True` only on `verify_certificate(...).ok`. A voter that errors, times out or stays silent
contributes no vote — Phase 9's rule, unchanged, and now distinguishable in the certificate from a
voter that voted *no*.

- [ ] Failing tests: a valid 3-of-4 certificate approves; an equivocating voter denies and is
  audited; the certificate is retrievable and verifies offline; a silent voter is absent from the
  certificate rather than counted as a no; it satisfies `ConsensusCoordinator` structurally and works
  through the real `governed_call`.
- [ ] **Full gate on the WHOLE suite** + `-m floor_invariant`, `-m regression_lock`, `-m latency`,
  coverage, single alembic head.
- [ ] Commit `feat(controlplane): Byzantine-tolerant consensus coordinator on the POL-09 seam (POL-12)`.

## Self-review

The four properties Byzantine tolerance actually needs are each present and each tested: signatures
that bind a vote to an action **and** an outcome (so neither can be replayed), 3f+1 arithmetic with a
construction-time refusal of a quorum below the threshold it claims, equivocation that voids a voter
rather than resolving last-write-wins, and a certificate that verifies as a pure function.

The honest statement is enforced mechanically rather than left to prose discipline: a test scans the
module docstring for the disclaimers and for over-claims, in the same shape as Phase 11's
conformity-language scan. It ships as agreement arithmetic with authenticated votes, not a
replicated state machine, and a reader who assumes the strong reading of "BFT" is corrected by the
first paragraph.

It also makes an existing default honest: POL-09's 2-of-3 tolerates one voter being **down**, not one
voter **lying**, and `byzantine_tolerance(3) == 0` says so rather than rounding up.

The coordinator satisfies the Phase-9 `ConsensusCoordinator` protocol unchanged, so the enforcement
path is untouched — the seam was built for this substitution, and using it means `require_consensus`
gains tolerance without a second outcome map.
