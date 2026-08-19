# Phase 13 — Constitution Amendments, Conflict Reasoning & Byzantine-Tolerant Quorum — Design

**Date:** 2026-08-19
**Branch:** `phase-10-gateway-adapter-graph` (continued — operator's instruction)
**Requirements:** POL-10, POL-11, POL-12
**Depends on:** Phase 12 (complete). Phase 3's approval workflow + constitution compiler, Phase 5's
versioned resource API, Phase 7's TRST-04 delegation authority, and Phase 9's POL-09 consensus seam
are the load-bearing prior art.

## Scope honesty, up front

These three are **P2 / moonshot tier**, and `.planning/STATE.md` flags Phases 13–14 as
*"LOW-confidence moonshot tech — evaluate before commit."* That evaluation is this section, and it
changes what one of the three means.

**POL-10 and POL-11 are ordinary engineering.** An amendment lifecycle is a resource with a
propose→review→ratify transition and a version history; transitive permission closure is a walk over
a delegation graph we already build. Both are buildable, testable, and land as specified.

**POL-12 is not, and pretending otherwise would be the phase's worst outcome.** "BFT consensus" names
a family of replicated-state-machine protocols — PBFT, Tendermint, HotStuff — with view changes,
leader election, and 3f+1 replicas exchanging authenticated messages over a network. This project has
no network consensus layer, no multi-node test harness, and no Docker on the development machine
(D-14). Implementing a genuine PBFT here would produce something that compiles, passes single-process
tests, and has never survived a partition — which is worse than not having it, because the name would
promise a guarantee nothing verified.

**So POL-12 ships the Byzantine-tolerant properties that are real at our scale, and says plainly what
it is not.** Concretely: votes are **signed**, so a vote cannot be forged or attributed to a voter who
never cast it; the quorum rule tolerates **f Byzantine voters out of 3f+1**, which is the arithmetic
BFT exists for; **equivocation** (one voter, two different votes on one action) is detected and voids
that voter rather than being silently last-write-wins; and the outcome is a **quorum certificate** —
the signed votes themselves — so a third party can re-verify the decision without trusting us, in the
same spirit as AUD-06's inclusion proofs.

What it is **not**, stated in the module and in the requirement's close-out: a replicated state
machine. There is no leader, no view change, no liveness guarantee under partition, and voters are
in-process or called over the existing seam. It is Byzantine-tolerant *agreement arithmetic with
authenticated, non-repudiable votes* — not a consensus protocol. Marking POL-12 "Complete" without
that sentence would be the same over-claim Phase 11 spent two review rounds removing from the
compliance bundle.

## Cross-cutting decisions

**D-1. An amendment is a proposal about the rules, so it may never bypass the rules.** POL-13
established that a `temporary_exception` is human-ratified only and the interpreter may recommend but
never grant. The same shape applies here: an agent (or a future self-play trainer) may **propose**,
and only a human may **ratify**. A proposal must have no effect on any decision until ratified —
tested by evaluating an action against a pending amendment and requiring the outcome to be unchanged.

**D-2. Versioned like a legal document means the old text survives.** Ratifying an amendment does not
edit the constitution in place; it produces a new version with the prior one retained and the
transition recorded. POL-08 already pins `constitution_version` on every `Decision`, so an audited
decision must remain explicable against the text that actually evaluated it — which is impossible if
that text was overwritten.

**D-3. Transitive permission is an INTERSECTION along the chain, never a union.** TRST-04 already
holds this for one hop (`effective_scope(child) = parent ∩ child`). The closure is the same rule
applied along the path, and the direction matters: a union would let a chain *manufacture* a
capability no participant held, which is precisely the escalation TRST-04 exists to prevent.

**D-4. A conflict is a finding, not a decision.** POL-11 says "flags emergent capability conflicts".
The engine reports; it does not deny. The floor invariant (POL-05/TRST-02) is that policy decides and
everything else may only restrict — a conflict engine that silently denied would be a second
enforcer beside the constitution, the exact thing ECON-02 was written to avoid.

**D-5. This is where 12e's claimed-lineage gap closes, as far as it can.** Phase 12 shipped the
evidence graph with `lineage` labelled CLAIMED because `identity_verified` authenticates who acted,
not that `parent_action_id` names a real delegation. POL-11 computes delegation authority, so a
claimed edge can now be **cross-checked** against it: an edge whose child was never granted authority
by its claimed parent is reportable. That upgrades a claim to *corroborated* or *contradicted* — it
still does not make it proven, because absence of a ledger entry is not proof of absence, and the
distinction is kept.

**D-6. Byzantine tolerance starts with authentication, not arithmetic.** A quorum rule that tolerates
f malicious voters is worthless if a voter's ballot can be forged, replayed onto a different action,
or counted twice. Votes are signed over `(action_id, decision, voter)` with the Ed25519 machinery
IDN-01/AUD-08 already ship, so a certificate is checkable offline and a vote for one action cannot be
replayed onto another.

## Slice breakdown

Four slices. 13d depends on 13b; the rest are independent.

### 13a — Amendment proposal & ratification (POL-10, part 1)

An `Amendment` resource with `proposed → ratified | rejected | withdrawn`, the proposer recorded
(agent or human), a human ratifier required, and every transition audited. A pending amendment is
inert (D-1). Gated API routes plus a dashboard page, reusing the Phase-3 approval idiom rather than
inventing a second review surface.

### 13b — Constitution versioning as a legal document (POL-10, part 2)

Ratification produces a new constitution **version** with the prior text retained, an effective-from
timestamp, and the ratified amendment recorded as its provenance. A history read shows what changed,
when, on whose authority. The old text stays queryable so a POL-08-pinned decision remains explicable
(D-2).

### 13c — Transitive permission closure & conflict detection (POL-11)

Walks the delegation chain, intersecting scope at every hop (D-3), and reports: the effective
capability set at each node, capabilities *lost* along the chain, and **conflicts** — two paths to one
agent conferring different effective scope, or a claimed lineage edge with no corresponding authority
(D-5). Bounded and cycle-safe, exactly as 12e's walk is, and for the same reason: the input is
caller-supplied.

### 13d — Byzantine-tolerant quorum with signed certificates (POL-12)

Extends the POL-09 seam: signed votes, 3f+1 quorum arithmetic, equivocation detection, and a quorum
certificate a third party can verify. Ships with the honest statement of what it is not.

## Out of scope (Phase 13)

- A real replicated-state-machine consensus protocol (PBFT/Tendermint/HotStuff), leader election,
  view change, or partition liveness — see the scope-honesty section. Deferred with the reason
  recorded, not silently.
- Self-play generating amendments (Phase 14 — POL-10 says "agents *or* the self-play trainer"; the
  proposal API is agent-usable now, and the trainer is Phase 14's).
- Making claimed lineage *proven* (D-5) — corroboration is the honest ceiling without a signed
  delegation grant, which is a bigger change than this phase.

## Risks / watch-items

- **Over-claiming BFT.** The single largest risk in this phase. Every emitted string, docstring and
  close-out line about POL-12 gets read as a hostile reviewer would.
- **An amendment that takes effect early.** D-1. Tested by evaluating against a pending proposal.
- **A union creeping into the closure.** D-3. A property test over random chains asserting the result
  is a subset of every participant's scope.
- **Conflict engine becoming an enforcer.** D-4. Assert an action's outcome is unchanged by the
  presence of a conflict finding.
- **Losing old constitution text.** D-2. A ratified amendment must leave the prior version readable.

## Verification (phase-level success criteria)

1. An agent can propose an amendment, a human ratifies it, the constitution gains a new version with
   the prior text retained and the provenance recorded — and a *pending* amendment changes no
   decision.
2. Transitive permissions are computed by intersection across delegation chains, conflicts are
   flagged as findings without denying anything, and a claimed lineage edge can be corroborated or
   contradicted against delegation authority.
3. `require_consensus` is backed by signed votes, 3f+1 Byzantine quorum arithmetic, equivocation
   detection and an offline-verifiable certificate — with the module and the requirement close-out
   stating that this is not a replicated consensus protocol.
4. Full suite green; `floor_invariant`, `regression_lock`, `latency` gates green; single alembic
   head; INT-06 coverage clean.
