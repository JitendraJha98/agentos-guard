# Phase 14 — Self-Play, Portable Reputation, ROI, Impact Analysis & the Rust Question — Design

**Date:** 2026-08-20
**Branch:** `phase-10-gateway-adapter-graph` (continued — operator's instruction)
**Requirements:** TEST-10, TEST-11, AUD-07, IDN-04, TRST-05, INT-09, PERF-01, ECON-04, ABOM-03
**Depends on:** Phase 13, and the P0/P1 gate — **verified before writing this spec**, not assumed:
latency 6 passed (budget held), audit externally verifiable (108 Merkle/verifier tests), coverage
matrix GREEN, red-team gating CI 444 passed.

## The scope decision, first, because it governs everything else

`.planning/STATE.md` flags Phases 13–14 as *"LOW-confidence moonshot tech — evaluate before commit."*
Phase 13 did that for POL-12 and shipped it scoped, with the caveat recorded on the requirement.
Phase 14 needs the same across nine requirements, and the answer is not uniform. **Checked on this
machine, 2026-08-20:**

| Requirement | Tooling present? | Decision |
|---|---|---|
| ABOM-03 impact analysis | yes — ABOM digests + SEC-08 shipped | **Build** |
| TEST-10 self-play | partial — corpus + POL-10 ratification shipped | **Build, scoped** |
| TEST-11 runtime patch + threat intel | yes — POL-10 is the ratified-rollout path | **Build** |
| TRST-05 portable reputation | yes — TRST-03 reputation shipped | **Build** |
| ECON-04 ROI analytics | partial — cost shipped, "value" is not measurable | **Build, scoped** |
| PERF-01 Rust hot path | **no cargo, no rustc** | **Answer with a profile** |
| AUD-07 ZK proofs | **no proving library** (py_ecc, galois, zksk, petlib, pysnark all absent) | **Defer, recorded** |
| IDN-04 SPIFFE/mTLS | **no spiffe/pyspiffe, no SPIRE** | **Defer, recorded** |
| INT-09 K8s sidecar/operator | kubectl present, **no Docker, no cluster** | **Defer, recorded** |

Three requirements are deferred and **recorded on the requirement itself**, the way POL-12's scope
was — not marked complete, not silently dropped. The reasoning is Phase 13's, sharpened by
repetition: shipping something that compiles, passes single-process tests, and has never met the
conditions it exists for is **worse** than not shipping it, because the name promises a guarantee
nothing verified. That is especially true of "zero-knowledge proof", which has a precise
cryptographic meaning a hand-rolled construction does not earn.

**PERF-01 is the interesting one.** The requirement says a Rust rewrite happens *"where profiling
justifies it"* — so its own precondition is a profile, and the profile is deliverable here even
though cargo is not. If the hot path sits well inside its budget, the evidence-based answer may be
**"profiling does not currently justify it"**, which satisfies the requirement as written rather than
dodging it. That answer must come from measurement, not from the absence of a toolchain — so the
slice produces the profile and lets it decide.

## Cross-cutting decisions

**D-1. "Self-play" here is mutation-based and deterministic, not LLM-generated.** TEST-10 wants novel
attacks. Genuine novelty needs a generator; the shipped interpreter seam is advisory-only, needs an
API key, and its tests skip without one — so an LLM-driven generator would be untested in CI, which
is the one place a red-team component must not be. Instead the generator **mutates the shipped
corpus** (recombination, obfuscation, encoding, splitting across a campaign) deterministically from a
seed. That produces attacks the corpus does not contain — genuinely new inputs — without claiming a
creativity it does not have. The module says which it is.

**D-2. A proposed patch is a POL-10 amendment, not a new mechanism.** TEST-10 says patches are
human-ratified; TEST-11 says ratified defenses roll out. Phase 13 built exactly that path, including
the guarantee that a pending proposal changes no decision. Self-play proposes *through* it. A second
ratification path would be a second way to change the rules, and the weaker one is the one an
attacker would use.

**D-3. Held-out evaluation, or the score is circular.** A generator that proposes a patch and then
scores it on the attacks it just generated always reports success. The corpus is split: patches are
proposed from the **train** half and scored on the **held-out** half, and a patch that only helps on
train is reported as not generalising. Without this, TEST-10's "scores defenses" is
self-congratulation.

**D-4. Nothing self-play generates is ever executed.** Phase 12's rule, inherited without exception:
every probe goes through `evaluate(action) -> Decision`. A generator that produced novel attacks
*and ran them* would be building and firing new exploits against a live deployment.

**D-5. ROI's "value" is operator-supplied, never inferred.** Cost is measured (ECON-01/03). Value is
not observable by a control plane: an action that succeeded may have produced something worthless,
and a denied one may have prevented a catastrophe. Inventing a proxy — counting allowed actions,
say — produces a number that rewards permissiveness, which on a governance product is the exact wrong
incentive. The operator supplies value; the module computes the ratio and shows both inputs.

**D-6. Portable reputation exports facts with provenance, and crypto-economics stay out of core.**
ADR-0007 fences staking/slashing into an optional backend that is *never required*. Core ships an
export/import format and a Protocol seam; a deployment with no backend loses nothing. Imported
reputation is quarantined as **claimed by another deployment** rather than merged into local trust —
an importable score that silently became authoritative would be a trust-laundering path between
deployments, TRST-04's escalation in a new place.

## Slice breakdown

- **14a — ABOM-03 vulnerability impact analysis.** "Which agents use compromised component vX?" from
  the Phase-8 ABOM component digests joined to SEC-08's known-bad set. Bounded read, gated route.
- **14b — TEST-10/11 self-play, threat intel, runtime patching.** Deterministic mutation generator,
  train/held-out scoring, patch proposal through POL-10, threat-intel import under the same
  evaluate-only rule.
- **14c — TRST-05 portable reputation.** Signed export bundle, import as *claimed*, optional backend
  Protocol with no core dependency.
- **14d — ECON-04 ROI analytics.** Operator-supplied value against measured cost, per agent, both
  inputs shown.
- **14e — PERF-01 profile.** Measure the hot path, report where time goes, let the evidence answer
  whether a Rust rewrite is justified.

## Out of scope (Phase 14), each recorded on its requirement

- **AUD-07** — no proving system; a hand-rolled construction would not be a zero-knowledge proof and
  calling it one would be a cryptographic over-claim.
- **IDN-04** — no SPIFFE library and no SPIRE to issue SVIDs. Phase 7 shipped IDN-03 with
  deliberately SPIFFE-shaped URI SANs so this stays a change of scheme, not of model.
- **INT-09** — no cluster to verify against; an unverified operator is a YAML file with a claim
  attached. Phase 10's gateway PEP already provides network-layer interception behind the same
  contract, which is the property INT-09 exists for.
- **PERF-01's rewrite half** — deferred *on the profile's evidence* rather than on tooling absence,
  which is what makes it an answer instead of an excuse.

## Risks / watch-items

- **Over-claiming "self-play" or "novel".** D-1, stated in the module.
- **Circular scoring.** D-3, held-out split asserted.
- **Executing generated attacks.** D-4, asserted with a handler that raises if awaited.
- **A value proxy sneaking into ROI.** D-5, asserted: no ROI number without operator input.
- **Imported reputation becoming authoritative.** D-6, asserted: import never moves local trust.

## Verification (phase-level success criteria)

1. ABOM-03 answers the impact question from shipped ABOM data over a gated, bounded read.
2. Self-play generates attacks absent from the corpus, scores on a held-out split, proposes patches
   through POL-10 human ratification, imports threat intel — and executes nothing.
3. Portable reputation exports/imports across deployments through an optional backend, imported
   values marked claimed, crypto-economics absent from core.
4. ROI presents value-vs-cost per agent with value operator-supplied and both inputs visible.
5. PERF-01 is answered by measurement, with the rewrite decision resting on that evidence.
6. Full suite green; gates green; single alembic head; INT-06 coverage clean.
