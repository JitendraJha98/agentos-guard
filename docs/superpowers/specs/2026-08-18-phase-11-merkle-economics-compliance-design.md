# Phase 11 — Merkle Audit, Economics & Compliance Export — Design

**Date:** 2026-08-18
**Branch:** `phase-10-gateway-adapter-graph` (continued — operator's instruction; Phase 11 commits stay
separable from the Phase 9/10 stack)
**Requirements:** AUD-06, ECON-01, ECON-02, ECON-03, CMP-04, CMP-05, CMP-06
**Depends on:** Phase 10 (complete). Phase 4's chain + checkpoints, Phase 6's compliance mapping,
Phase 9's `governed_call` execution seams are the load-bearing prior art.

> The roadmap title for this phase says "ABOM". That is stale: ABOM-01/02 shipped in Phase 8 and
> ABOM-03 is Phase 14. Phase 11's requirement set contains no ABOM item, and this spec does not
> invent one. The roadmap title is corrected at close-out rather than honored as scope.

## Goal

Three things that only matter together: make the audit log **selectively provable** (AUD-06), make
agent **spend governable by the same engine that governs everything else** (ECON-01/02/03), and turn
both into **evidence a regulator or auditor can check without trusting us** (CMP-04/05/06).

The through-line is the Merkle work. Today an operator who must prove one action to an auditor has
exactly two options: hand over the entire audit log, or hand over an unverifiable extract. A Merkle
tree makes the third option real — disclose one record plus a proof path, and the recipient verifies
it against an externally anchored root without ever seeing the other records. CMP-06's export bundle
is that capability, wearing a compliance label.

## Cross-cutting decisions

**D-1. The linear hash chain stays; the Merkle tree is additive.** AUD-01's `prev_hash` chain, the
AUD-05 CI verifier, and the RFC-3161 checkpoints all keep working byte-for-byte. The tree is built
*over* `record_hash` values that already exist. Replacing the chain would invalidate every existing
audit record and the verifier that guards it — a rewrite of shipped, load-bearing evidence to gain a
property we can get by addition.

**D-2. RFC-6962 hashing, not naive concatenation.** Leaf = `H(0x00 ‖ record_hash)`, internal =
`H(0x01 ‖ left ‖ right)`, odd node promoted (never duplicated). The domain-separation prefixes stop
leaf/internal confusion, and promoting the odd node avoids the duplicate-node ambiguity that let
distinct trees share a root (CVE-2012-2459). Both rules are cheap and both are load-bearing for the
proof to *mean* anything.

**D-3. Spend is enforced by the PDP, never beside it.** No budget enforcer, no separate deny path.
The ledger exposes accumulated spend as **policy-input fields**; a constitution principle conditions
on them; the graduated engine produces the outcome. This is the roadmap's explicit constraint and it
is also what keeps the floor invariant (POL-05/TRST-02) intact — a budget breach is a policy floor
like any other, subject to the same explainability and the same audit.

**D-4. Enforcement reads accumulated FACT, not a predicted cost.** Spend is knowable only after a
call returns. So the pre-call gate conditions on what has already been spent, and the honest bound is
stated plainly: **overshoot is capped at one action's cost.** The rejected alternative was estimating
the pending call's tokens pre-flight — a provider-specific number that is wrong in ways the operator
cannot see, and that an agent can shape its prompt to evade. A verifiable bound beats a fragile
tighter one. This mirrors RUN-05's preventive-vs-detected honesty.

**D-5. The hot path stays clean.** `enrich()` is pure-CPU and stateless by contract, so budget state
does not enter through it. The ledger is an **in-memory cached lookup** consulted in the runner and
passed into `build_policy_input` — exactly how the stateful `SequenceCorrelator` already enters, and
exactly the caching discipline `ResourceGovernor.limits_for` already requires. An API-04 reconciler
converges the cache from the table. PIPE-04 (p95 < 10 ms) is a gate, not an aspiration.

**D-6. Metering hangs off the one execution seam.** Cost is recorded by a `CostMeter` injected into
`governed_call` alongside `governor`/`reporter`, applied at `_run_reported` — the single site every
PEP form already funnels through. A second recording path would mean the gateway and the SDK could
disagree about what an agent spent.

**D-7. Never fabricate a number.** Where usage is not reported, record **nothing** — not zero. A zero
reads as "this agent used no GPU"; absence reads as "we do not know", which is the truth. Phase 9's
9c review killed a design that cross-attributed process-wide `tracemalloc` deltas into per-action
audit accusations; the same trap is waiting in GPU attribution and this phase walks around it (D-9).

**D-8. Compliance output is evidence, never a conformity claim.** We emit "here are the controls and
the records that bear on Art. 14" — never "this system is Art. 14 compliant." Risk *classification*
is a legal determination about a deployment's use case, so it is **operator-declared** and echoed,
never inferred. A tool that guesses a customer's regulatory class and is wrong does real harm.

**D-9. GPU attribution is labelled by what it actually measured.** Hosted APIs do not report
GPU-seconds, and device-wide NVML counters in a shared process cannot be honestly divided among
concurrent agents. Every GPU record therefore carries `attribution` ∈ {`process`, `device_shared`},
and `device_shared` is explicitly not a per-agent bill.

## Verified external facts (to check at implementation time, against the installed package)

- RFC 6962 §2.1 leaf/node hashing and the odd-node promotion rule — confirm against the RFC text
  before encoding; the tree is worthless if the rule is wrong.
- Whether `pynvml` / `nvidia-ml-py` is importable here, and whether per-process GPU memory is
  available via `nvmlDeviceGetComputeRunningProcesses`. **This box has no GPU**, so the NVML path
  ships behind a capability probe with the same posture as 9c's POSIX `setrlimit` path: real code,
  gated, honestly documented as unexercised locally.
- LangChain's `usage_metadata` shape on `AIMessage` (v1) and the OpenAI Agents SDK's usage object —
  confirmed by introspecting the installed packages, not from docs.
- EU AI Act article numbering and the SOC 2 Trust Services Criteria point references — quoted only as
  far as they can be confirmed; anything uncertain is omitted rather than approximated.

## Slice breakdown

Six slices. 11a is a prerequisite for 11f; 11b → 11c → 11d run in order; 11e is independent.

### 11a — Merkle DAG, inclusion proofs, partial disclosure (AUD-06)

`agentos_controlplane/merkle.py` + a `merkle_root` table (migration 0023). An **epoch** is a
contiguous `seq` range; sealing an epoch builds the RFC-6962 tree over its `record_hash` leaves and
persists `{epoch, seq_start, seq_end, root, leaf_count}`. `inclusion_proof(seq)` returns the sibling
path; `verify_inclusion(record_hash, proof, root)` is a pure function with no DB access so a third
party can run it against nothing but the bundle. Checkpoints learn to anchor a **root** as well as a
head, so an epoch inherits RFC-3161 external authority. The AUD-05 verifier gains a Merkle pass:
every sealed epoch's root must re-derive from the records still in the table.

Honest limit to document: this proves **inclusion**, not **completeness**. A root cannot prove that no
record was withheld before sealing; that needs a witness quorum (out of scope, Phase 14).

### 11b — Cost attribution (ECON-01)

`agentos_controlplane/economics.py` + `cost_record` table (0024). A `CostMeter` protocol with
`record(action, decision, usage)`; `UsageExtractor` pulls `{input_tokens, output_tokens, model}` from
a returned LangChain `AIMessage` / OpenAI Agents result, returning `None` when the shape is
unrecognized (D-7). A `PriceBook` maps `(provider, model) -> per-1k-token rates`, operator-supplied
and versioned — prices change, and a stale hardcoded rate silently misbills. Wired into
`governed_call` as `meter=`, applied in `_run_reported` after a successful run. Audited as
`cost_recorded` with short identifiers and numbers only.

### 11c — Budget as policy (ECON-02)

`BudgetLedger` with an in-memory per-agent running total (D-5), fed by the meter and reconciled by a
`BudgetReconciler` (API-04 pattern). New policy-input fields registered in `POLICY_INPUT_FIELDS` in
lockstep with the builder (the drift-lock test already enforces this):
`cost.spend_usd`, `cost.tokens`, `cost.budget_usd`, `cost.budget_used_ratio`, `cost.over_budget`.
A shipped constitution principle denies over-budget actions and escalates at a warning ratio, proving
the graduated engine — not a parallel enforcer — does the work. Unknown budget **fails open to
"no budget configured"**, not to over-budget: an unconfigured deployment must not deadlock its fleet,
and the absence of a budget is not evidence of a breach. Regression-locked: deleting the principle
must flip an over-budget action to allow.

### 11d — GPU & downstream API attribution (ECON-03)

Extends 11b rather than forking it. `downstream` attribution covers non-model spend — `tool_call` /
`mcp_call` to metered third-party APIs — keyed by `(agent, provider)`. `GpuMeter` is a probe-gated
NVML path recording `{gpu_seconds, memory_mib, attribution}` per D-9. Roll-ups per agent land on the
gated API.

### 11e — EU AI Act mapping & SOC 2 evidence (CMP-04, CMP-05)

Extends `compliance.py` (no new module — the mapping is one place by design). CMP-04 widens the
article set beyond Phase 6's minimal Art.12/26 claim (risk management, data governance, technical
documentation, record-keeping, transparency, human oversight, accuracy/robustness/cybersecurity,
deployer obligations, post-market monitoring), plus an operator-declared `risk_classification` per
agent (D-8). CMP-05 derives Trust Services Criteria evidence from the audit log by event kind:
logical access (identity verdicts, cert issue/revoke, privilege gates), change management (resource
version bumps, constitution/policy versions), monitoring (detector fires, breaker trips, kill
switches, shadow/rogue findings). The existing coverage test is extended so a live control that maps
to nothing fails the build.

### 11f — One-click evidence export (CMP-06)

`export_evidence_bundle(framework, start, end)` → the framework's mapping, the derived evidence for
the range, the in-range audit records, **and their Merkle inclusion proofs plus the anchored root**.
That last clause is the point: the bundle is verifiable standalone, by someone holding neither our
database nor our trust. Delivered as a library call, a CLI, and a gated API route. A bundle manifest
digest lets the recipient detect a bundle edited after export.

## Out of scope (Phase 11)

- Witness quorum / split-view defense and completeness proofs (Phase 14).
- Zero-knowledge compliance proofs (Phase 14, CMP/ZK).
- ABOM-03 vulnerability impact analysis (Phase 14).
- Automated regulatory *classification* of a deployment (D-8 — deliberately never).
- Real-time cost streaming / per-token metering mid-stream; metering is per completed action.

## Risks / watch-items

- **Latency (PIPE-04).** 11c touches the hot path. The ledger lookup must be a dict read; the gate
  runs before the slice commits, and the budget is never loosened to accommodate the feature.
- **Price drift.** A `PriceBook` that ships with hardcoded 2026 rates will be wrong. It is
  operator-supplied and versioned, and an unpriced model records tokens with no dollar figure rather
  than a wrong one.
- **Merkle sealing concurrency.** Sealing an epoch while records are appending must not seal a
  partially-visible range. Sealing takes the current head seq as an explicit upper bound.
- **Compliance overreach.** The single largest reputational risk in this phase is emitting something
  that reads as a conformity certificate. Every string in the bundle is reviewed against D-8.
- **GPU cross-attribution.** See D-9. The 9c precedent is the reason this is called out by name.

## Verification (phase-level success criteria)

1. A record's inclusion is provable against an externally anchored root, by a pure function, without
   disclosing any other record — and a tampered record, proof, or root fails that check.
2. Token/API/GPU cost is attributed per agent and per action, and an over-budget action is denied or
   escalated **by the graduated-response engine**, with the regression lock proving the principle is
   what does it.
3. A one-click export produces a per-framework, per-time-range bundle carrying EU AI Act and SOC 2
   evidence derived from the audit log, verifiable standalone via its inclusion proofs.
4. Full suite green; `floor_invariant`, `regression_lock` and `latency` gates green; single alembic
   head; INT-06 coverage clean.
