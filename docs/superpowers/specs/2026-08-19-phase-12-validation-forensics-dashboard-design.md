# Phase 12 — Continuous Adversarial Validation, Forensics & Rich Dashboard — Design

**Date:** 2026-08-19
**Branch:** `phase-10-gateway-adapter-graph` (continued — operator's instruction; Phase 12 commits stay
separable from the Phase 9/10/11 stack)
**Requirements:** TEST-07, TEST-08, TEST-09, OBS-04, OBS-05, OBS-06, AUD-09, DASH-04
**Depends on:** Phase 11 (complete). Phase 6's red-team harness, Phase 9's circuit breakers, Phase 10's
materialized agent graph, and Phase 11's audit/Merkle work are the load-bearing prior art.

## Goal

Phase 6 proved the guard holds **once**, in CI, against a fixed corpus. Phase 12 makes that a
**continuous** claim, and adds the two things an operator needs when something does slip: a way to see
an agent's health before it fails, and a way to reconstruct what actually happened after it does.

The three strands are one story. Continuous validation says *is the guard still holding?* Health
monitoring says *is this agent behaving?* The evidence graph says *what caused what?* The dashboard is
where an operator sees all three without running a query.

## Cross-cutting decisions

**D-1. Validation ASKS the guard; it never ATTACKS through it.** The Phase-6 harness feeds each attack
through `evaluate(action) -> Decision` — the PDP — and never invokes the handler. Scheduled validation
against a live agent keeps exactly that: it asks the live pipeline what it *would* decide. This is not
a performance choice, it is the safety property. An executing probe run on a schedule against a
deployment whose guard has a hole would *perform* the exfiltration it was checking for — the
validation tool becoming the breach it exists to detect. Nothing in this phase executes an attack
payload.

**D-2. Lineage is CLAIMED, not proven — and a *forensic* graph must say so on every answer.** Phase 10
(DISC-06) established that `identity_verified` authenticates who **acted**, not that
`parent_action_id` names a real delegation. AUD-09 raises the stakes by calling its output evidence:
an investigator reading a reconstructed causal chain as proven would draw a conclusion the data cannot
support, and would do it in exactly the setting where being wrong matters most. Every chain this phase
returns carries the same honest qualifier, in the payload rather than in our docs. Closing the gap
needs the TRST-04 authority cross-check — Phase 13, and named as such.

**D-3. Query-time joins, no separate graph database.** A recursive CTE over `audit_record`, joined to
the Phase-10 `agent_graph` tables. Verified available on this machine (SQLite 3.45.3) and on the
Postgres production target. Two hazards are structural, not hypothetical: `parent_action_id` is
caller-supplied, so a **cycle** is reachable and an unbounded recursive CTE on a cycle does not
terminate; and depth is unbounded by nature. Both are capped, and truncation is reported rather than
silent — the no-silent-caps rule the DISC-04/05/06 stores already follow.

**D-4. A rate with a small denominator is a lie told with arithmetic.** TEST-07 tracks
attack-success-rate per agent and attack class over time. One run of two attacks yielding 50% must
never render like five hundred runs yielding 50%. So the store keeps **counts**, the rate is derived,
and `n` travels with every rate we report. A trend line that hides its sample size invites exactly the
"the numbers went up, ship it" reading a safety metric must resist.

**D-5. Idle is not dead.** OBS-04's liveness derives from audit records, and an agent with nothing to
do is byte-identical to one that crashed. We report `last_seen_at` as a fact and let the operator's
threshold decide; the health surface never asserts "this agent is down". Same discipline as ECON-01's
absent-vs-zero: the two readings mean different things and collapsing them invents information.

**D-6. Error rate needs its denominator stated.** "Error rate" over what — all actions, executed
actions, or the ones the breaker saw? A governance **deny** is not an error; it is the system working.
The health surface counts execution failures against executed actions and says so, because a number
that silently counts denials as errors makes a well-governed agent look broken and pushes an operator
to loosen the guard.

**D-7. The evidence graph inherits AUD-04 redaction and must not become a way around it.** Audit bodies
are already fail-closed redacted at write time, so a reconstructed conversation carries redacted
bodies by construction. The forensic surface adds no un-redacted read path, and it rides the same
gate as the rest of the operator API: a conversation reconstruction is the most sensitive read in the
product.

**D-8. OBS-06 and DASH-04 are one deliverable.** "Per-agent SLO and violation dashboards with attack
visualization" (OBS-06) and "the dashboard adds the live agent graph, per-agent SLOs/violations, and
attack visualization" (DASH-04) describe the same screen from two requirement families. One slice
satisfies both; splitting them would produce two half-dashboards.

**D-9. The dashboard renders server-side, like the Phase-5 one.** No new frontend stack, no CDN — the
existing Jinja templates plus inline SVG for the graph. A governance console that pulls a charting
library from a CDN is an unreviewed third-party dependency on the operator's most privileged screen.

## Verified at plan time (2026-08-19, this machine)

- **SQLite 3.45.3** supports `WITH RECURSIVE`; the depth-bounded lineage walk was run and returned the
  expected chain. Postgres supports the same syntax, so one query serves both (D-14).
- `agentos_sdk.redteam.run_suite(evaluate, suite, *, agent_id, token)` is **evaluate-only** and
  deterministic — no LLM, no network, no clock, no RNG. This is the seam D-1 preserves.
- `CircuitBreakerStore` exposes `status(agent, target)`, `list_open()`, `record_failure/success`.
- `AgentGraphStore.view()` returns a bounded, closed subgraph (Phase 10's re-review fix).
- The dashboard is Jinja + cookie-gated (`make_require_session`), templates in
  `agentos_controlplane/templates/`.

## Slice breakdown

Six slices. 12f consumes 12a and 12d; 12b consumes 12a; 12e is independent.

### 12a — Attack-success-rate over time (TEST-07)

`redteam_run` + `redteam_result` tables (migration 0028) and a `ValidationStore` that records one run
(agent, suite, timestamp, per-attack outcome) and answers "ASR per agent per attack class over
window W". Counts stored, rate derived, `n` always reported (D-4). A run is audited as
`validation_run` with short identifiers and numbers only.

### 12b — Continuous validation on a schedule (TEST-08)

A `ValidationScheduler` following the API-04 reconciler pattern: on each pass it re-runs the suites
against the **live pipeline's `evaluate`** (D-1) and records a run via 12a. Bounded concurrency, and a
failure in one suite isolates rather than killing the loop — a dead validation loop rots the very
signal it exists to produce, which is the Phase-7 reconciler lesson.

The honest limit to document: this validates the **decision path** on the corpus we ship. It is not a
pentest and does not discover novel attacks; it detects *regression* — a guard that used to hold and
now does not.

### 12c — Campaign-style multi-step attacks (TEST-09)

A `Campaign` is an ordered sequence of attacks sharing a `conversation_id`, so it exercises the
SEC-13 sequence correlator that single-shot probes cannot reach — the `rename_then_drop` shape is the
canonical case, and it is precisely the class Phase 3 built the correlator for. Scored on whether the
campaign was blocked **at any step**, with the step recorded: a campaign blocked at step 4 of 5 is a
materially different result from one blocked at step 1, and reporting only "blocked" throws that away.
Evaluate-only (D-1).

### 12d — Agent health monitoring (OBS-04)

A read-side `HealthStore` over data that already exists: `last_seen_at` from the audit log (a fact, not
a verdict — D-5), execution-failure rate with its denominator named (D-6), and live circuit-breaker
state from `CircuitBreakerStore`. No new hot-path work and no new writer; health is a **query**, not a
subsystem.

### 12e — Evidence graph & conversation tracing (AUD-09, OBS-05)

`forensics.py`: a depth-bounded, cycle-safe recursive CTE over `audit_record` following
`parent_action_id`, plus a `conversation_id` reconstruction, joined at query time to the Phase-10
graph for the component view. Every result carries the D-2 qualifier and a `truncated` flag. Gated
read routes.

### 12f — Rich dashboard (OBS-06, DASH-04)

Three additions to the existing Jinja dashboard: the live agent graph (inline SVG, from
`AgentGraphStore.view()`), per-agent SLO/violation panels (from 12d plus the outcome mix), and attack
visualization (from 12a's trend, with `n` shown — D-4). Server-rendered, no CDN (D-9).

## Out of scope (Phase 12)

- Proving lineage (D-2) — the TRST-04 authority cross-check is Phase 13.
- Discovering novel attacks. Self-play and runtime patching are Phase 14.
- Executing attack payloads anywhere, on any schedule (D-1) — deliberately never.
- A separate graph database (AUD-09 says so explicitly).
- A frontend framework or client-side charting library (D-9).

## Risks / watch-items

- **A validation tool that attacks production.** The single largest risk in this phase, addressed by
  D-1 and to be re-checked by every reviewer: no code path may invoke a handler with an attack payload.
- **Recursive CTE non-termination** on a forged `parent_action_id` cycle. Depth cap + cycle detection,
  tested with an actual cycle rather than argued.
- **Forensic overclaim.** D-2. An evidence graph is used to attribute blame; a claimed edge presented
  as proven is the Phase-11 conformity mistake wearing a different hat.
- **Metric cardinality.** Phase 6's Slice 6b review found a metric-cardinality DoS. Per-agent ×
  per-attack-class × per-window is exactly that shape again; bound the key space.
- **Dashboard as a disclosure surface.** Conversation tracing on a screen is the most sensitive read
  in the product. Same gate, redacted bodies, no new read path (D-7).

## Verification (phase-level success criteria)

1. ASR is tracked per agent and attack class over time with its sample size, continuous validation
   re-runs suites against the live decision path on a schedule, and campaigns run multi-step attacks
   scored by the step at which they were blocked — with no code path executing an attack payload.
2. Health reports liveness, error rate with its denominator, and breaker state per agent, without
   asserting a verdict the data does not support; conversation tracing and the evidence graph
   reconstruct causal chains at query time from the audit log joined to the agent graph, bounded,
   cycle-safe, and labelled as claimed rather than proven lineage.
3. The dashboard shows the live agent graph, per-agent SLOs/violations, and attack trends, rendered
   server-side with no third-party CDN.
4. Full suite green; `floor_invariant`, `regression_lock` and `latency` gates green; single alembic
   head; INT-06 coverage clean.
