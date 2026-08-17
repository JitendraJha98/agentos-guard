# Phase 9 — Runtime Containment & Consensus — Design

**Date:** 2026-08-04
**Branch:** `phase-9-runtime-containment-consensus` (off `development` @ `3fd1694` — phases 1–8 merged)
**Roadmap:** `.planning/ROADMAP.md` Phase 9 · **Requirements:** RUN-03, RUN-04, RUN-05, RUN-06,
RUN-07, POL-09

## Goal

Make the containment outcomes **real**. Today `graduated.py` genuinely emits `sandbox` (risk ≥
`sandbox_at`, or a low-trust escalation of `allow`) and `require_consensus`, but `enforce.py`
*substitutes* both onto the human-approval path — an audited placeholder explicitly marked "until
RUN-03/POL-09 (Phase 9)". This phase replaces that substitution with real enforcement and adds the
platform-team containment levers:

1. a `sandbox` outcome that executes in an isolated context with **quarantined** side effects (RUN-03);
2. **privilege rings** gating sensitive tools per agent (RUN-04);
3. **resource isolation** — CPU/wall, memory, and network limits per agent execution (RUN-05);
4. **circuit breakers** that auto-trip an agent/tool after a threshold of violations or errors (RUN-06);
5. **emergency shutdown** — a fleet-wide stop with an audit-logged justification (RUN-07);
6. a `require_consensus` outcome requiring **2-of-3** agent agreement before the action proceeds (POL-09).

## Cross-cutting decisions

1. **One enforcement seam, extended — never bypassed.** `enforce.py::governed_call` is the single
   outcome-enforcement map every PEP form shares (middleware hooks + the memory/MCP/delegation
   wrappers), so allow/deny/contain can never diverge. Phase 9 retires
   `_SUBSTITUTED_TO_APPROVAL` and routes `sandbox` → a `SandboxRunner` seam and `require_consensus`
   → a `ConsensusCoordinator` seam. **Fail-closed is preserved exactly as today:** a missing seam
   raises `GovernanceDenied` *before* `run()` is awaited — no side effect, no egress, never silent
   execution.
2. **The SDK stays decoupled.** New collaborators are structural `Protocol`s in the SDK (no
   control-plane import — Anti-Pattern 5); concrete implementations live in `agentos_controlplane`
   beside `StoreApprovalCoordinator`.
3. **Every containment action is audited** (`docs/architecture/05`: "All findings and containment
   actions are `AuditRecord`s and OTel events"). New `EVENT_KINDS`: `sandbox_executed`,
   `consensus_vote`, `consensus_resolved`, `circuit_tripped`, `circuit_reset`, `emergency_shutdown`,
   `privilege_ring_set`, `resource_limit_exceeded`. **Convention (settled in 9b):** a per-action
   *deny* by a pipeline gate is audited as the **decision record** carrying its `Reason` — the
   established shape for stages 1b/1c/1d — so no duplicate per-action event is added; dedicated event
   kinds are reserved for **state transitions and administration** (ring assignment, breaker
   trip/reset, shutdown, sandbox run, consensus votes). Event bodies carry **short identifiers only**;
   operator/agent free text (shutdown justification, quarantine detail) lives in its table — the
   Phase-4 AUD-04 secret-gate lesson, so a hostile string can never block an emergency control.
4. **Hot-path discipline.** The per-action gates (privilege ring, circuit breaker) follow the proven
   `KillSwitchStore` design: in-memory state for the lookup, a durable table behind it, audited
   transitions, and **fail-toward-contained** ordering on write failure (the Phase-4 4e review
   lesson — a failed clear must never silently un-contain). No per-action DB read; the `-m latency`
   gate stays green. `tracemalloc` is enabled **only** in the limited/sandbox path, never on the
   default hot path.
5. **Persistence** — new tables via Alembic `0011+` on the existing dialect-agnostic models
   (`JSON` not `JSONB`, generic types): SQLite for dev/CI, Postgres as the documented production
   target (D-14).
6. **Deterministic, offline tests** — stub handlers and stub voters; no Docker, no network, no LLM.
   `floor_invariant`, `regression_lock`, and `latency` gates green at every commit.

## RUN-05 enforcement model (the one environment-constrained decision)

This machine is Windows with no Docker, so POSIX `resource.setrlimit` and cgroups are not portable
options. `docs/architecture/05` already sets the boundary: *"Sandbox semantics depend on the PEP: the
SDK shim can intercept and stub side-effectful tools; the gateway/sidecar (later phases) can enforce
network-level isolation."* So Phase 9 enforces what the PEP layer genuinely can, portably and
deterministically:

- **Wall/CPU budget** — an `asyncio.timeout` deadline around the governed call. Cancellation lands
  only while the handler is suspended at an await; a handler that blocks the loop or swallows its
  `CancelledError` runs to completion, so the overrun is then DETECTED AFTERWARDS (elapsed time
  compared to the budget). Either way `resource_limit_exceeded` is audited and the result is withheld,
  and `preventive` states which of the two happened.
- **Memory ceiling** — sampled with stdlib `tracemalloc` around the limited call; detected at
  completion (the handler already ran) and audited. Enabled only on the limited path (measurable
  overhead). The counters are process-global, so a window that OVERLAPPED another governed call is
  unmeasurable and yields no verdict rather than cross-attributing an allocation.
- **Network** — denied outright in sandbox mode (the PEP simply never calls the real handler); on the
  normal path egress remains governed by the constitution's allowlist principle.
- **Opt-in hard OS path** — where `resource` is importable (POSIX), a subprocess runner applying
  `RLIMIT_CPU`/`RLIMIT_AS`, behind a platform capability check that **skips cleanly on Windows**
  (the established gated-test pattern).

**Honest scope, documented in code:** these are PEP-level budgets, not kernel isolation. True
CPU/memory/network confinement is the gateway/sidecar (Phase 10) and K8s (Phase 14) layer. We claim
enforcement of the budget, not containment of a hostile native process.

## Slice breakdown

Each slice is an independently shippable vertical slice, built subagent-driven
(implement → spec-review → quality-review → fix → re-review), one commit per task, gates green at
every commit — the Phases 3–6 rhythm.

### 9a — Sandboxed execution + quarantined side effects (RUN-03)
- `SandboxRunner` Protocol in `enforce.py`; `sandbox` routes to it instead of the approval
  substitution. A `QuarantineSandbox` in the control plane runs the action in **quarantine**: the real
  handler is never invoked, so no side effect and no egress occur; the runner records a `SandboxRun`
  row (agent, action, target, redacted effect summary, observed outcome).
- **Return contract (explicit, to remove ambiguity):** `governed_call` is typed `-> _T`, so the
  sandbox path returns whatever the injected `SandboxRunner.run(action, decision)` yields, and that
  value is a **`SandboxResult`** carrying `quarantined=True` + the run id — never a fabricated
  imitation of the real handler's return value. The PEP surfaces it as a governed, clearly-marked
  quarantine outcome (the middleware renders it like the deny path's `ToolMessage`, i.e. the model
  sees that the call was contained, not that it succeeded).
- Audited `sandbox_executed`; **fail-closed** when no runner is wired (`GovernanceDenied`).
- Tests: a `sandbox` decision does NOT invoke the real handler (the load-bearing no-side-effect
  assertion); a quarantine row + audit event are written; without a runner the call is denied; the
  existing substitution tests are updated to the new semantics.

### 9b — Privilege rings (RUN-04)
- `PrivilegeRingStore`: per-agent ring tier and per-target `required_ring` (table + in-memory
  lookup). A verified agent whose ring is below the target's requirement is denied with
  `Reason(stage="privilege", code="insufficient_ring")`, audited as a **decision record** (per the
  convention in decision 3); the *administrative* ring assignment is audited as `privilege_ring_set`.
  A delegated action's effective ring is **capped by its delegation chain**, so a child can never
  exceed the ring its parent held (the TRST-04 intersection principle applied to privilege).
- Gate placement: a deterministic check **after** identity verification (it needs the verified
  agent_id) and before policy — a pure restriction, so the floor invariant holds trivially.
- **Registered-sensitivity model:** only explicitly registered targets carry a `required_ring`;
  unregistered targets are ring 0 and remain governed by the constitution floor. This keeps every
  existing pipeline and test working, and the gate optional (`None` default → check never runs).
- Tests: under-privileged → deny + reason + audit; at/above → proceeds; unregistered target →
  unaffected; `None` default → behavior unchanged; in-memory (no per-action DB read).

### 9c — Resource isolation (RUN-05)
- `ResourceLimits` (wall_s, cpu_s, memory_mb, network: allow|deny) resolved per agent from a table +
  in-memory cache; a `LimitedRunner` wrapper applies the budget model above around the governed call,
  aborting and auditing `resource_limit_exceeded` on breach.
- The opt-in POSIX `setrlimit` subprocess path behind a capability check (skips on Windows).
- Tests: a handler exceeding the wall budget is aborted + audited (and its side effect does not
  complete); a memory-ceiling breach is detected; network is denied under sandbox; the POSIX path is
  exercised where available and skipped otherwise; default (no limits configured) leaves the hot path
  untouched and `-m latency` green.

### 9d — Circuit breakers (RUN-06)
- `CircuitBreakerStore`: rolling-window counters of violations (non-allow outcomes) and execution
  errors, keyed per agent and per (agent, target). Crossing a threshold trips the breaker OPEN →
  subsequent actions are denied with `circuit_open`; a cooldown moves it HALF_OPEN (one trial) and a
  success closes it; an operator can reset explicitly. Transitions are audited
  (`circuit_tripped`/`circuit_reset`) and reload on restart.
- **Precedence is explicit:** kill switch (stage 0, operator intent) is checked before the breaker
  (automatic), and each denies with its own distinct reason code so audit forensics can tell an
  operator halt from an auto-trip.
- Tests: N violations → trip → next action denied; cooldown → half-open → success closes; per-target
  scoping; audited transitions; restart reload; `None` default → unchanged.

### 9e — Emergency shutdown (RUN-07)
- `emergency_shutdown(justification, set_by)` on the containment surface: a fleet-wide halt that
  **requires** a non-empty justification (empty → rejected, `422` at the API), persists the
  justification to its table, audits `emergency_shutdown` with short identifiers only, and is cleared
  only by an explicit operator resume.
- Exposed on the existing gated API (`POST /kill/emergency-shutdown` + resume) and the Phase-5
  dashboard.
- Tests: shutdown → every agent (including one never seen before) is denied; empty justification
  rejected and nothing halted; justification persisted + event audited; resume restores; e2e through
  the API and dashboard into a real pipeline denial.

### 9f — 2-of-3 consensus (POL-09)
- `ConsensusCoordinator` Protocol in `enforce.py`; `require_consensus` routes to it. A
  `StoreConsensusCoordinator` collects votes from registered voters through an injectable
  `ConsensusVoter` seam (`async vote(action, decision) -> bool`), requires a **2-of-3 quorum** to
  proceed, persists a `ConsensusRound` + per-vote rows, and audits `consensus_vote` per vote plus
  `consensus_resolved`.
- **Fail-closed everywhere:** no coordinator → `GovernanceDenied`; a voter timeout/exception counts as
  no-vote; abstains/ties that miss quorum → deny.
- Tests: 2 approve of 3 → proceeds; 1 of 3 → denied; a raising/timing-out voter counts as no-vote and
  quorum logic still holds; every vote + the resolution audited; no coordinator → denied.

## Out of scope (Phase 9)

- Kernel/container/network-level isolation — the gateway/sidecar PEP (Phase 10, INT-07) and the K8s
  operator (Phase 14, INT-09).
- **Reversible-execution** sandbox mode (execute-then-roll-back). The success criterion allows
  "quarantined **or** reversible"; Phase 9 ships quarantine, which is deterministic and testable
  without a live side-effecting resource.
- BFT-backed consensus (POL-12, Phase 13) — POL-09 is application-level voting.
- Reputation/trust changes (Phase 7, shipped) — breakers read violation history but do not restate
  reputation.
- Phase 6's **OSS-01** (first tagged PyPI release) remains open and unrelated: it needs PyPI
  Trusted-Publisher setup under the maintainer's account.

## Risks / watch-items

- **`enforce.py` is the shared map for all five interception types.** The reviewers must answer "can
  any outcome now reach `run()` without its seam?" — every new path keeps the fail-closed
  `GovernanceDenied` default, and the existing substitution tests get updated rather than deleted.
- **Latency.** Ring + breaker checks run per action. Keep them in-memory, keep `tracemalloc` off the
  default path, and keep `-m latency` green (the Phase-6 best-of-N/interleaved gates are the guard).
- **Containment-write ordering.** Every state change must fail toward contained (kill/trip persist
  before the in-memory un-contain is released) — the Phase-4 4e lesson.
- **Sandbox honesty.** A quarantined run must not be reported to the caller as a real execution;
  the returned result is explicitly marked quarantined so callers cannot mistake it for success.
- **Windows-gated RUN-05 path.** The POSIX `setrlimit` runner cannot be validated on this machine; it
  is capability-gated and skipped, and that limitation is reported rather than implied away.

## Verification (phase-level success criteria)

1. A `sandbox` outcome runs in an isolated context with quarantined side effects, and sensitive tools
   are gated behind higher privilege rings per agent (9a + 9b).
2. Resource isolation enforces CPU/wall, memory, and network limits per agent execution, and circuit
   breakers auto-trip an agent/tool after a threshold of violations or errors (9c + 9d).
3. Emergency shutdown stops the fleet with an audit-logged justification (9e).
4. A `require_consensus` outcome requires 2-of-3 agreement before the action proceeds (9f).
5. `floor_invariant` + `regression_lock` + `latency` green throughout; no outcome can execute without
   its enforcement seam.
