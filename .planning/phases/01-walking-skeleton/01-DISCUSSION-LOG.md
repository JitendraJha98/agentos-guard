# Phase 1: Walking Skeleton - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-01
**Phase:** 01-walking-skeleton
**Areas discussed:** Demo slice, Policy engine deployment, Pipeline boundary, Audit substrate

---

## Demo slice

| Option | Description | Selected |
|--------|-------------|----------|
| File read + path confinement | `read_file` tool governed by "never read outside the workspace"; injection → read secret file → deny. (Claude recommended) | |
| HTTP fetch + egress allowlist | `http_get` tool governed by "no requests to non-allowlisted hosts" (data-exfil framing) | ✓ |
| Shell run + unsafe-command block | `run_command` tool governed by "no destructive/unsafe commands" | |

**User's choice:** HTTP fetch + egress allowlist
**Notes:** Diverged from the recommendation (file read). Red-team test framed as injected-content telling the agent to exfiltrate to a non-allowlisted URL → deny.

---

## Policy engine deployment

| Option | Description | Selected |
|--------|-------------|----------|
| OPA server / HTTP sidecar | Full Rego, no WASM build pain, easy to cache. (Claude recommended — research P0 pick) | |
| opa-wasm in-process | Single deployable, lowest latency, adds `opa build -t wasm` + wasmer runtime | ✓ |

**User's choice:** opa-wasm in-process
**Notes:** Diverged from the recommendation. Kept behind the `PolicyEngine` interface so OPA-server remains a future toggle.

---

## Pipeline boundary

| Option | Description | Selected |
|--------|-------------|----------|
| In-process library call | Simplest; AgentAction serializable from day one so a network PEP drops in later. (Claude recommended) | ✓ |
| Local HTTP control-plane endpoint | Exercises the network contract now; heavier for a thinnest-slice skeleton | |

**User's choice:** In-process library call
**Notes:** Aligned with recommendation. Contract package (PIPE-07) built first, serializable.

---

## Audit substrate

| Option | Description | Selected |
|--------|-------------|----------|
| Postgres now | Real append-only hash-chained table from Phase 1; Phase 5 adds the API over it. (Claude recommended) | ✓ |
| Lightweight store, Postgres in Phase 5 | SQLite/file to bootstrap; risk of rework + false-confidence | |
| In-memory only for skeleton | Thinnest; not durable; weakest proof of AUD-01 | |

**User's choice:** Postgres now
**Notes:** Aligned with recommendation. docker-compose (dev) + testcontainers (tests); SQLite avoided per research.

---

## Claude's Discretion

- Identity token mechanism (JWT vs Ed25519)
- Repo/package layout (uv workspace: contract, pipeline, SDK, policies, tests)
- Egress allowlist source (Rego data document vs config)
- Exact prompt-injection heuristic for SEC-01
- Postgres dev wiring (docker-compose vs testcontainers)

## Deferred Ideas

No scope creep arose. Out-of-phase items captured in CONTEXT.md `<deferred>`: Constitution authoring/compiler (P3), semantic interpreter (P3), own-cache/latency/fail-posture (P3), other interception types (P2), full graduated outcomes + approvals (P3/P9), audit provenance/verifier/anchoring/Merkle (P4/P11), control-plane API + dashboard (P5).
