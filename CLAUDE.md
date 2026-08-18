# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`agentos-guard` is an open-source governance and security **control plane for AI agents** — it intercepts every agent action (tool / memory / MCP / model / delegation), checks it against policy + a semantic constitution, returns a graduated decision, and writes tamper-evident audit evidence. Python-first; Rust reserved for later hot paths.

## Architecture / design docs

Design is documented under `docs/architecture/`. Start with `docs/architecture/README.md`, then `01-overview.md`. Key decisions are in `docs/architecture/adr/`. The build is phased — see `docs/architecture/20-roadmap.md` (Phase 0 MVP → Phase 2 moonshot). Implementation lives in `packages/` (uv workspace: contract, pipeline, constitution, controlplane, sdk); execution Phases 1–5 are built and merged.

## Branches

- `main` — stable/release branch
- `development` — active development branch; use this for feature work

## Working in this repo

These bias toward caution over speed; use judgment on trivial tasks.

- **Think before coding.** State assumptions explicitly; if uncertain, ask before implementing. If multiple interpretations exist, surface them — don't pick silently. If a simpler approach exists, say so and push back when warranted.
- **Simplicity first.** Write the minimum code that solves the problem. No speculative features, single-use abstractions, unrequested configurability, or error handling for impossible cases. If 200 lines could be 50, rewrite it.
- **Surgical changes.** Touch only what the request requires; every changed line should trace to it. Don't refactor or reformat working adjacent code, and match existing style. Remove imports/vars/functions *your* change orphaned, but leave pre-existing dead code (mention it, don't delete it) unless asked.
- **Goal-driven execution.** Turn tasks into verifiable goals before starting (e.g. "fix the bug" → "write a failing test that reproduces it, then make it pass"). For multi-step work, state a brief plan with a verification check per step, then loop until verified.

## Planning (GSD)

Project planning lives in `.planning/` and drives *what* to build next. `docs/architecture/` remains the authoritative design; `.planning/` decomposes it into executable phases.

- `.planning/PROJECT.md` — project context, scoped requirements, key decisions
- `.planning/REQUIREMENTS.md` — requirements (REQ-IDs, phase-tagged P0/P1/P2) + traceability to phases
- `.planning/ROADMAP.md` — 14 vertical-slice phases covering the full Phase 0–2 vision
- `.planning/research/` — domain research: `STACK.md`, `FEATURES.md`, `ARCHITECTURE.md`, `PITFALLS.md`, `SUMMARY.md`
- `.planning/STATE.md` — current workflow state

Recommended stack (from `.planning/research/STACK.md`): LangChain v1 `AgentMiddleware` interception, OPA server behind a `PolicyEngine` interface (opa-wasm in-process toggle), Anthropic structured outputs for the semantic interpreter, FastAPI + Pydantic v2 + SQLAlchemy 2.0/asyncpg/Alembic on Postgres, stdlib `hashlib` hash-chain audit, Presidio redaction, OpenTelemetry, and garak + PyRIT under pytest for the red-team gate.

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Route phase work through GSD commands so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:discuss-phase <n>` then `/gsd:plan-phase <n>` to plan a roadmap phase
- `/gsd:execute-phase <n>` for planned phase work
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing

Next step: **Phase 11 (Merkle Audit, Economics, ABOM & Compliance Export)**. Phases 7–10 are complete: Phase 7 = TRST-03 reputation, TRST-04 delegation trust/scope, IDN-03 X.509 certs, API-04 reconcilers; Phase 8 = the full detector surface (SEC-04/05/06/07/08/09/10/11/14) + MCP gateway + ABOM-01/02; Phase 9 = runtime containment & consensus (RUN-03..07 + POL-09) on branch `phase-9-runtime-containment-consensus`, **pending PR into `development`** — every graduated outcome now has real enforcement and the interim sandbox/require_consensus approval substitution is retired; Phase 10 = gateway PEP + second adapter + discovery + live graph (INT-07/08, DISC-03..06) on branch `phase-10-gateway-adapter-graph`, **pending PR into `development`** — agents are now governable with no SDK in their process, and the fleet is discoverable rather than only declared. The AGT re-verification debt is cleared (AGT still v4.1.0; cross-action-correlation gap downgraded Durable→Contested — see `docs/architecture/30-comparison-agt.md`). **The one remaining item from earlier phases is Phase 6's OSS-01** — the first tagged PyPI release (`.github/workflows/release.yml` is scaffolded; PyPI Trusted-Publisher setup + a `vX.Y.Z` tag pending). Use judgment on trivial tasks per "Working in this repo" above.
<!-- GSD:workflow-end -->
