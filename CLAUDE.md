# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`agentos-guard` is an open-source governance and security **control plane for AI agents** — it intercepts every agent action (tool / memory / MCP / model / delegation), checks it against policy + a semantic constitution, returns a graduated decision, and writes tamper-evident audit evidence. Python-first; Rust reserved for later hot paths.

## Architecture / design docs

Design is documented (no code yet) under `docs/architecture/`. Start with `docs/architecture/README.md`, then `01-overview.md`. Key decisions are in `docs/architecture/adr/`. The build is phased — see `docs/architecture/20-roadmap.md` (Phase 0 MVP → Phase 2 moonshot).

## Branches

- `main` — stable/release branch
- `development` — active development branch; use this for feature work

## Working in this repo

These bias toward caution over speed; use judgment on trivial tasks.

- **Think before coding.** State assumptions explicitly; if uncertain, ask before implementing. If multiple interpretations exist, surface them — don't pick silently. If a simpler approach exists, say so and push back when warranted.
- **Simplicity first.** Write the minimum code that solves the problem. No speculative features, single-use abstractions, unrequested configurability, or error handling for impossible cases. If 200 lines could be 50, rewrite it.
- **Surgical changes.** Touch only what the request requires; every changed line should trace to it. Don't refactor or reformat working adjacent code, and match existing style. Remove imports/vars/functions *your* change orphaned, but leave pre-existing dead code (mention it, don't delete it) unless asked.
- **Goal-driven execution.** Turn tasks into verifiable goals before starting (e.g. "fix the bug" → "write a failing test that reproduces it, then make it pass"). For multi-step work, state a brief plan with a verification check per step, then loop until verified.
