# .planning/ — the execution layer (GSD)

This folder holds the **execution decomposition** for agentos-guard: *how* and *in what order* we
build the design. It is driven by the GSD workflow (see the root `CLAUDE.md`). It **references** the
design in [`../docs/architecture/`](../docs/architecture/) — it does **not** re-specify it.

> **Design vs execution:** if you want to know *what the system is and why*, read
> [`../docs/`](../docs/). If you want to know *what we're building next and how it's tracked*, read
> here. When the two seem to overlap on a topic, `docs/` is authoritative; planning carries a
> summary + a pointer.

## What's here

| Path | Role | Authoritative for |
|------|------|-------------------|
| [`PROJECT.md`](PROJECT.md) | Project context, scoped requirements overview, key decisions | Project-level scope & decisions |
| [`REQUIREMENTS.md`](REQUIREMENTS.md) | Every requirement (REQ-IDs, P0/P1/P2 tags) + phase traceability | The committed requirement set |
| [`ROADMAP.md`](ROADMAP.md) | The 14 vertical-slice phases, their goals, success criteria, status | Build sequence & phase status |
| [`STATE.md`](STATE.md) | Current GSD workflow state (where we are right now) | "What's the next action" |
| [`config.json`](config.json) | GSD tooling config | — |
| [`phases/`](phases/) | Per-phase execution records: plans, summaries, verification, security, review | **History of executed work** (e.g. `01-walking-skeleton/`) |
| [`research/`](research/) | 📸 Dated research snapshots that fed the design & plan | *Why* we chose what we chose (not current truth) |

## Two important conventions

1. **`research/` is a snapshot, not live truth.** Every file there is dated 2026-06-01 and carries a
   banner saying so. It records the reasoning that informed the design; the *current* design lives in
   `docs/architecture/`, and the *current* plan lives in the four top-level files above.
2. **`phases/NN-*/` is history.** Once a phase is executed and merged, its plans/summaries/verification
   are an immutable record (they trace merged code to REQ-IDs). We don't rewrite them; new work creates
   new phase folders.

## Where to look

- *"What should I build next?"* → [`STATE.md`](STATE.md) then [`ROADMAP.md`](ROADMAP.md).
- *"Is requirement X done, and in which phase?"* → [`REQUIREMENTS.md`](REQUIREMENTS.md) traceability table.
- *"Why is the design the way it is?"* → [`research/`](research/) + `../docs/architecture/adr/`.
- *"What is the system, precisely?"* → [`../docs/architecture/`](../docs/architecture/).
