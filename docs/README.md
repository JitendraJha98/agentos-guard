# docs/ — the design layer

This folder holds the **authoritative design** for agentos-guard: *what* the system is and *why*
it's built that way. It is the source of truth. If the design and any other document disagree,
**the design here wins**.

## What's here

| Path | Contents |
|------|----------|
| [`architecture/`](architecture/) | The full architecture: the manifesto, the numbered spec docs (01–10), the roadmap, the AGT comparison, and the ADRs. **Start at [`architecture/00-manifesto.md`](architecture/00-manifesto.md).** |

## How this relates to `.planning/`

Two folders, two distinct jobs — **not duplicates**:

| | `docs/` (here) | [`.planning/`](../.planning/) |
|---|----------------|------------------------------|
| **Answers** | *What is the system, and why?* | *How and in what order do we build it?* |
| **Role** | Authoritative **design** | Execution **decomposition** (GSD workflow) |
| **Stability** | Changes only when the design changes | Changes every time a phase is planned/executed |
| **Source of truth for** | Components, contracts, paradigm, decisions | Phases, REQ-IDs, plans, traceability, status |

Rule of thumb: **`docs/` defines; `.planning/` executes.** Planning documents *reference* the
design here — they must not re-specify it. (The one research file that used to re-render the
architecture, `.planning/research/ARCHITECTURE.md`, has been trimmed to validation + pointers.)

## Status

Phase 1 (the walking skeleton) is implemented and merged; everything beyond it is design ahead of
code. Build sequence: [`architecture/20-roadmap.md`](architecture/20-roadmap.md); live execution
status: [`../.planning/ROADMAP.md`](../.planning/ROADMAP.md).
