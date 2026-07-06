# Planning & Architecture Audit — 2026-07-05

**Scope:** every artifact in `.planning/` (PROJECT, REQUIREMENTS, ROADMAP, STATE, research/,
phases/) and `docs/architecture/` (manifesto, 01–10, 20, 30, ADRs), cross-checked against the
implemented code on `development` (Phases 1–5 merged 2026-07-03).

**Verdict up front:** the plan is structurally sound — the phase decomposition, dependency
spine, REQ traceability discipline, P0-killer invariants, and competitive wedge logic all hold
up under adversarial reading. The problems found were (a) systematic **status drift** (the docs
lagged the code by two full phases), (b) one **strategic hole** (zero open-source distribution
requirements in a plan whose stated goal is winning the open-source market), and (c) a small set
of **timeline and process risks** that Phase 6 planning must absorb. Everything in category (a)
and (b) was fixed in this audit; category (c) is recorded here and in `STATE.md` Blockers.

## Evidence base

- 1,043 tests collected (`pytest --collect-only`, 2026-07-05); CI (`.github/workflows/ci.yml`)
  runs the full suite plus a hard `regression_lock` gate and a 100× detector-determinism check.
- Code spot-checks confirmed the Phase 3–5 claims are real, not aspirational: full 8-outcome
  spectrum incl. `temporary_exception`/`governance_review` (`graduated.py`, `decision.py`),
  sequence-intent correlation (`pipeline/sequence.py`), latency benchmark
  (`tests/benchmarks/test_latency_trend.py`), RFC-3161 anchoring (`checkpoint.py`), secret
  last gate (`secret_scan.py`), offline chain verifier (`audit_verify.py`), red-team lock
  (`tests/redteam/`), golden compiler tests (`tests/golden/`).
- Merges PR #12 (Phase 5) and PR #14 (Phase 4) on `development`, 2026-07-03.

## A — Status drift (FIXED in this audit)

| # | Finding | Where | Fix applied |
|---|---------|-------|-------------|
| A1 | **36 delivered requirements still marked Pending.** Everything Phases 3–5 shipped (PIPE-04/05/06/08/09, POL-01/02/04/05/07/08/13/14, SEC-02/03/12/13, TRST-02, RUN-01/02, AUD-02/03/04/05/08, API-01/02/03, SDK-02/04/05, DISC-01/02, DASH-01/02/03) was unchecked and "Pending" in traceability — the traceability table could not be trusted at a glance, defeating its purpose. | `.planning/REQUIREMENTS.md` | All 36 checkboxes + traceability rows flipped to Complete (script-verified: exactly one match per REQ-ID). |
| A2 | **"Design-only project, no code"** in the Validated section; Active checklist showed zero shipped items; ADR outcomes all "Pending"; Context said only Phase 1 implemented. | `.planning/PROJECT.md` | Validated section populated with the Phase 1–5 capability groups; 15 shipped P0 bullets checked; ADR-0001–0006 outcomes marked validated with phase references; Context corrected. |
| A3 | **"Design is documented (no code yet)"** — misleads every future Claude session. | `CLAUDE.md` | Corrected; now points at `packages/` and states Phases 1–5 built. |
| A4 | Footer said only Phase 1 implemented. | `docs/architecture/README.md` | Corrected to Phases 1–5 + Phase 6 closes P0. |
| A5 | **Resolved conditionals left standing:** "until roadmap Phase 3 lands, AGT's three shipped outcomes exceed our shipped three" (manifesto + 30-comparison) — Phase 3 landed 2026-06-12. The "ahead today" lists also omitted the shipped wedge (graduated spectrum, sequence correlation, signed/anchored audit, kill switch, quickstart). | `docs/architecture/00-manifesto.md`, `30-comparison-agt.md` | Both honest-positioning sections updated with an explicit as-of date (shipped list 2026-07-03; AGT facts still labeled verified 2026-06-10 — NOT re-verified here, see C2). |
| A6 | Phases 3–5 detail sections still said "**Plans**: TBD"; Phase 4's user-requested scope addition (NVIDIA interpreter adapter, slice 4f) appears nowhere in roadmap/requirements. | `.planning/ROADMAP.md` | Plan lines now point at the phase folders; Phase 4 line records the 4f scope addition (no REQ-ID, user-requested). |

**Root cause & prevention:** phase close-outs updated ROADMAP.md and STATE.md but not
REQUIREMENTS.md/PROJECT.md (the GSD transition step was skipped or partial for Phases 3–5).
Recommendation: make "flip REQ checkboxes + traceability + PROJECT Validated" an explicit
item in every phase-close checklist.

## B — Strategic hole (FIXED: requirements added)

| # | Finding | Fix applied |
|---|---------|-------------|
| B1 | **Zero open-source distribution/community requirements** in all 121 REQs, for a project whose stated goal is *winning the open-source market*. Nothing is published to PyPI (the quickstart's "single `pip install`" is only true inside this repo); no `CONTRIBUTING.md`; no `SECURITY.md` — a security product without a vulnerability-disclosure policy is a credibility problem at launch. The README even links a Contributing anchor and shows a CI badge, but the community scaffolding doesn't exist. | Added **OSS-01** (PyPI release engineering, tagged release workflow) and **OSS-02** (CONTRIBUTING.md, SECURITY.md, issue/PR templates) as P0 requirements mapped to Phase 6; Phase 6 success criterion 5 added; coverage now 123/123. Rationale: Phase 6 closes P0 = "launch"; launching un-installable is not launching. |

## C — Timeline & process risks (OPEN — recorded in STATE.md Blockers, absorb into Phase 6 planning)

| # | Risk | Recommendation |
|---|------|----------------|
| C1 | **EU AI Act high-risk obligations bind 2026-08-02 — under four weeks away.** CMP-03 (minimal Art. 12/26 evidence claim) is in Phase 6, which has not started. This is the only hard external date in the whole plan. | Run `/gsd:plan-phase 6` immediately; order slices so CMP-03 (and the OWASP/NIST mapping it leans on, CMP-01/02) lands first, before the OTel and red-team slices. |
| C2 | **AGT re-verification is overdue by the project's own rule** ("re-verify at the start of every phase"; competitive facts older than one phase are presumed stale). Last verification: 2026-06-10 (v4.1.0). Phases 4 and 5 both started without a documented re-check; AGT ships monthly, so the scorecard is now ~1 month / potentially 1 release stale. All positioning edits in this audit deliberately kept the 2026-06-10 label rather than fabricating freshness. | Make the AGT re-check the first task of Phase 6 planning, and add it as a standing checklist item in the phase-plan template so it stops being skipped. |
| C3 | **Phase 6 is now the heaviest remaining P0 phase (15 REQs: OBS×3, CMP×3, TEST×6, SDK-03, OSS×2)** after phases that carried 6–10. It is also the phase where the 2026-06-01 stack research is most perishable: garak 0.15.x / PyRIT 0.13.x pins and the *experimental* OTel GenAI semantic conventions (`OTEL_SEMCONV_STABILITY_OPT_IN`) all need re-verification before slicing. | Expect 6–8 slices, not 4; re-verify the three version pins during planning; keep the research's advice to isolate garak/PyRIT in a dev/redteam extra so the runtime stays lean. |
| C4 | **Second framework adapter waits until Phase 10**, but the research flagged single-framework launch as "the biggest addressable-market gap" and suggested it as P0-stretch. The wedge-first rationale for deferring is sound — this is a conscious bet, not an oversight — but it was made 2026-06-10 and should be re-validated once P0 closes rather than silently ridden to Phase 10. | At Phase 6 close (= P0 launch review), explicitly re-decide: pull a CrewAI/OpenAI-Agents adapter forward into a decimal phase (6.1) if OSS adoption feedback demands it, or reaffirm Phase 10. |
| C5 | **The AGT adapter exists only in prose** (30-comparison + ROADMAP overview: "tracked alongside the Phase-10 gateway PEP") — no REQ-ID, so nothing forces the decision. | Fine to leave untracked until Phase 10 planning, but the Phase 10 plan must explicitly decide it (add a REQ or drop it) so it doesn't evaporate. |
| C6 | **Postgres is the declared production target but the entire suite runs SQLite**; Phase 5 said a Postgres-validation CI job would be "gated the way the live-interpreter tests are gated" — no such job exists in `ci.yml` yet. Risk compounds at Phase 7 (reconciliation loops, cache invalidation) and Phase 11 (Merkle/exports). | Add the gated Postgres job (testcontainers or service container) during Phase 6; it must exist before any Phase 7 work. |
| C7 | **Phase-1 deferred item still live:** the `opa-wasmtime` atexit benchmark hook still spews `ValueError: min() iterable argument is empty` at interpreter shutdown (reproduced during this audit's pytest run). Harmless, but it pollutes CI logs and will be the first "is this project healthy?" impression an OSS contributor gets. | Fix alongside OSS-02 (a `conftest`/CI stderr filter or upstream pin re-evaluation, owned by the 01-04 dependency decision). |
| C8 | **README claims will face outside scrutiny at launch** (e.g. trust is still a static seed score until Phase 7 TRST-03 — "dynamic trust score" phrasing oversells slightly; "makes safety regressions fail CI" is true today only for the D-04 egress lock until TEST-01–06 land). | Do a claims-vs-shipped pass over README.md as part of OSS-02, same discipline as the manifesto's honest-positioning section. |

## D — What was checked and found sound (no action)

- **Dependency spine:** hash chain → Merkle DAG → ZK; approval → 2-of-3 consensus → BFT;
  discovery → live graph → conflict reasoning; ABOM → supply-chain checks. No inversions; no
  phase consumes an artifact a later phase produces.
- **Traceability:** 123/123 REQs map to exactly one phase; no orphans; phase REQ lists match
  the traceability table (verified for all 14 phases).
- **P0-killer invariants** are not just documented but enforced in code/CI: advisory-only
  interpreter with restrict-only clamp (430-case `floor_invariant` sweep), fail-closed
  redaction + secret last gate, no-silent-allow, latency benchmark, coverage registry +
  bypass detection, deny-by-default Rego. This is the strongest part of the whole plan.
- **ADR-0007 fence** (no crypto-economics in core) is consistently applied everywhere it
  could leak (TRST-05, Phase 14, RFC-3161 chosen explicitly as "a notary, not a chain").
- **Honesty discipline** (kill-switch scope, anchoring threat model, xfail'd detector
  evasions, "behind today" lists) is genuinely unusual and worth preserving as a norm.
- **Two-roadmap split** (design 20-roadmap vs execution ROADMAP) is clearly cross-referenced
  in both directions; not a duplication hazard.
- **v2 fence** (HIPAA/FedRAMP/ISO-42001, Cedar, DID) appropriately parked.

## Changes applied by this audit (for the record)

1. `.planning/REQUIREMENTS.md` — 36 checkboxes + 36 traceability rows → Complete; OSS-01/02
   added (Phase 6); coverage 121→123; changelog updated.
2. `.planning/ROADMAP.md` — Phase 6 REQ list + success criterion 5 + sequencing note (EU AI
   Act, AGT re-verify, pin re-check); Phases 3–5 "Plans: TBD" → completion pointers; Phase 4
   NVIDIA scope addition recorded; SDK-05 pip-install caveat noted.
3. `.planning/PROJECT.md` — Validated section populated; 15 Active bullets checked; SDK
   bullet annotated (SDK-03 outstanding); ADR outcomes validated; Context corrected; OSS
   decision logged; changelog updated.
4. `.planning/STATE.md` — three new Blockers (EU AI Act clock, AGT re-verify overdue, OSS
   gap); frontmatter updated to this audit.
5. `CLAUDE.md` — "no code yet" corrected.
6. `docs/architecture/README.md` — footer corrected to Phases 1–5.
7. `docs/architecture/00-manifesto.md` + `30-comparison-agt.md` — honest-positioning sections
   updated to the 2026-07-03 shipped state with explicit as-of dating (AGT facts left labeled
   2026-06-10 pending re-verification).

---
*Audited 2026-07-05. Next audit: at P0 close (Phase 6 verification), and thereafter at each
design-phase boundary (P0→P1, P1→P2).*
