# Phase 10 · Slice 10e — Rogue-Agent Detection (DISC-05) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and marginal on this box —
> re-run when idle and compare against a scratch worktree at `886ad59` before claiming a regression.
> NEVER loosen the budget.)

**Goal (DISC-05):** Flag a **registered** agent whose behaviour diverges from its **declared scope** —
it uses a tool, memory or MCP server it never declared. Shadow detection (10d) answers "who is not
registered"; this answers "who is registered but is not doing what they said".

**Architecture:** Phase 5's `InventoryStore` already distinguishes `source="declared"` (the
registration manifest, authoritative) from `source="observed"` (what actually happened). Divergence is
therefore already latent in the data: **a component observed for an agent that the agent never
declared**. A `RogueDetector` performs that comparison as a batch sweep, records each divergence in a
`rogue_finding` table, audits `rogue_agent_detected` once per finding, and exposes a read route.

**Advisory by design.** This does NOT add a deny path. A declaration gap is evidence, not proof of
compromise — a manifest can simply be stale — so the control plane surfaces it and an operator decides,
escalating with Phase-9 containment (kill switch, breaker, rings) if warranted. Turning a stale
manifest into an automatic fleet-wide deny would make the feature unusable in practice.

**An agent that declared NOTHING is not automatically rogue.** Phase 5 made the manifest optional, so
"no declarations" means "scope unknown", not "scope empty" — flagging every such agent for every action
would bury the real signal. Only an agent that declared *something* is held to its declaration; this is
an explicit, documented rule with a test.

**Tech Stack:** SQLAlchemy 2.0 + Alembic, FastAPI, pytest.

> First commit in this slice: `docs(phase-10): Slice 10e plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — `RogueFinding`.
- Create `.../store/migrations/versions/0019_rogue_finding.py` (down_revision `0018_shadow_agent`).
- Modify `.../audit.py` — `EVENT_KINDS += "rogue_agent_detected"`.
- Create `.../agentos_controlplane/rogue.py` — `RogueDetector`.
- Modify `.../api.py` — a read route.
- Tests: `tests/unit/test_rogue_agents.py`, `tests/integration/test_rogue_agents_api.py`.

---

### Task 1: model + migration 0019 + event kind

**Files:** modify `.../store/models.py`, `.../audit.py`; create the migration; test
`tests/unit/test_rogue_agents.py` (round-trip portion).

```python
class RogueFinding(Base):
    """DISC-05 — a registered agent used a component it never declared.

    Advisory evidence, not a verdict: the manifest may simply be stale. `resolved` lets an operator
    acknowledge a finding without deleting the history the audit chain already carries.
    """

    __tablename__ = "rogue_finding"
    __table_args__ = (UniqueConstraint("agent_id", "kind", "name", name="uq_rogue_finding"),)

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)   # tool | memory | mcp | model | ...
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

`audit.py`:
```python
        # DISC-05 (Slice 10e): a registered agent used a component it never declared. Short
        # identifiers only; ADVISORY — the control plane surfaces it, an operator decides.
        "rogue_agent_detected",
```

Migration `0019_rogue_finding.py` (`revision = "0019_rogue_finding"`,
`down_revision = "0018_shadow_agent"`): create `rogue_finding` with those columns plus the named
unique constraint `sa.UniqueConstraint("agent_id", "kind", "name", name="uq_rogue_finding")`;
`downgrade` drops it.

**Steps:**
- [ ] Failing test: in-memory store; insert a `RogueFinding(agent_id="a", kind="tool",
  name="db_drop")`, read it back with `resolved is False`; a duplicate `(agent_id, kind, name)`
  raises `IntegrityError`; assert `append_event("rogue_agent_detected", {...})` is accepted and an
  unknown kind still raises. Run → fails.
- [ ] Add model + event kind + migration. Run → passes; verify a SINGLE head (`['0019_rogue_finding']`).
- [ ] Commit `feat(controlplane): rogue_finding table + event kind + migration 0019 (DISC-05)`.

---

### Task 2: `RogueDetector` — declared vs observed

**Files:** create `.../agentos_controlplane/rogue.py`; test `tests/unit/test_rogue_agents.py`.

Read `packages/controlplane/src/agentos_controlplane/inventory.py` first: `list_inventory()` returns
`ComponentData(agent_id, kind, name, source, first_seen_at, last_seen_at)` where `source` is
`"declared"` or `"observed"`, and the `(agent_id, kind, name)` key is unique — a component that was
declared AND later observed stays `source="declared"` (declared wins in `_upsert`). That is what makes
this comparison sound: anything still marked `observed` was never declared.

```python
"""DISC-05 — rogue-agent detection: a REGISTERED agent acting outside its DECLARED scope.

Phase 5 already stores the two halves this needs — `source="declared"` (the registration manifest,
authoritative) and `source="observed"` (what actually happened) — and `InventoryStore._upsert` keeps a
declared component marked declared even after it is observed. So a row still marked `observed` is
precisely a component the agent never declared: the divergence, already latent in the data.

ADVISORY by design: this adds no deny path. A declaration gap is evidence, not proof — a manifest goes
stale — so findings are surfaced for an operator, who escalates with Phase-9 containment if warranted.

An agent that declared NOTHING is NOT flagged: Phase 5 made the manifest optional, so no declarations
means "scope unknown", not "scope empty". Flagging those would bury the real signal under every
unmanifested agent in the fleet.
"""
from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import select

from agentos_controlplane.store.models import RogueFinding


@dataclass(frozen=True)
class Divergence:
    agent_id: str
    kind: str
    name: str


class RogueDetector:
    def __init__(self, session_factory, audit, inventory) -> None:
        self._sf = session_factory
        self._audit = audit
        self._inventory = inventory

    def divergences(self) -> list[Divergence]:
        """Pure comparison: components observed for an agent that DECLARED something but never
        declared this. No DB writes, no audit — so it is safe to call for a dry run."""
        components = self._inventory.list_inventory()
        declarers = {c.agent_id for c in components if c.source == "declared"}
        return sorted(
            (
                Divergence(agent_id=c.agent_id, kind=c.kind, name=c.name)
                for c in components
                if c.source == "observed" and c.agent_id in declarers
            ),
            key=lambda d: (d.agent_id, d.kind, d.name),
        )

    async def scan(self) -> list[Divergence]:
        """Persist + audit every NEW divergence. Idempotent: a repeat scan of an unchanged fleet
        writes nothing and appends no events, so a scheduled sweep cannot bloat the hash chain."""
        found = self.divergences()
        fresh: list[Divergence] = []
        with self._sf() as s:
            for d in found:
                existing = s.scalar(
                    select(RogueFinding).where(
                        RogueFinding.agent_id == d.agent_id,
                        RogueFinding.kind == d.kind,
                        RogueFinding.name == d.name,
                    )
                )
                if existing is None:
                    s.add(
                        RogueFinding(
                            id=uuid4(), agent_id=d.agent_id, kind=d.kind, name=d.name
                        )
                    )
                    fresh.append(d)
            s.commit()
        for d in fresh:
            await self._audit.append_event(
                "rogue_agent_detected",
                {"agent_id": d.agent_id, "kind": d.kind, "name": d.name},
            )
        return fresh

    def list_findings(self, *, include_resolved: bool = False) -> list[dict]:
        with self._sf() as s:
            stmt = select(RogueFinding).order_by(RogueFinding.first_seen_at.desc())
            if not include_resolved:
                stmt = stmt.where(RogueFinding.resolved.is_(False))
            return [
                {
                    "id": str(r.id),
                    "agent_id": r.agent_id,
                    "kind": r.kind,
                    "name": r.name,
                    "resolved": r.resolved,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                }
                for r in s.scalars(stmt).all()
            ]

    async def resolve(self, finding_id: str, *, set_by: str) -> bool:
        """Operator acknowledgement. The audit chain keeps the original sighting either way."""
        with self._sf() as s:
            row = s.get(RogueFinding, finding_id)
            if row is None:
                return False
            row.resolved = True
            s.commit()
        return True
```

**Steps (TDD):**
- [ ] Failing tests over a shared in-memory store (`InventoryStore` + real `AuditWriter`):
  - an agent that declared `tools=["http_get"]` and is then observed using `http_get` → NO
    divergence (declared wins in the inventory upsert, so this must not false-positive);
  - the same agent observed using `db_drop` (never declared) → ONE divergence, one `rogue_finding`
    row, one `rogue_agent_detected` event;
  - **an agent that declared NOTHING and is observed using a tool → NO finding** (the documented
    rule: unknown scope is not rogue) — assert explicitly, since it is the judgement call most
    likely to be "fixed" by a future reader;
  - a repeat `scan()` on an unchanged fleet → returns `[]`, adds no row, appends NO event
    (idempotent, so a scheduled sweep cannot bloat the chain);
  - a NEW divergence after the first scan → exactly one further event;
  - `divergences()` is pure — call it twice and assert no rows and no events were created;
  - `resolve()` on a real id → True and the finding leaves the default list but is still returned by
    `list_findings(include_resolved=True)`; `resolve()` on an unknown id → False;
  - `verify_chain(sf).ok` holds and no event body carries anything beyond the three short fields.
  Run → fails.
- [ ] Implement `rogue.py`. Run → passes.
- [ ] Commit `feat(controlplane): RogueDetector — declared-vs-observed divergence, advisory (DISC-05)`.

---

### Task 3: read API + e2e + full gate

**Files:** modify `.../api.py`; test `tests/integration/test_rogue_agents_api.py`.

Extend `build_inventory_router` with `rogue: "RogueDetector | None" = None` (thread `rogue_detector`
through `create_app`, defaulting to `None`) and add:

```python
    @router.get("/discovery/rogue-agents")
    def list_rogue_findings(include_resolved: bool = False) -> list[dict]:
        """DISC-05 — registered agents observed outside their declared scope (advisory)."""
        if rogue is None:
            raise HTTPException(status_code=404, detail="rogue detection is not wired")
        return rogue.list_findings(include_resolved=include_resolved)
```

**Steps (TDD):**
- [ ] Failing e2e over the REAL stack sharing ONE store: register an agent with a manifest
  (`Registry(sf, inventory=InventoryStore(sf)).register(AGENT_ID, manifest={"tools": ["http_get"]})`),
  run a real governed action against a DIFFERENT tool so the inventory observes it (or call
  `InventoryStore.observe` directly, mirroring how `test_inventory_api.py` seeds observations), then
  `await detector.scan()`. Assert:
  - `GET /discovery/rogue-agents` → 200 listing the undeclared component;
  - the declared component is NOT listed;
  - `?include_resolved=true` after `resolve()` shows it again while the default list does not;
  - no token → 401; app built without a detector → 404;
  - `verify_chain` still ok.
- [ ] Run → fails, then passes.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency`
  (baseline-check before attributing a wall-clock failure — detection is a batch sweep, entirely off
  the per-action hot path).
- [ ] Commit `feat(controlplane): rogue-agent read API + e2e (DISC-05)`.

## Self-review
DISC-05 is realized by comparing the two halves Phase 5 already stores rather than inventing a second
source of truth: a component still marked `observed` is exactly one the agent never declared. The two
judgement calls are explicit, documented and tested — detection is ADVISORY (no deny path; a stale
manifest must not become an automatic outage) and an agent that declared nothing is NOT rogue (unknown
scope is not empty scope). Scans are idempotent so a scheduled sweep cannot bloat the hash chain,
`divergences()` is pure so a dry run is free, and operator acknowledgement is recorded without
destroying history. Migration 0019 single-head; the API parameter defaults to `None` so existing
callers are unchanged; nothing touches the per-action hot path.
