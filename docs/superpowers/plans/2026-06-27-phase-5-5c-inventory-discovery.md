# Phase 5 · Slice 5c — Agent Inventory & Discovery (DISC-01, DISC-02) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) green at every commit.

**Goal (DISC-01/02):** An authoritative agent inventory that tracks agents and their tools / prompts
/ memories, populated two ways: a **declared** registration manifest (the authoritative baseline) and
**observed** activity reconciled in from the audit log. A read API exposes it.

**Architecture:** An `InventoryStore` over the shared `session_factory` does upsert CRUD on a single
`InventoryComponent` table, unique on `(agent_id, kind, name)`. `declare(...)` writes
`source="declared"` rows; `observe(agent_id, kind, name)` upserts an `source="observed"` row and
**reconciles** with a declared row of the same key (declared wins; `last_seen_at` always bumped).
`enrich_from_audit(...)` scans decision audit records and calls `observe(...)` per
`(agent_id, capability-class)`.

> **Honest scope (document this):** the audit-record body intentionally omits per-action `target`
> (it stores `agent_id` + `action_type` + a redacted payload only — see `audit.py`), so
> audit-derived observation is at the **capability-class** level (`tool`/`memory`/`mcp`/`model`/
> `delegation`, one row per agent per class). Precise per-tool observation (e.g. the exact
> `http_get` name) is wired in Slice 5d through the same `observe(agent_id, "tool", action.target)`
> seam, where the SDK still holds the full `AgentAction`. The `observe()` method itself is
> full-fidelity now; only the audit-mining shortcut is class-level.

**Tech Stack:** FastAPI + Pydantic v2, SQLAlchemy 2.0 (sync), pytest.

> First commit in this slice: `docs(phase-5): Slice 5c plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — add `InventoryComponent` (unique `(agent_id, kind, name)`).
- Create `.../store/migrations/versions/0008_inventory.py` (down_revision `0007_constitution_policy`).
- Create `.../inventory.py` — `InventoryStore`, `ComponentData`, `enrich_from_audit`.
- Modify `.../registry.py` — optional `inventory` dependency + `manifest` arg on `register`
  (backward compatible).
- Modify `.../api.py` — `build_inventory_router` (or add inventory routes) on the auth-gated app.
- Tests: `tests/unit/test_inventory_store.py`, `tests/integration/test_inventory_api.py`.

---

### Task 1: model + migration 0008

**Files:**
- Modify: `.../store/models.py`
- Create: `.../store/migrations/versions/0008_inventory.py`
- Test: `tests/unit/test_inventory_store.py` (round-trip portion)

Add to `models.py` (add `UniqueConstraint` to the sqlalchemy import):

```python
class InventoryComponent(Base):
    """DISC-01/02 — an authoritative inventory row: one component (a tool/prompt/memory/etc.) tied to
    an agent. `source` is 'declared' (registration manifest, authoritative) or 'observed' (reconciled
    from activity). Unique on (agent_id, kind, name) so declare+observe of the same component
    reconcile into ONE row."""
    __tablename__ = "inventory_component"
    __table_args__ = (UniqueConstraint("agent_id", "kind", "name", name="uq_inventory_component"),)
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)   # tool|prompt|memory|model|mcp|delegation
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)  # declared|observed
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

Migration `0008_inventory.py` (mirror prior migrations; `revision="0008_inventory"`,
`down_revision="0007_constitution_policy"`): create `inventory_component` with the columns above +
the named unique constraint (`sa.UniqueConstraint("agent_id","kind","name",
name="uq_inventory_component")`); downgrade drops it.

**Steps:**
- [ ] Failing test: insert two `InventoryComponent` rows, read back; assert inserting a duplicate
  `(agent_id, kind, name)` raises `IntegrityError`. Run → fails.
- [ ] Add model + `UniqueConstraint` import. Run → passes.
- [ ] Add migration 0008; verify single head `('0008_inventory',)`.
- [ ] Commit `feat(controlplane): InventoryComponent model + migration 0008 (DISC-01/02)`.

---

### Task 2: `InventoryStore` (declare / observe / read) + audit enrichment

**Files:**
- Create: `.../inventory.py`
- Test: `tests/unit/test_inventory_store.py`

```python
"""DISC-01/02 — authoritative agent inventory. Declared (registration manifest, authoritative) +
observed (reconciled from activity). Sync store over the shared session_factory (D-14)."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.store.models import AuditRecord, InventoryComponent

# action_type -> inventory capability class (audit body omits per-action target -> class-level).
_KIND_BY_ACTION = {
    "tool_call": "tool",
    "memory_access": "memory",
    "mcp_call": "mcp",
    "model_invocation": "model",
    "delegation": "delegation",
}


@dataclass(frozen=True)
class ComponentData:
    agent_id: str
    kind: str
    name: str
    source: str
    first_seen_at: str | None
    last_seen_at: str | None


class InventoryStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def declare(self, agent_id: str, *, tools=(), prompts=(), memories=()) -> None:
        """Upsert authoritative declared rows from a registration manifest (DISC-01)."""
        items = (
            [("tool", n) for n in tools]
            + [("prompt", n) for n in prompts]
            + [("memory", n) for n in memories]
        )
        with self._sf() as s:
            for kind, name in items:
                self._upsert(s, agent_id, kind, name, source="declared")
            s.commit()

    def observe(self, agent_id: str, kind: str, name: str) -> None:
        """Upsert an observed row; reconcile with a declared row of the same key (declared wins;
        last_seen_at always bumped)."""
        with self._sf() as s:
            self._upsert(s, agent_id, kind, name, source="observed")
            s.commit()

    def enrich_from_audit(self, audit_session_factory: sessionmaker[Session] | None = None) -> int:
        """Scan decision audit records and record observed capability-class activity per agent.
        Returns the number of (agent, class) observations applied. Class-level by design (the audit
        body omits target)."""
        sf = audit_session_factory or self._sf
        with sf() as s:
            rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq)).all()
            seen = []
            for r in rows:
                body = r.body
                if "kind" in body:  # event record, not a decision — skip
                    continue
                agent_id = body.get("agent_id")
                klass = _KIND_BY_ACTION.get(body.get("action_type"))
                if agent_id and klass:
                    seen.append((agent_id, klass))
        for agent_id, klass in seen:
            self.observe(agent_id, klass, klass)  # class-level name
        return len(seen)

    def list_inventory(self) -> list[ComponentData]:
        with self._sf() as s:
            rows = s.scalars(
                select(InventoryComponent).order_by(
                    InventoryComponent.agent_id, InventoryComponent.kind, InventoryComponent.name
                )
            ).all()
            return [self._cd(r) for r in rows]

    def get_inventory(self, agent_id: str) -> list[ComponentData]:
        with self._sf() as s:
            rows = s.scalars(
                select(InventoryComponent)
                .where(InventoryComponent.agent_id == agent_id)
                .order_by(InventoryComponent.kind, InventoryComponent.name)
            ).all()
            return [self._cd(r) for r in rows]

    @staticmethod
    def _upsert(s: Session, agent_id: str, kind: str, name: str, *, source: str) -> None:
        row = s.scalar(
            select(InventoryComponent).where(
                InventoryComponent.agent_id == agent_id,
                InventoryComponent.kind == kind,
                InventoryComponent.name == name,
            )
        )
        if row is None:
            s.add(InventoryComponent(agent_id=agent_id, kind=kind, name=name, source=source))
            return
        # declared is authoritative: never downgrade declared -> observed; always bump last_seen.
        if source == "declared":
            row.source = "declared"
        row.last_seen_at = func.now()

    @staticmethod
    def _cd(r: InventoryComponent) -> ComponentData:
        return ComponentData(
            r.agent_id, r.kind, r.name, r.source,
            r.first_seen_at.isoformat() if r.first_seen_at else None,
            r.last_seen_at.isoformat() if r.last_seen_at else None,
        )
```

**Steps (TDD):**
- [ ] Test: `declare("a", tools=["http_get"], prompts=["sys"], memories=["m1"])` → 3 declared rows;
  `observe("a","tool","http_get")` → STILL one tool row, `source=="declared"` (reconciled, not
  duplicated); `observe("a","tool","other")` → new observed row; `get_inventory("a")` /
  `list_inventory()` shapes + ordering. For `enrich_from_audit`: build a store, append a couple of
  decision audit records (use `AuditWriter` with `make_http_get`-style actions, or insert
  `AuditRecord` rows directly with bodies `{"seq":..,"agent_id":"a","action_type":"tool_call",...}`),
  then `enrich_from_audit()` → an observed `(a,"tool","tool")` row appears; an event record (body has
  `"kind"`) is skipped. Run → fails.
- [ ] Implement `inventory.py`. Run → passes.
- [ ] Commit `feat(controlplane): InventoryStore — declared manifest + observed reconciliation (DISC-02)`.

---

### Task 3: wire declared inventory into registration (DISC-01)

**Files:**
- Modify: `.../registry.py`
- Test: `tests/unit/test_inventory_store.py` (registration portion) — or a small `test_registry_manifest.py`

Make `Registry` optionally own an `InventoryStore` and accept a manifest on `register` (backward
compatible — existing `register(agent_id)` / `register(agent_id, trust_score)` unchanged):

```python
class Registry:
    def __init__(self, session_factory, identity=None, inventory=None) -> None:
        self._session_factory = session_factory
        self.identity = identity or IdentityEngine(
            is_registered=self.is_registered, load_trust=self.load_trust
        )
        self._inventory = inventory  # optional InventoryStore (DISC-01)

    def register(self, agent_id: str, trust_score: float = DEFAULT_TRUST_SCORE,
                 manifest: dict | None = None) -> str:
        # ... existing Agent upsert + token issue unchanged ...
        token = self.identity.issue_token(agent_id)
        if manifest is not None and self._inventory is not None:
            self._inventory.declare(
                agent_id,
                tools=manifest.get("tools", []),
                prompts=manifest.get("prompts", []),
                memories=manifest.get("memories", []),
            )
        return token
```

**Steps (TDD):**
- [ ] Test: `Registry(sf, inventory=InventoryStore(sf)).register("a", manifest={"tools":["http_get"],
  "memories":["m1"]})` → declared rows present via `InventoryStore(sf).list_inventory()`; AND
  `Registry(sf).register("b")` (no inventory, no manifest) still returns a valid token and writes no
  components (backward compat). Run → fails.
- [ ] Implement the `register` change. Run → passes (don't break existing registry tests).
- [ ] Commit `feat(controlplane): registration manifest -> declared inventory (DISC-01)`.

---

### Task 4: inventory read API

**Files:**
- Modify: `.../api.py`
- Test: `tests/integration/test_inventory_api.py`

Add an inventory router and wire it into `create_app` (gated like the others). Pass an optional
`inventory_store` to `create_app`:

```python
from agentos_controlplane.inventory import InventoryStore


def build_inventory_router(inventory: InventoryStore) -> APIRouter:
    router = APIRouter()

    @router.get("/inventory")
    def list_inventory() -> list[dict]:
        return [vars(d) for d in inventory.list_inventory()]

    @router.get("/inventory/{agent_id}")
    def get_inventory(agent_id: str) -> list[dict]:
        return [vars(d) for d in inventory.get_inventory(agent_id)]

    return router
```

`create_app(store, kill_store=None, resource_store=None, inventory_store=None, api_token=None)`:
include `build_inventory_router(inventory_store)` with `dependencies=guard` when provided (keep all
existing callers working).

**Steps (TDD):**
- [ ] Test: build app with `inventory_store=InventoryStore(sf)`, Bearer header; declare some rows;
  GET `/inventory` → 200 list; GET `/inventory/{agent_id}` → 200 filtered; no Bearer → 401;
  `create_app` without `inventory_store` → GET `/inventory` 404 (backward compat). Run → fails.
- [ ] Implement router + `create_app` change. Run → full suite green.
- [ ] Commit `feat(controlplane): agent-inventory read API (DISC-01/02)`.

---

### Task 5: full gate
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy
  (inventory is off the per-action hot path — declare/observe are operator/registration writes;
  enrich_from_audit is a batch sweep).
- [ ] Commit only if incidental fixes were needed.

## Self-review
DISC-01: agents declare a manifest at registration -> authoritative declared inventory rows; DISC-02:
the inventory tracks tools/prompts/memories (+ observed capability classes), reconciling declared and
observed into single rows via the `(agent_id, kind, name)` unique key (declared wins, last_seen
bumped). `enrich_from_audit` sweeps decision records into observed class-level rows (honest-scope
documented: audit body omits target; precise per-tool observation is the SDK's `observe()` in 5d).
Read API rides the auth-gated app (401 without token); migration 0008 single-head; Registry change is
backward compatible. Gates green; hot path untouched.
