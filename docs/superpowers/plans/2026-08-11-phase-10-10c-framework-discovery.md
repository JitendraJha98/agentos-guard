# Phase 10 · Slice 10c — Framework Discovery (DISC-03) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. (`-m latency` is wall-clock and marginal on this box —
> re-run when idle and compare against a scratch worktree at `886ad59` before claiming a regression.
> NEVER loosen the budget.)

**Goal (DISC-03):** Detect which agent frameworks are actually present — LangChain/LangGraph, CrewAI,
AutoGen, the OpenAI Agents SDK, MCP — record them with their versions, and expose them for reading.
You cannot govern what you cannot see.

**Architecture:** A `FrameworkDetector` enumerates a fixed catalogue of known frameworks and resolves
each against the **installed distributions** (`importlib.metadata`) rather than guessing. Findings are
upserted into a `discovered_framework` table (in-memory cache is unnecessary — this is a scan, not a
hot path) and each newly-observed framework is audited as `framework_discovered` with short
identifiers only. A read route on the existing gated API exposes the inventory. Detection is evidence
based: a framework is reported present **iff** its distribution is genuinely importable/installed.

**Tech Stack:** stdlib `importlib.metadata` + `importlib.util`, SQLAlchemy 2.0 + Alembic, FastAPI,
pytest.

> First commit in this slice: `docs(phase-10): Slice 10c plan` for this file, then the tasks below.

## File structure
- Modify `.../store/models.py` — `DiscoveredFramework`.
- Create `.../store/migrations/versions/0017_discovered_framework.py` (down_revision `0016_consensus`).
- Modify `.../audit.py` — `EVENT_KINDS += "framework_discovered"`.
- Create `.../agentos_controlplane/framework_discovery.py` — catalogue + `FrameworkDetector`.
- Modify `.../api.py` — a read route on the inventory router.
- Tests: `tests/unit/test_framework_discovery.py`, `tests/integration/test_framework_discovery_api.py`.

---

### Task 1: model + migration 0017 + event kind

**Files:** modify `.../store/models.py`, `.../audit.py`; create the migration; test
`tests/unit/test_framework_discovery.py` (round-trip portion).

```python
class DiscoveredFramework(Base):
    """DISC-03 — an agent framework observed in this deployment.

    `name` is the catalogue key (stable), `distribution` the PyPI name actually found, and `version`
    what was installed at detection time. Keyed by name: the CURRENT observation per framework, with
    first/last-seen bracketing it; the audit chain carries the immutable history.
    """

    __tablename__ = "discovered_framework"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    distribution: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
```

`audit.py` — add in the file's comment style:
```python
        # DISC-03 (Slice 10c): a framework observed in this deployment. Short identifiers only.
        "framework_discovered",
```

Migration `0017_discovered_framework.py` (`revision = "0017_discovered_framework"`,
`down_revision = "0016_consensus"`): create `discovered_framework` with the columns above
(`sa.String(64)` pk, `sa.String(128)`, `sa.String(64)`, two `sa.DateTime(timezone=True)` with
`server_default=sa.func.now()`); `downgrade` drops it.

**Steps:**
- [ ] Failing test: in-memory store (`create_engine("sqlite+pysqlite:///:memory:")` → `create_all` →
  `create_session_factory`); insert `DiscoveredFramework(name="langchain", distribution="langchain",
  version="1.3.2")`, read it back; assert `append_event("framework_discovered", {...})` is accepted
  and an unknown kind still raises. Run → fails.
- [ ] Add model + event kind + migration. Run → passes; verify a SINGLE head
  (`['0017_discovered_framework']`) with the alembic heads one-liner used in earlier slices.
- [ ] Commit `feat(controlplane): discovered_framework table + event kind + migration 0017 (DISC-03)`.

---

### Task 2: `FrameworkDetector`

**Files:** create `.../agentos_controlplane/framework_discovery.py`; test
`tests/unit/test_framework_discovery.py`.

```python
"""DISC-03 — framework discovery. You cannot govern what you cannot see.

Detection is EVIDENCE-BASED: a framework counts as present only when its distribution is genuinely
installed, resolved through `importlib.metadata`. Guessing from a stray import name would put
frameworks in the operator's inventory that are not actually there, which is worse than silence — an
inventory is only useful if it is true.

This is a SCAN, not a hot path: findings go straight to the table (no in-memory cache) and the
detector is driven by an operator call or a reconciler pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata

from sqlalchemy import select

from agentos_controlplane.store.models import DiscoveredFramework

# name -> the candidate PyPI distributions that indicate it. Several names per framework because
# these projects have renamed/split (autogen -> autogen-agentchat/pyautogen; the OpenAI Agents SDK
# ships as `openai-agents` but imports as `agents`).
FRAMEWORK_CATALOGUE: dict[str, tuple[str, ...]] = {
    "langchain": ("langchain",),
    "langgraph": ("langgraph",),
    "crewai": ("crewai",),
    "autogen": ("autogen-agentchat", "pyautogen", "autogen"),
    "openai_agents": ("openai-agents",),
    "mcp": ("mcp",),
}


@dataclass(frozen=True)
class FrameworkFinding:
    name: str
    distribution: str
    version: str


def detect_frameworks(
    catalogue: dict[str, tuple[str, ...]] | None = None,
) -> list[FrameworkFinding]:
    """Resolve the catalogue against the INSTALLED distributions. Pure — no DB, no audit."""
    found: list[FrameworkFinding] = []
    for name, distributions in sorted((catalogue or FRAMEWORK_CATALOGUE).items()):
        for dist in distributions:
            try:
                version = metadata.version(dist)
            except metadata.PackageNotFoundError:
                continue
            found.append(FrameworkFinding(name=name, distribution=dist, version=version))
            break  # first match wins: the catalogue lists aliases, not separate installs
    return found


class FrameworkDetector:
    """Persists + audits what `detect_frameworks` finds."""

    def __init__(self, session_factory, audit, *, catalogue: dict[str, tuple[str, ...]] | None = None) -> None:
        self._sf = session_factory
        self._audit = audit
        self._catalogue = catalogue

    async def scan(self) -> list[FrameworkFinding]:
        """Detect, upsert, and audit each framework whose presence or version is NEW. Returns
        everything found (not only the new ones) so a caller can report the full picture."""
        findings = detect_frameworks(self._catalogue)
        newly: list[FrameworkFinding] = []
        with self._sf() as s:
            for f in findings:
                row = s.get(DiscoveredFramework, f.name)
                if row is None:
                    s.add(
                        DiscoveredFramework(
                            name=f.name, distribution=f.distribution, version=f.version
                        )
                    )
                    newly.append(f)
                elif row.version != f.version or row.distribution != f.distribution:
                    row.version, row.distribution = f.version, f.distribution
                    newly.append(f)
                else:
                    row.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
            s.commit()
        # Audit AFTER the commit, and only for genuine changes — a scan on a schedule must not
        # append an identical event on every pass and bloat the chain.
        for f in newly:
            await self._audit.append_event(
                "framework_discovered",
                {"framework": f.name, "distribution": f.distribution, "version": f.version},
            )
        return findings

    def list_frameworks(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(DiscoveredFramework).order_by(DiscoveredFramework.name)).all()
            return [
                {
                    "name": r.name,
                    "distribution": r.distribution,
                    "version": r.version,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                    "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                }
                for r in rows
            ]
```

**Steps (TDD):**
- [ ] Failing tests over a shared in-memory store + real `AuditWriter`:
  - `detect_frameworks()` on the REAL environment finds `langchain` and `langgraph` (both are hard
    dependencies of this repo, so this is a true positive that cannot be faked) with non-empty
    versions;
  - a catalogue naming a distribution that is definitely absent
    (`{"nope": ("agentos-definitely-not-installed",)}`) yields `[]` — **no false positives**, the
    property that makes the inventory trustworthy;
  - alias resolution: a catalogue `{"langchain": ("not-real-dist", "langchain")}` still resolves via
    the second candidate, and reports `distribution == "langchain"`;
  - `await scan()` writes one row per finding and one `framework_discovered` event per finding;
  - a SECOND `scan()` with the same environment adds NO new events (idempotent — a scheduled scan
    must not bloat the audit chain) but does advance `last_seen_at`;
  - a version CHANGE (inject via a stub catalogue + a pre-seeded row with a different version) emits
    a fresh event and updates the row;
  - `verify_chain(sf).ok` holds; no audit body carries anything but the three short fields.
  Run → fails.
- [ ] Implement `framework_discovery.py`. Run → passes.
- [ ] Commit `feat(controlplane): FrameworkDetector — evidence-based, idempotent scan (DISC-03)`.

---

### Task 3: read API + full gate

**Files:** modify `.../api.py`; test `tests/integration/test_framework_discovery_api.py`.

Add to `build_inventory_router` (it already takes the inventory store; add a second optional
collaborator rather than a new router, so the gated surface stays one place). Change its signature to
`build_inventory_router(inventory: InventoryStore, detector: "FrameworkDetector | None" = None)` and
add:

```python
    @router.get("/discovery/frameworks")
    def list_frameworks() -> list[dict]:
        """DISC-03 — the frameworks observed in this deployment."""
        if detector is None:
            raise HTTPException(status_code=404, detail="framework discovery is not wired")
        return detector.list_frameworks()
```

`create_app` gains `framework_detector: "FrameworkDetector | None" = None` and passes it through to
`build_inventory_router`. Keep every existing caller working (both parameters default to `None`).

**Steps (TDD):**
- [ ] Failing test: build the app with `inventory_store=InventoryStore(sf)` and
  `framework_detector=FrameworkDetector(sf, audit)`, a `TestClient` with the Bearer token (mirror
  `tests/integration/test_inventory_api.py`). Assert: `await detector.scan()` then
  `GET /discovery/frameworks` → 200 listing entries whose names include `langchain`; without a token
  → 401; with `create_app(...)` built WITHOUT a detector → 404 (backward compat, the inventory routes
  still work).
- [ ] Implement. Run → passes.
- [ ] `pytest -q` green; `-m floor_invariant`, `-m regression_lock` green; `-m latency` (baseline-check
  a wall-clock failure before attributing it). Discovery is off the per-action hot path entirely.
- [ ] Commit `feat(controlplane): framework-discovery read API (DISC-03)`.

## Self-review
DISC-03 is realized: the listed frameworks are detected from INSTALLED distributions rather than
guessed, so the inventory is true — asserted in both directions (a real positive on langchain/langgraph
which this repo genuinely depends on, and no false positive for an absent distribution). Findings are
persisted, exposed on the existing gated API, and audited with short identifiers only; a repeat scan is
idempotent so a scheduled pass cannot bloat the hash chain, while a version change is a fresh event.
Migration 0017 single-head; both new `create_app` parameters default to `None` so every existing caller
is unchanged; nothing touches the per-action hot path.
