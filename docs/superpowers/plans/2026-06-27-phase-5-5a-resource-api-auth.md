# Phase 5 · Slice 5a — Declarative Resource API + Versioning + Auth Gate (API-01) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) green at every commit.

**Goal (API-01):** Stand up the declarative-resource layer of the control-plane API — validated,
versioned, persisted resources — behind a shared-token auth gate, proving the pattern on two mutable
resources (`TrustProfile`, `ABOM`). Constitution/Policy (compile-on-write) land in Slice 5b on the
same foundation.

**Architecture:** A sync `ResourceStore` over the existing `session_factory` does optimistic-version
CRUD on dialect-agnostic SQLAlchemy models (SQLite now, Postgres target — D-14). A FastAPI
`build_resource_router` exposes them; a `require_token` dependency gates this router **and** the
existing approval/kill routers. `create_app` resolves the shared token (explicit arg →
`AGENTOS_API_TOKEN` → ephemeral-with-warning) and wires everything.

**Tech Stack:** FastAPI + Pydantic v2, SQLAlchemy 2.0 (sync), Alembic, pytest + `fastapi.testclient`.

> First commit in this slice: `docs(phase-5): Slice 5a plan` for this file, then the tasks below.

## File structure
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — add `TrustProfile`,
  `Abom` models.
- Create `packages/controlplane/src/agentos_controlplane/store/migrations/versions/0006_resources.py`
  — create both tables (down_revision `0005_kill_switch`).
- Create `packages/controlplane/src/agentos_controlplane/resources.py` — `ResourceStore`,
  `VersionConflict`.
- Create `packages/controlplane/src/agentos_controlplane/auth.py` — `resolve_api_token`,
  `make_require_token`.
- Modify `packages/controlplane/src/agentos_controlplane/api.py` — `build_resource_router` + extend
  `create_app` (auth gate on all routers; new `resource_store` / `api_token` params).
- Modify `packages/controlplane/pyproject.toml` — add `fastapi`, `uvicorn` runtime deps.
- Tests: `tests/unit/test_resources_store.py`, `tests/unit/test_auth.py`,
  `tests/integration/test_resource_api.py`; UPDATE `tests/integration/test_kill_switch_api.py`,
  `tests/unit/test_resolve_api.py`, `tests/integration/test_approval_e2e.py` (and any other
  `create_app` caller) to send the token.

---

### Task 1: models + migration

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/store/models.py`
- Create: `packages/controlplane/src/agentos_controlplane/store/migrations/versions/0006_resources.py`
- Test: `tests/unit/test_resources_store.py` (model round-trip portion)

Add to `models.py` (the `Boolean`, `Float`, `Integer`, `JSON`, `String`, `Text`, `Uuid`, `DateTime`,
`func` imports already exist except `Integer` — add `Integer` to the sqlalchemy import):

```python
class TrustProfile(Base):
    """Declarative TrustProfile resource (API-01). The current trust posture for an agent,
    versioned for optimistic concurrency. `band` is an optional graduated-response band config.
    Keyed by agent_id (one current profile per agent); the Agent row keeps the seed trust_score."""
    __tablename__ = "trust_profile"
    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    band: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class Abom(Base):
    """Declarative Agent Bill of Materials resource (API-01 / ABOM-01 seed). Phase 5 only
    validates/versions/stores it; provenance + vuln-impact analysis are Phase 8/14. Keyed by
    agent_id (current ABOM per agent), version-incremented for optimistic concurrency."""
    __tablename__ = "abom"
    agent_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    components: Mapped[dict] = mapped_column(JSON, nullable=False)  # {models,prompts,tools,mcp:[...]}
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

Migration `0006_resources.py` (mirror `0005_kill_switch.py`'s structure; `down_revision =
"0005_kill_switch"`; `revision = "0006_resources"`):

```python
def upgrade() -> None:
    op.create_table(
        "trust_profile",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("trust_score", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("band", sa.JSON(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "abom",
        sa.Column("agent_id", sa.String(length=255), primary_key=True),
        sa.Column("components", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("abom")
    op.drop_table("trust_profile")
```

**Steps:**
- [ ] Write a failing test in `test_resources_store.py` that creates an in-memory store
  (`create_engine("sqlite+pysqlite:///:memory:")` → `create_all` → `create_session_factory`),
  inserts a `TrustProfile(agent_id="a", trust_score=0.7)` and an `Abom(agent_id="a",
  components={"tools": ["http_get"]})`, commits, and asserts they read back. Run → fails (models
  don't exist).
- [ ] Add the two models + the `Integer` import. Run → passes.
- [ ] Add migration `0006_resources.py`. Verify single head:
  `./.venv/Scripts/python.exe -c "from alembic.config import Config; from alembic.script import ScriptDirectory; import agentos_controlplane.store as s, os; d=os.path.dirname(s.__file__); c=Config(); c.set_main_option('script_location', os.path.join(d,'migrations')); print(ScriptDirectory.from_config(c).get_heads())"`
  Expected: `('0006_resources',)`.
- [ ] Commit `feat(controlplane): TrustProfile + Abom resource models + migration 0006 (API-01)`.

---

### Task 2: `ResourceStore` with optimistic versioning

**Files:**
- Create: `packages/controlplane/src/agentos_controlplane/resources.py`
- Test: `tests/unit/test_resources_store.py`

```python
"""API-01 — declarative resource persistence with optimistic versioning.

Sync store over the shared session_factory (D-14 SQLite now, Postgres target). Each mutable
resource is keyed by agent_id and carries a monotonic `version`; an update supplying a stale
(or missing) version raises VersionConflict -> the API maps it to 409. A create supplies no
version (or 0/1) and starts at version 1.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.store.models import Abom, TrustProfile


class VersionConflict(Exception):
    """Optimistic-concurrency failure: the supplied version != the current row version."""


@dataclass(frozen=True)
class TrustProfileData:
    agent_id: str
    trust_score: float
    band: dict | None
    version: int
    updated_at: str | None


@dataclass(frozen=True)
class AbomData:
    agent_id: str
    components: dict
    version: int
    created_at: str | None


class ResourceStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    # ---- TrustProfile ----
    def put_trust_profile(
        self, agent_id: str, *, trust_score: float, band: dict | None, expected_version: int | None
    ) -> TrustProfileData:
        with self._sf() as s:
            row = s.get(TrustProfile, agent_id)
            if row is None:
                row = TrustProfile(agent_id=agent_id, trust_score=trust_score, band=band, version=1)
                s.add(row)
            else:
                if expected_version != row.version:
                    raise VersionConflict(
                        f"trust_profile {agent_id}: expected version {row.version}, got {expected_version}"
                    )
                row.trust_score, row.band, row.version = trust_score, band, row.version + 1
            s.commit()
            return self._tp(row)

    def get_trust_profile(self, agent_id: str) -> TrustProfileData | None:
        with self._sf() as s:
            row = s.get(TrustProfile, agent_id)
            return self._tp(row) if row else None

    def list_trust_profiles(self) -> list[TrustProfileData]:
        with self._sf() as s:
            return [self._tp(r) for r in s.scalars(select(TrustProfile).order_by(TrustProfile.agent_id)).all()]

    # ---- Abom ----
    def put_abom(
        self, agent_id: str, *, components: dict, expected_version: int | None
    ) -> AbomData:
        with self._sf() as s:
            row = s.get(Abom, agent_id)
            if row is None:
                row = Abom(agent_id=agent_id, components=components, version=1)
                s.add(row)
            else:
                if expected_version != row.version:
                    raise VersionConflict(
                        f"abom {agent_id}: expected version {row.version}, got {expected_version}"
                    )
                row.components, row.version = components, row.version + 1
            s.commit()
            return self._abom(row)

    def get_abom(self, agent_id: str) -> AbomData | None:
        with self._sf() as s:
            row = s.get(Abom, agent_id)
            return self._abom(row) if row else None

    def list_aboms(self) -> list[AbomData]:
        with self._sf() as s:
            return [self._abom(r) for r in s.scalars(select(Abom).order_by(Abom.agent_id)).all()]

    @staticmethod
    def _tp(r: TrustProfile) -> TrustProfileData:
        return TrustProfileData(r.agent_id, r.trust_score, r.band, r.version,
                                r.updated_at.isoformat() if r.updated_at else None)

    @staticmethod
    def _abom(r: Abom) -> AbomData:
        return AbomData(r.agent_id, r.components, r.version,
                        r.created_at.isoformat() if r.created_at else None)
```

**Steps (TDD):**
- [ ] Test: create a TrustProfile (expected_version=None) → version 1; `get` returns it; update with
  `expected_version=1` → version 2; update with stale `expected_version=1` → raises `VersionConflict`;
  `list` returns sorted. Same matrix for `put_abom`. Run → fails (module missing).
- [ ] Implement `resources.py`. Run → passes.
- [ ] Commit `feat(controlplane): ResourceStore — optimistic-versioned TrustProfile/Abom CRUD (API-01)`.

---

### Task 3: shared-token auth dependency

**Files:**
- Create: `packages/controlplane/src/agentos_controlplane/auth.py`
- Test: `tests/unit/test_auth.py`

```python
"""Phase-5 shared-token API auth (P0). A single shared secret gates every control-plane route via
`Authorization: Bearer <token>`. Token resolution order: explicit arg -> AGENTOS_API_TOKEN env ->
an ephemeral random token (logged loudly; never silently wide-open). Per-principal authn/RBAC is a
later phase (documented limitation)."""
from __future__ import annotations

import logging
import os
import secrets

from fastapi import Header, HTTPException

log = logging.getLogger("agentos_controlplane.auth")


def resolve_api_token(explicit: str | None = None) -> str:
    token = explicit or os.environ.get("AGENTOS_API_TOKEN")
    if not token:
        token = secrets.token_urlsafe(32)
        log.warning(
            "AGENTOS_API_TOKEN not set and no token passed to create_app — generated an EPHEMERAL "
            "API token for this process. Set AGENTOS_API_TOKEN for a stable shared secret."
        )
    return token


def make_require_token(token: str):
    """Build a FastAPI dependency that enforces `Authorization: Bearer <token>`."""
    expected = f"Bearer {token}"

    def require_token(authorization: str | None = Header(default=None)) -> None:
        # constant-time compare; reject missing/short/incorrect uniformly as 401.
        if authorization is None or not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="invalid or missing API token")

    return require_token
```

**Steps (TDD):**
- [ ] Test (build a tiny FastAPI app with one route guarded by `Depends(make_require_token("t"))`,
  `TestClient`): no header → 401; `Authorization: Bearer wrong` → 401; `Bearer t` → 200. Plus
  `resolve_api_token("x") == "x"`; with env set returns env; with neither, returns a non-empty
  string (ephemeral). Run → fails.
- [ ] Implement `auth.py`. Run → passes.
- [ ] Commit `feat(controlplane): shared-token API auth dependency (Phase-5 P0)`.

---

### Task 4: resource router + create_app wiring + auth retrofit

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/api.py`
- Modify: `packages/controlplane/pyproject.toml` (add `fastapi`, `uvicorn`)
- Test: `tests/integration/test_resource_api.py`
- Update: `tests/integration/test_kill_switch_api.py`, `tests/unit/test_resolve_api.py`,
  `tests/integration/test_approval_e2e.py` (+ any other `create_app` caller — grep first)

Add Pydantic schemas + router to `api.py`:

```python
from fastapi import Depends
from agentos_controlplane.auth import make_require_token, resolve_api_token
from agentos_controlplane.resources import ResourceStore, VersionConflict


class TrustProfileIn(BaseModel):
    model_config = {"extra": "forbid"}
    trust_score: float = Field(ge=0.0, le=1.0)
    band: dict | None = None
    version: int | None = None  # required (== current) to update; omit/None to create


class AbomIn(BaseModel):
    model_config = {"extra": "forbid"}
    components: dict
    version: int | None = None


def build_resource_router(resources: ResourceStore) -> APIRouter:
    router = APIRouter()

    @router.get("/trust-profiles")
    def list_tp() -> list[dict]:
        return [vars(d) for d in resources.list_trust_profiles()]

    @router.get("/trust-profiles/{agent_id}")
    def get_tp(agent_id: str) -> dict:
        d = resources.get_trust_profile(agent_id)
        if d is None:
            raise HTTPException(status_code=404, detail="unknown trust_profile")
        return vars(d)

    @router.put("/trust-profiles/{agent_id}")
    def put_tp(agent_id: str, body: TrustProfileIn) -> dict:
        try:
            d = resources.put_trust_profile(
                agent_id, trust_score=body.trust_score, band=body.band,
                expected_version=body.version,
            )
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return vars(d)

    @router.get("/aboms")
    def list_abom() -> list[dict]:
        return [vars(d) for d in resources.list_aboms()]

    @router.get("/aboms/{agent_id}")
    def get_abom(agent_id: str) -> dict:
        d = resources.get_abom(agent_id)
        if d is None:
            raise HTTPException(status_code=404, detail="unknown abom")
        return vars(d)

    @router.put("/aboms/{agent_id}")
    def put_abom(agent_id: str, body: AbomIn) -> dict:
        try:
            d = resources.put_abom(agent_id, components=body.components, expected_version=body.version)
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return vars(d)

    return router
```

Extend `create_app` (keep existing positional callers working; gate ALL routers):

```python
def create_app(
    store: ApprovalStore,
    kill_store: KillSwitchStore | None = None,
    resource_store: ResourceStore | None = None,
    api_token: str | None = None,
) -> FastAPI:
    token = resolve_api_token(api_token)
    guard = [Depends(make_require_token(token))]
    app = FastAPI(title="agentos-guard control plane", version="0.1.0")
    app.state.api_token = token
    app.include_router(build_router(store), dependencies=guard)
    if kill_store is not None:
        app.include_router(build_kill_router(kill_store), dependencies=guard)
    if resource_store is not None:
        app.include_router(build_resource_router(resource_store), dependencies=guard)
    return app
```

`pyproject.toml` controlplane deps gain: `"fastapi>=0.115"`, `"uvicorn>=0.30"`.

**Steps (TDD):**
- [ ] `test_resource_api.py`: build app with `create_app(ApprovalStore(sf, AuditWriter(sf)),
  resource_store=ResourceStore(sf), api_token="test-token")`; a `TestClient` with
  `client.headers["Authorization"] = "Bearer test-token"`. Assert: PUT `/trust-profiles/a`
  `{"trust_score":0.7}` → 200 version 1; PUT again `{"trust_score":0.8,"version":1}` → 200 version 2;
  PUT `{"trust_score":0.8,"version":1}` again → 409; GET `/trust-profiles/a` → 200; GET
  `/trust-profiles/missing` → 404; PUT `{"trust_score":2.0}` → 422 (bounds). Same happy/conflict for
  `/aboms/{id}`. A request with NO auth header → 401 on a resource route AND on `/approvals`. Run →
  fails.
- [ ] Implement schemas + `build_resource_router` + `create_app` changes + pyproject deps. Run →
  passes.
- [ ] Update existing `create_app` callers: grep `git grep -l "create_app(" tests/` and for each
  TestClient, pass `api_token="test-token"` and set `client.headers["Authorization"] = "Bearer
  test-token"` (the kill-switch `Wired`, the resolve-api tests, approval-e2e). Run the FULL suite →
  green.
- [ ] Commit `feat(controlplane): resource API router + auth gate on all routers (API-01)`.

---

### Task 5: full gate
- [ ] `./.venv/Scripts/python.exe -m pytest -q` green; `-m floor_invariant` 430; `-m regression_lock`
  10; `-m latency` healthy (the resource API + auth are OFF the per-action hot path).
- [ ] Commit only if incidental fixes were needed.

## Self-review
API-01 (validate + version + store) proven on TrustProfile + Abom with optimistic-concurrency 409,
Pydantic validation 422, 404 on missing; the shared-token gate (Task 3) enforces `Authorization:
Bearer` on the resource router AND the retrofitted approval/kill routers (401), with token resolution
explicit→env→ephemeral-warn (never silently open); migration 0006 single-head; backward-compatible
`create_app(store)` / `create_app(store, kill_store=...)` still construct (now token-gated, existing
tests updated). Constitution/Policy compile-on-write is Slice 5b on this same foundation. Gates green;
hot path untouched.
