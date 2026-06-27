# Phase 5 · Slice 5b — Compile-on-Write Constitution → Policy/Rego (API-02) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) green at every commit.

**Goal (API-02):** Applying a `Constitution` through the API **compiles it to Policy/Rego on write**
and atomically persists both the Constitution version and its derived Policy. A malformed
Constitution is rejected `422` with nothing written; the latest compiled Policy is retrievable for
the engine. Builds on the Slice-5a resource foundation (`ResourceStore`, auth gate).

**Architecture:** A new `apply_constitution(name, source)` on `ResourceStore` validates the authored
document with the Pydantic `Constitution` schema, runs the existing pure compiler
(`agentos_constitution.compile_constitution`), and inserts a `ConstitutionResource` + `PolicyResource`
row **in one transaction**. The compile produces Rego *text* + the reviewable YAML middle layer +
graduated/lists/sequences metadata — no OPA binary needed at write time (WASM build for the hot path
is separate, Phase-7 reconciliation). Apply is idempotent on the content-hash `constitution_version`.

**Tech Stack:** FastAPI + Pydantic v2, SQLAlchemy 2.0 (sync), `agentos_constitution` compiler, pytest.

> First commit in this slice: `docs(phase-5): Slice 5b plan` for this file, then the tasks below.

## File structure
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — add `ConstitutionResource`
  + `PolicyResource` (table names `constitution` / `policy`; class names avoid colliding with the
  Pydantic `Constitution`).
- Create `.../store/migrations/versions/0007_constitution_policy.py` (down_revision `0006_resources`).
- Modify `packages/controlplane/src/agentos_controlplane/resources.py` — `apply_constitution`,
  getters, `ConstitutionError`, `ConstitutionData` / `PolicyData`.
- Modify `packages/controlplane/src/agentos_controlplane/api.py` — `ConstitutionIn` schema + routes on
  the existing (already auth-gated) resource router.
- Tests: `tests/unit/test_constitution_resource_store.py`,
  `tests/integration/test_constitution_api.py`.

---

### Task 1: models + migration 0007

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/store/models.py`
- Create: `.../store/migrations/versions/0007_constitution_policy.py`
- Test: `tests/unit/test_constitution_resource_store.py` (model round-trip portion)

Add to `models.py` (`Uuid`/`uuid4`/`String`/`Text`/`JSON`/`DateTime`/`func` already imported):

```python
class ConstitutionResource(Base):
    """Declarative Constitution resource (API-01/02). One row per applied version; `version` is the
    content-hash constitution_version (idempotent apply). `source` is the authored document (JSON)."""
    __tablename__ = "constitution"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)  # constitution_version
    source: Mapped[dict] = mapped_column(JSON, nullable=False)  # the authored document, verbatim
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class PolicyResource(Base):
    """The compile-on-write output for a Constitution version (API-02). Stores the Rego + the
    reviewable YAML middle layer + graduated/lists/sequences metadata the engine consumes."""
    __tablename__ = "policy"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    constitution_version: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    yaml_policy: Mapped[str] = mapped_column(Text, nullable=False)
    rego: Mapped[str] = mapped_column(Text, nullable=False)
    graduated_config: Mapped[dict] = mapped_column(JSON, nullable=False)
    lists: Mapped[dict] = mapped_column(JSON, nullable=False)
    sequences: Mapped[list] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
```

Migration `0007_constitution_policy.py` (mirror `0006_resources.py`; `revision =
"0007_constitution_policy"`, `down_revision = "0006_resources"`): `op.create_table("constitution",
...)` and `op.create_table("policy", ...)` with the same columns (string/text/JSON; unique on
`version` / `constitution_version`); `downgrade` drops `policy` then `constitution`.

**Steps:**
- [ ] Failing test: in-memory store (`create_engine(":memory:")` → `create_all` →
  `create_session_factory`), insert a `ConstitutionResource(name="t", version="v1", source={"a":1})`
  and a `PolicyResource(constitution_version="v1", yaml_policy="y", rego="r", graduated_config={},
  lists={}, sequences=[])`, commit, read back. Run → fails.
- [ ] Add both models. Run → passes.
- [ ] Add migration 0007; verify single head == `('0007_constitution_policy',)` (same one-liner as
  the 5a plan's Task 1).
- [ ] Commit `feat(controlplane): Constitution + Policy resource models + migration 0007 (API-02)`.

---

### Task 2: `apply_constitution` — compile-on-write, atomic, idempotent

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/resources.py`
- Test: `tests/unit/test_constitution_resource_store.py`

Add to `resources.py`:

```python
from dataclasses import dataclass

from pydantic import ValidationError

from agentos_constitution import Constitution, compile_constitution
from agentos_controlplane.store.models import ConstitutionResource, PolicyResource


class ConstitutionError(Exception):
    """The authored Constitution failed validation or compilation — the API maps it to 422
    and NOTHING is persisted (fail-closed compile-on-write)."""


@dataclass(frozen=True)
class ConstitutionData:
    id: str
    name: str
    version: str
    source: dict
    created_at: str | None


@dataclass(frozen=True)
class PolicyData:
    constitution_version: str
    yaml_policy: str
    rego: str
    graduated_config: dict
    lists: dict
    sequences: list
    created_at: str | None
```

`ResourceStore` gains:

```python
    def apply_constitution(self, name: str, source: dict) -> tuple[ConstitutionData, PolicyData]:
        """API-02 — validate + compile + persist Constitution and its Policy in ONE transaction.
        Idempotent on the content-hash version: re-applying the same source returns the existing
        rows. Validation/compile failure -> ConstitutionError (no write)."""
        # 1) validate + compile FIRST — no DB work happens if either fails (fail-closed).
        try:
            constitution = Constitution.model_validate(source)
            bundle = compile_constitution(constitution)
        except (ValidationError, ValueError) as exc:
            raise ConstitutionError(str(exc)) from exc
        version = bundle.constitution_version
        # 2) persist atomically; idempotent on version.
        with self._sf() as s:
            existing = s.scalar(
                select(ConstitutionResource).where(ConstitutionResource.version == version)
            )
            if existing is not None:
                pol = s.scalar(
                    select(PolicyResource).where(PolicyResource.constitution_version == version)
                )
                return self._con(existing), self._pol(pol)
            con = ConstitutionResource(name=name, version=version, source=source)
            pol = PolicyResource(
                constitution_version=version,
                yaml_policy=bundle.yaml_policy,
                rego=bundle.rego,
                graduated_config=bundle.graduated_config,
                lists=bundle.lists,
                sequences=bundle.sequences,
            )
            s.add(con)
            s.add(pol)
            s.commit()
            return self._con(con), self._pol(pol)

    def get_constitution(self, version: str) -> ConstitutionData | None:
        with self._sf() as s:
            row = s.scalar(select(ConstitutionResource).where(ConstitutionResource.version == version))
            return self._con(row) if row else None

    def list_constitutions(self) -> list[ConstitutionData]:
        with self._sf() as s:
            rows = s.scalars(
                select(ConstitutionResource).order_by(ConstitutionResource.created_at)
            ).all()
            return [self._con(r) for r in rows]

    def get_latest_policy(self) -> PolicyData | None:
        with self._sf() as s:
            row = s.scalar(select(PolicyResource).order_by(PolicyResource.created_at.desc()).limit(1))
            return self._pol(row) if row else None

    def get_policy(self, version: str) -> PolicyData | None:
        with self._sf() as s:
            row = s.scalar(
                select(PolicyResource).where(PolicyResource.constitution_version == version)
            )
            return self._pol(row) if row else None

    @staticmethod
    def _con(r: ConstitutionResource) -> ConstitutionData:
        return ConstitutionData(str(r.id), r.name, r.version, r.source,
                                r.created_at.isoformat() if r.created_at else None)

    @staticmethod
    def _pol(r: PolicyResource) -> PolicyData:
        return PolicyData(r.constitution_version, r.yaml_policy, r.rego, r.graduated_config,
                          r.lists, r.sequences, r.created_at.isoformat() if r.created_at else None)
```

**Steps (TDD):**
- [ ] Failing test: load a known-valid document `src = yaml.safe_load(open("tests/fixtures/test_constitution.yaml"))`;
  `con, pol = store.apply_constitution("test", src)`; assert `con.version == pol.constitution_version`,
  `"package agentos.constitution" in pol.rego`, `pol.yaml_policy` non-empty; `get_latest_policy()`
  returns it; a malformed source (`src2 = {**src, "bogus_top_level": 1}` → extra=forbid) raises
  `ConstitutionError` and leaves `list_constitutions() == []`; re-applying the SAME `src` returns the
  same version and does NOT create a second row (`len(list_constitutions()) == 1`). Run → fails.
- [ ] Implement the methods + classes. Run → passes.
- [ ] Commit `feat(controlplane): apply_constitution — atomic idempotent compile-on-write (API-02)`.

---

### Task 3: API routes

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/api.py`
- Test: `tests/integration/test_constitution_api.py`

Add to `api.py` (`ResourceStore`/`VersionConflict` already imported from 5a; add `ConstitutionError`):

```python
from agentos_controlplane.resources import ConstitutionError  # add to existing resources import


class ConstitutionIn(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(max_length=255)
    source: dict  # the authored Constitution document (validated by the compiler)
```

In `build_resource_router` add:

```python
    @router.post("/constitutions")
    def apply_constitution(body: ConstitutionIn) -> dict:
        try:
            con, pol = resources.apply_constitution(body.name, body.source)
        except ConstitutionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"constitution": vars(con), "policy_version": pol.constitution_version}

    @router.get("/constitutions")
    def list_constitutions() -> list[dict]:
        return [vars(d) for d in resources.list_constitutions()]

    @router.get("/constitutions/{version}")
    def get_constitution(version: str) -> dict:
        d = resources.get_constitution(version)
        if d is None:
            raise HTTPException(status_code=404, detail="unknown constitution")
        return vars(d)

    @router.get("/policies/latest")
    def latest_policy() -> dict:
        d = resources.get_latest_policy()
        if d is None:
            raise HTTPException(status_code=404, detail="no policy compiled yet")
        return vars(d)

    @router.get("/policies/{version}")
    def get_policy(version: str) -> dict:
        d = resources.get_policy(version)
        if d is None:
            raise HTTPException(status_code=404, detail="unknown policy")
        return vars(d)
```

**Steps (TDD):**
- [ ] Failing test (`test_constitution_api.py`): build app with
  `create_app(ApprovalStore(sf, AuditWriter(sf)), resource_store=ResourceStore(sf),
  api_token="test-token")`; `TestClient` with the Bearer header. POST `/constitutions`
  `{"name":"t","source": <valid fixture dict>}` → 200; the returned `policy_version` ==
  `constitution["version"]`; GET `/policies/latest` → 200 with `rego` containing
  `"package agentos.constitution"`; GET `/constitutions/{version}` → 200; POST with a malformed
  source → 422 and GET `/constitutions` still `[]`; POST the SAME valid body twice → second still 200,
  GET `/constitutions` length 1 (idempotent); no Bearer header → 401. Run → fails.
- [ ] Implement the schema + routes. Run → passes.
- [ ] Commit `feat(controlplane): constitution apply + policy read API (compile-on-write, API-02)`.

---

### Task 4: full gate
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy.
- [ ] Commit only if incidental fixes were needed.

## Self-review
API-02: applying a Constitution validates (Pydantic) + compiles (existing pure compiler) + persists
Constitution and Policy in ONE transaction; malformed → `ConstitutionError` → 422 with nothing
written (fail-closed); idempotent on the content-hash `constitution_version` (re-apply returns the
existing rows, no duplicate); the latest compiled Policy (Rego text + reviewable YAML + metadata) is
retrievable for the engine; routes ride the existing auth-gated resource router (401 without token);
migration 0007 single-head; ORM class names avoid colliding with the Pydantic `Constitution`. Gates
green; hot path untouched (compile-on-write is an operator write path, not per-action).
