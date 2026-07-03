# Phase 5 · Slice 5d — SDK Self-Register + Control-Plane Client (SDK-02, SDK-04) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) green at every commit.

**Goal (SDK-02/04):** The SDK lets an agent **self-register** and receive an identity token, and
provides a **control-plane client** for resource CRUD and approvals. Registration presents the shared
enrollment token (the Phase-5 gate) and returns the agent's per-agent EdDSA identity token; a manifest
declares the agent's components into the inventory (DISC-01).

**Architecture:** Control-plane side adds a gated `POST /agents/{agent_id}/register` endpoint backed by
the existing `Registry` (with an optional `InventoryStore` for the manifest). SDK side adds
`ControlPlaneClient` — a thin `httpx`-based client carrying the shared token as a Bearer header, with
`register(...)` + approvals + resource/inventory methods. Tests drive the client against the live
FastAPI app via `httpx.ASGITransport` — no network/server.

**Tech Stack:** FastAPI, `httpx` (new SDK runtime dep), Pydantic v2, pytest.

> First commit in this slice: `docs(phase-5): Slice 5d plan` for this file, then the tasks below.

## File structure
- Modify `.../controlplane/api.py` — `RegisterIn` + `build_registration_router(registry)` +
  `create_app(..., registry=None)`.
- Create `packages/sdk/src/agentos_sdk/client.py` — `ControlPlaneClient`, `ControlPlaneError`.
- Modify `packages/sdk/src/agentos_sdk/__init__.py` — export them.
- Modify `packages/sdk/pyproject.toml` — add `httpx>=0.27` runtime dep.
- Tests: `tests/integration/test_registration_api.py`, `tests/integration/test_control_plane_client.py`.

---

### Task 1: registration API endpoint (SDK-02 server side)

**Files:**
- Modify: `.../controlplane/api.py`
- Test: `tests/integration/test_registration_api.py`

Add to `api.py`:

```python
from agentos_controlplane.registry import Registry


class RegisterIn(BaseModel):
    model_config = {"extra": "forbid"}
    trust_score: float | None = Field(default=None, ge=0.0, le=1.0)
    manifest: dict | None = None  # {tools: [...], prompts: [...], memories: [...]}


def build_registration_router(registry: Registry) -> APIRouter:
    router = APIRouter()

    @router.post("/agents/{agent_id}/register")
    def register_agent(agent_id: str, body: RegisterIn) -> dict:
        kwargs = {}
        if body.trust_score is not None:
            kwargs["trust_score"] = body.trust_score
        token = registry.register(agent_id, manifest=body.manifest, **kwargs)
        return {"agent_id": agent_id, "token": token}

    return router
```

Extend `create_app` with `registry: Registry | None = None`; when provided, include
`build_registration_router(registry)` with `dependencies=guard` (keep all existing callers working —
no `/agents` routes without a registry).

**Steps (TDD):**
- [ ] Failing test: build a `Registry(sf, inventory=InventoryStore(sf))`; app =
  `create_app(ApprovalStore(sf, AuditWriter(sf)), inventory_store=InventoryStore(sf), registry=registry,
  api_token="test-token")`; `TestClient` with the Bearer header. POST
  `/agents/a/register` `{"manifest":{"tools":["http_get"]}}` → 200 with a non-empty `token`;
  `Registry(sf).is_registered("a")` is True; the declared inventory row exists; `trust_score` 2.0 →
  422; no Bearer header → 401; `create_app` without `registry` → POST `/agents/a/register` → 404. Run
  → fails.
- [ ] Implement `RegisterIn` + `build_registration_router` + `create_app` change. Run → passes.
- [ ] Commit `feat(controlplane): gated self-registration endpoint -> identity token (SDK-02)`.

---

### Task 2: `ControlPlaneClient` core + register + approvals

**Files:**
- Create: `packages/sdk/src/agentos_sdk/client.py`
- Modify: `packages/sdk/src/agentos_sdk/__init__.py`, `packages/sdk/pyproject.toml`
- Test: `tests/integration/test_control_plane_client.py`

```python
"""SDK-02/04 — the control-plane client. A thin httpx wrapper that carries the shared API token as a
Bearer header; register() self-registers an agent and returns its identity token; the rest is
resource CRUD + approvals over the declarative API. Decoupled from the control plane internals — pure
HTTP, depends only on httpx."""
from __future__ import annotations

import httpx


class ControlPlaneError(Exception):
    """A non-2xx control-plane response (status + body)."""


class ControlPlaneClient:
    def __init__(self, base_url: str, token: str, *, transport: httpx.BaseTransport | None = None,
                 timeout: float = 10.0) -> None:
        self._http = httpx.Client(
            base_url=base_url,
            headers={"Authorization": f"Bearer {token}"},
            transport=transport,   # tests inject httpx.ASGITransport(app=app)
            timeout=timeout,
        )

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "ControlPlaneClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _request(self, method: str, path: str, **kw):
        resp = self._http.request(method, path, **kw)
        if resp.status_code >= 400:
            raise ControlPlaneError(f"{method} {path} -> {resp.status_code}: {resp.text}")
        return resp.json() if resp.content else None

    # ---- SDK-02 self-registration ----
    def register(self, agent_id: str, *, trust_score: float | None = None,
                 manifest: dict | None = None) -> str:
        body: dict = {}
        if trust_score is not None:
            body["trust_score"] = trust_score
        if manifest is not None:
            body["manifest"] = manifest
        return self._request("POST", f"/agents/{agent_id}/register", json=body)["token"]

    # ---- approvals (SDK-04) ----
    def list_approvals(self, status: str | None = None) -> list[dict]:
        return self._request("GET", "/approvals", params={"status": status} if status else None)

    def resolve_approval(self, approval_id: str, *, approved: bool, resolver: str,
                         note: str | None = None) -> dict:
        body: dict = {"approved": approved, "resolver": resolver}
        if note is not None:
            body["note"] = note
        return self._request("POST", f"/approvals/{approval_id}/resolve", json=body)
```

Export `ControlPlaneClient`, `ControlPlaneError` from `agentos_sdk/__init__.py`. Add
`"httpx>=0.27"` to `packages/sdk/pyproject.toml` dependencies.

**Steps (TDD):**
- [ ] Failing test: build the app (with `registry`, `inventory_store`, `resource_store`, an
  `ApprovalStore`, `api_token="test-token"`); `client = ControlPlaneClient("http://test", "test-token",
  transport=httpx.ASGITransport(app=app))`. Assert `client.register("a",
  manifest={"tools":["http_get"]})` returns a non-empty token and `is_registered("a")`; park an
  `ApprovalRequest` in the store, `client.list_approvals()` returns it, `client.resolve_approval(id,
  approved=True, resolver="op")` resolves it; a client built with the WRONG token raises
  `ControlPlaneError` (401) on any call. Run → fails.
- [ ] Implement `client.py` + exports + dep. Run → passes.
- [ ] Commit `feat(sdk): ControlPlaneClient — self-register + approvals over httpx (SDK-02/04)`.

---

### Task 3: `ControlPlaneClient` resource CRUD + inventory (SDK-04)

**Files:**
- Modify: `packages/sdk/src/agentos_sdk/client.py`
- Test: `tests/integration/test_control_plane_client.py`

Add methods:

```python
    # ---- resources (SDK-04) ----
    def put_trust_profile(self, agent_id: str, *, trust_score: float, band: dict | None = None,
                          version: int | None = None) -> dict:
        return self._request("PUT", f"/trust-profiles/{agent_id}",
                             json={"trust_score": trust_score, "band": band, "version": version})

    def get_trust_profile(self, agent_id: str) -> dict:
        return self._request("GET", f"/trust-profiles/{agent_id}")

    def list_trust_profiles(self) -> list[dict]:
        return self._request("GET", "/trust-profiles")

    def put_abom(self, agent_id: str, *, components: dict, version: int | None = None) -> dict:
        return self._request("PUT", f"/aboms/{agent_id}",
                             json={"components": components, "version": version})

    def apply_constitution(self, name: str, source: dict) -> dict:
        return self._request("POST", "/constitutions", json={"name": name, "source": source})

    def get_latest_policy(self) -> dict:
        return self._request("GET", "/policies/latest")

    def list_inventory(self) -> list[dict]:
        return self._request("GET", "/inventory")

    def get_inventory(self, agent_id: str) -> list[dict]:
        return self._request("GET", f"/inventory/{agent_id}")
```

**Steps (TDD):**
- [ ] Failing test (same app/client harness): `put_trust_profile("a", trust_score=0.7)` → version 1,
  again with `version=1` → version 2, stale `version=1` → `ControlPlaneError` (409);
  `apply_constitution("t", <valid fixture dict>)` → returns `policy_version`, then
  `get_latest_policy()` rego contains `package agentos.constitution`; after `register("a",
  manifest=...)`, `list_inventory()` / `get_inventory("a")` show the declared rows. Run → fails.
- [ ] Implement the methods. Run → passes.
- [ ] Commit `feat(sdk): ControlPlaneClient resource CRUD + inventory reads (SDK-04)`.

---

### Task 4: full gate
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy
  (the SDK client + registration endpoint are off the per-action hot path).
- [ ] Commit only if incidental fixes were needed.

## Self-review
SDK-02: `client.register(agent_id, manifest=...)` presents the shared enrollment token (the gate),
self-registers via `POST /agents/{id}/register`, returns the per-agent identity token, and declares
the manifest into the inventory. SDK-04: the client does resource CRUD (trust-profiles/aboms/
constitutions/policies) + inventory reads + approvals (list/resolve), surfacing non-2xx as
`ControlPlaneError` (incl. 401 on a bad token and 409 on a version conflict). Tested against the live
app via `httpx.ASGITransport` (no server). `httpx` added as an SDK runtime dep; the client stays pure
HTTP (no control-plane import — no PDP/PEP coupling regression). Gates green; hot path untouched.
