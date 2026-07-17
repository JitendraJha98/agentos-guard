"""The minimal operator resolve API (API-03) — a FastAPI router over the ApprovalStore.

The API holds no in-process state: it reads and writes the SAME persisted rows
`wait_resolved` polls (D3), so a resolve from this API — in-process today, the
Phase-5 out-of-process service tomorrow — unblocks any parked waiter. Resolution
auditing (`approval_resolved` / `exception_granted` events) happens inside the
store, not here, so every writer is audited identically.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from agentos_controlplane.approvals import AlreadyResolvedError, ApprovalStore
from agentos_controlplane.auth import make_require_token, resolve_api_token
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.resources import ConstitutionError, ResourceStore, VersionConflict
from agentos_controlplane.store.models import ApprovalRequest, GovernanceReview


class ResolveRequest(BaseModel):
    model_config = {"extra": "forbid"}

    approved: bool
    resolver: str = Field(max_length=128)  # bounded operator input -> 422
    note: str | None = Field(default=None, max_length=512)
    # POL-13: the ONLY door a temporary exception comes through (human-ratified).
    exception_expires_at: datetime | None = None


class KillRequest(BaseModel):
    model_config = {"extra": "forbid"}

    set_by: str = Field(max_length=128)  # bounded operator input -> 422
    reason: str | None = Field(default=None, max_length=512)


class ClearRequest(BaseModel):
    model_config = {"extra": "forbid"}

    set_by: str = Field(max_length=128)


def _approval_json(row: ApprovalRequest) -> dict:
    return {
        "id": str(row.id),
        "action_id": str(row.action_id),
        "agent_id": row.agent_id,
        "action_type": row.action_type,
        "target": row.target,
        "context": row.context,
        "reasons": row.reasons,
        "risk_score": row.risk_score,
        "trust_score": row.trust_score,
        "status": row.status,
        "deadline_at": row.deadline_at.isoformat(),
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "resolver": row.resolver,
        "resolution_note": row.resolution_note,
    }


def _review_json(row: GovernanceReview) -> dict:
    return {
        "id": str(row.id),
        "action_id": str(row.action_id),
        "agent_id": row.agent_id,
        "summary": row.summary,
        "status": row.status,
        "opened_at": row.opened_at.isoformat() if row.opened_at else None,
        "closed_at": row.closed_at.isoformat() if row.closed_at else None,
    }


def build_router(store: ApprovalStore) -> APIRouter:
    router = APIRouter()

    @router.get("/approvals")
    def list_approvals(status: str | None = None) -> list[dict]:
        return [_approval_json(r) for r in store.list_requests(status)]

    @router.post("/approvals/{approval_id}/resolve")
    async def resolve_approval(approval_id: UUID, body: ResolveRequest) -> dict:
        try:
            row = await store.resolve(
                approval_id,
                approved=body.approved,
                resolver=body.resolver,
                note=body.note,
                grant_exception_until=body.exception_expires_at,
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown approval") from None
        except AlreadyResolvedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return _approval_json(row)

    @router.get("/reviews")
    def list_reviews(status: str | None = None) -> list[dict]:
        return [_review_json(r) for r in store.list_reviews(status)]

    return router


def build_kill_router(kill_store: KillSwitchStore) -> APIRouter:
    """RUN-01/02 — operator kill-switch endpoints. POST is used for clear too (avoids a
    DELETE-with-body). The free-text reason rides only into the kill_switch table; the
    audited toggle body carries short identifiers only (handled in KillSwitchStore)."""
    router = APIRouter()

    @router.get("/kill")
    def list_kills() -> list[dict]:
        return kill_store.list_active()

    @router.post("/kill/agents/{agent_id}")
    async def kill_agent(agent_id: str, body: KillRequest) -> dict:
        await kill_store.kill(agent_id, set_by=body.set_by, reason=body.reason or "")
        return {"target": agent_id, "scope": "agent", "active": True}

    @router.post("/kill/agents/{agent_id}/clear")
    async def clear_agent(agent_id: str, body: ClearRequest) -> dict:
        await kill_store.clear(agent_id, set_by=body.set_by)
        return {"target": agent_id, "scope": "agent", "active": False}

    @router.post("/kill/fleet")
    async def kill_fleet(body: KillRequest) -> dict:
        await kill_store.kill_fleet(set_by=body.set_by, reason=body.reason or "")
        return {"target": "*", "scope": "fleet", "active": True}

    @router.post("/kill/fleet/clear")
    async def clear_fleet(body: ClearRequest) -> dict:
        await kill_store.clear_fleet(set_by=body.set_by)
        return {"target": "*", "scope": "fleet", "active": False}

    return router


class TrustProfileIn(BaseModel):
    model_config = {"extra": "forbid"}

    trust_score: float = Field(ge=0.0, le=1.0)
    band: dict | None = None
    # TRST-04: the agent's own capability scope; `["*"]` is the wildcard, null leaves it
    # unset (which resolves to the wildcard). Bounded so an operator cannot author an
    # unbounded scope list into the hot path.
    scope: list[str] | None = Field(default=None, max_length=256)
    version: int | None = None  # required (== current) to update; omit/None to create


class AbomIn(BaseModel):
    model_config = {"extra": "forbid"}

    components: dict
    version: int | None = None


class ConstitutionIn(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(max_length=255)
    source: dict  # the authored Constitution document (validated + compiled on write)


def build_resource_router(resources: ResourceStore) -> APIRouter:
    """API-01 — declarative TrustProfile / Abom resources: validate (422), version (409), store."""
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
                agent_id,
                trust_score=body.trust_score,
                band=body.band,
                expected_version=body.version,
                scope=body.scope,
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

    @router.put("/aboms/{agent_id}/declare")
    def declare_abom(agent_id: str, body: AbomIn) -> dict:
        """ABOM-02 — declare an ABOM as provenance-tracked components (digest/version/source)."""
        try:
            d = resources.declare_abom(
                agent_id, body.components, expected_version=body.version
            )
        except VersionConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return vars(d)

    @router.get("/aboms/{agent_id}/components")
    def get_abom_components(agent_id: str) -> list[dict]:
        return resources.get_abom_components(agent_id)

    # ---- Constitution / Policy (compile-on-write, API-02) ----
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

    return router


def build_inventory_router(inventory: InventoryStore) -> APIRouter:
    """DISC-01/02 — read API over the authoritative agent inventory."""
    router = APIRouter()

    @router.get("/inventory")
    def list_inventory() -> list[dict]:
        return [vars(d) for d in inventory.list_inventory()]

    @router.get("/inventory/{agent_id}")
    def get_inventory(agent_id: str) -> list[dict]:
        return [vars(d) for d in inventory.get_inventory(agent_id)]

    return router


class RegisterIn(BaseModel):
    model_config = {"extra": "forbid"}

    # No trust_score: registration is not a self-grading channel. The shared enrollment token
    # authenticates a legitimate enrollee, it does not authorize that enrollee to set its own
    # reputation. New agents are seeded with the server-side DEFAULT_TRUST_SCORE; trust is graded only
    # via the gated, operator-facing PUT /trust-profiles route.
    manifest: dict | None = None  # {tools: [...], prompts: [...], memories: [...]}


def build_registration_router(registry: Registry) -> APIRouter:
    """SDK-02 — gated self-registration: persist the Agent + return its identity token; an optional
    manifest declares the agent's components into the inventory (DISC-01)."""
    router = APIRouter()

    @router.post("/agents/{agent_id}/register")
    def register_agent(agent_id: str, body: RegisterIn) -> dict:
        token = registry.register(agent_id, manifest=body.manifest)
        return {"agent_id": agent_id, "token": token}

    return router


def create_app(
    store: ApprovalStore,
    kill_store: KillSwitchStore | None = None,
    resource_store: ResourceStore | None = None,
    inventory_store: InventoryStore | None = None,
    api_token: str | None = None,
    registry: Registry | None = None,
    session_factory=None,
    dashboard: bool = False,
) -> FastAPI:
    # Phase-5 P0: a shared-token gate guards EVERY router. Token resolution is
    # explicit arg -> AGENTOS_API_TOKEN env -> ephemeral random (logged) — never silently open.
    token = resolve_api_token(api_token)
    guard = [Depends(make_require_token(token))]
    app = FastAPI(title="agentos-guard control plane", version="0.1.0")
    app.state.api_token = token
    app.include_router(build_router(store), dependencies=guard)
    # RUN-01/02: the kill-switch router is wired only when a kill_store is supplied —
    # existing create_app(store) callers keep working with no /kill routes.
    if kill_store is not None:
        app.include_router(build_kill_router(kill_store), dependencies=guard)
    if resource_store is not None:
        app.include_router(build_resource_router(resource_store), dependencies=guard)
    # DISC-01/02: the inventory read router rides the same gate; absent an inventory_store the
    # routes are not wired (GET /inventory -> 404), keeping existing create_app callers working.
    if inventory_store is not None:
        app.include_router(build_inventory_router(inventory_store), dependencies=guard)
    # SDK-02: self-registration rides the same gate; absent a registry the /agents routes are not
    # wired (POST /agents/{id}/register -> 404), keeping existing create_app callers working.
    if registry is not None:
        app.include_router(build_registration_router(registry), dependencies=guard)
    # DASH-01/02/03: the operator dashboard mounts ONLY when dashboard=True; it is NOT behind the
    # Bearer guard (browsers cannot send it on page navs) — it has its OWN cookie-login gate over the
    # same shared token. Default off keeps every existing create_app caller working.
    if dashboard:
        from agentos_controlplane.dashboard import mount_dashboard

        mount_dashboard(
            app,
            token,
            approvals=store,
            kill_store=kill_store,
            inventory=inventory_store,
            session_factory=session_factory,
        )
    return app
