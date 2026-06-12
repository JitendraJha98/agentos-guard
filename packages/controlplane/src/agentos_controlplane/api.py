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

from fastapi import APIRouter, FastAPI, HTTPException
from pydantic import BaseModel

from agentos_controlplane.approvals import AlreadyResolvedError, ApprovalStore
from agentos_controlplane.store.models import ApprovalRequest, GovernanceReview


class ResolveRequest(BaseModel):
    model_config = {"extra": "forbid"}

    approved: bool
    resolver: str
    note: str | None = None
    # POL-13: the ONLY door a temporary exception comes through (human-ratified).
    exception_expires_at: datetime | None = None


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


def create_app(store: ApprovalStore) -> FastAPI:
    app = FastAPI(title="agentos-guard control plane", version="0.1.0")
    app.include_router(build_router(store))
    return app
