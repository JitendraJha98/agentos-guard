"""ApprovalStore — parked approvals, temporary exceptions, governance reviews.

POL-07 / POL-13 / POL-14 over the same session factory the audit writer uses.

WHY STORE-AWAITED BLOCKING, NEVER IN-PROCESS FUTURES (D3): `wait_resolved`
async-POLLS the persisted row state. An in-process future would tie a parked
approval's resolvability to the lifetime (and address space) of the process
that parked it — kill the process and the approval is unresolvable; resolve
from another process (the Phase-5 out-of-process API, a CLI, a second worker)
and the future never fires. Polling the row makes the DB the single
rendezvous: any writer that flips `status` resolves the wait, and a restarted
process can re-issue the same wait against the same row (kill-the-process
resumability). The 0.2 s default poll is humans-approving latency, not hot-path
latency.

Redaction: approval-row `context` goes through the SAME `_redact_or_raise` the
audit writer uses (imported, not forked) — an unclassifiable payload raises
RedactionError and NO row is created (fail closed, D-15).

Every lifecycle mutation here writes an event through the ONE audit hash chain
(`AuditWriter.append_event`): `approval_resolved`, `approval_timed_out`,
`exception_granted`, `review_opened`.

Datetimes are persisted UTC-NAIVE (SQLite drops tz offsets, D-14); this module
normalizes aware datetimes on write and re-attaches UTC on read, so callers
only ever see tz-aware datetimes.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_contract import AgentAction, Decision
from agentos_controlplane.audit import AuditWriter, _redact_or_raise
from agentos_controlplane.store.models import (
    ApprovalRequest,
    GovernanceReview,
    TemporaryException,
)

_RESOLVABLE = ("pending",)
_TERMINAL = frozenset({"approved", "denied", "timed_out"})


class AlreadyResolvedError(Exception):
    """Raised on resolving a non-pending approval (the API maps this to 409)."""


def _utc_naive(dt: datetime) -> datetime:
    """Normalize to UTC-naive for persistence (SQLite drops tz offsets)."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _utc_aware(dt: datetime) -> datetime:
    """Re-attach UTC on read (stored values are UTC-naive by construction)."""
    return dt.replace(tzinfo=timezone.utc)


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ApprovalStore:
    """All approval/exception/review persistence over the one session factory."""

    def __init__(self, session_factory: sessionmaker[Session], audit: AuditWriter) -> None:
        self.session_factory = session_factory
        self._audit = audit

    # --- approvals (POL-07) ---------------------------------------------------

    def create(self, action: AgentAction, decision: Decision, *, deadline_s: float) -> UUID:
        """Park one approval request. Context is REDACTED fail-closed first —
        a RedactionError means NO row is created."""
        context = _redact_or_raise(action.payload)  # raises -> no row (D-15)
        row = ApprovalRequest(
            action_id=action.id,
            agent_id=action.agent_id,
            action_type=action.type.value,
            target=action.target,
            context=context,
            reasons=[r.model_dump(mode="json") for r in decision.reasons],
            risk_score=decision.risk_score,
            trust_score=decision.trust_score,
            status="pending",
            deadline_at=_now_naive() + timedelta(seconds=deadline_s),
        )
        with self.session_factory() as session:
            session.add(row)
            session.commit()
            return row.id

    def get(self, approval_id: UUID) -> ApprovalRequest | None:
        with self.session_factory() as session:
            return session.get(ApprovalRequest, approval_id)

    def list_requests(self, status: str | None = None) -> list[ApprovalRequest]:
        stmt = select(ApprovalRequest).order_by(ApprovalRequest.created_at)
        if status is not None:
            stmt = stmt.where(ApprovalRequest.status == status)
        with self.session_factory() as session:
            return list(session.scalars(stmt))

    def list_pending(self) -> list[ApprovalRequest]:
        return self.list_requests("pending")

    async def resolve(
        self,
        approval_id: UUID,
        *,
        approved: bool,
        resolver: str,
        note: str | None = None,
        grant_exception_until: datetime | None = None,
    ) -> ApprovalRequest:
        """The single status transition (pending -> approved|denied), audited.

        `grant_exception_until` (POL-13) is the ONLY way a TemporaryException is
        born: human resolution — never authorable, never interpreter-grantable.
        It requires an approve; it grants one exception per fired principle ref.
        """
        if grant_exception_until is not None and not approved:
            raise ValueError("grant_exception_until requires approved=True")
        with self.session_factory() as session:
            row = session.get(ApprovalRequest, approval_id)
            if row is None:
                raise KeyError(f"unknown approval: {approval_id}")
            if row.status != "pending":
                raise AlreadyResolvedError(
                    f"approval {approval_id} already {row.status}"
                )
            row.status = "approved" if approved else "denied"
            row.resolved_at = _now_naive()
            row.resolver = resolver
            row.resolution_note = note
            granted: list[TemporaryException] = []
            if approved and grant_exception_until is not None:
                for ref in self._fired_refs(row.reasons):
                    granted.append(
                        TemporaryException(
                            agent_id=row.agent_id,
                            principle_ref=ref,
                            granted_by=resolver,
                            approval_id=approval_id,
                            expires_at=_utc_naive(grant_exception_until),
                        )
                    )
                session.add_all(granted)
            session.commit()
        await self._audit.append_event(
            "approval_resolved",
            {
                "approval_id": str(approval_id),
                "action_id": str(row.action_id),
                "agent_id": row.agent_id,
                "approved": approved,
                "resolver": resolver,
            },
        )
        for exc in granted:
            await self._audit.append_event(
                "exception_granted",
                {
                    "exception_id": str(exc.id),
                    "approval_id": str(approval_id),
                    "agent_id": exc.agent_id,
                    "principle_ref": exc.principle_ref,
                    "granted_by": exc.granted_by,
                    "expires_at": _utc_aware(exc.expires_at).isoformat(),
                },
            )
        return row

    @staticmethod
    def _fired_refs(reasons: list[dict]) -> list[str]:
        """Distinct fired-principle refs from the parked reasons (order-stable)."""
        refs: list[str] = []
        for r in reasons:
            ref = r.get("principle_ref")
            if r.get("stage") == "policy" and ref and ref not in refs:
                refs.append(ref)
        return refs

    async def wait_resolved(
        self, approval_id: UUID, deadline_s: float, poll_s: float = 0.2
    ) -> ApprovalRequest | None:
        """Block until the persisted row leaves `pending` or the deadline passes.

        POLLS the row (D3, module docstring) — never an in-process future. On
        deadline: mark the row `timed_out` (audited) and return None; the caller
        applies the per-action-class posture default.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + deadline_s
        while True:
            row = self.get(approval_id)
            if row is None:
                raise KeyError(f"unknown approval: {approval_id}")
            if row.status != "pending":
                return row
            remaining = deadline - loop.time()
            if remaining <= 0:
                return await self._mark_timed_out(approval_id)
            await asyncio.sleep(min(poll_s, remaining))

    async def _mark_timed_out(self, approval_id: UUID) -> ApprovalRequest | None:
        """Transition pending -> timed_out (audited). A racing resolve wins:
        if the row left `pending` in the meantime, return the resolved row."""
        with self.session_factory() as session:
            row = session.get(ApprovalRequest, approval_id)
            if row.status != "pending":  # resolved at the deadline boundary
                return row
            row.status = "timed_out"
            row.resolved_at = _now_naive()
            session.commit()
        await self._audit.append_event(
            "approval_timed_out",
            {
                "approval_id": str(approval_id),
                "action_id": str(row.action_id),
                "agent_id": row.agent_id,
            },
        )
        return None

    # --- temporary exceptions (POL-13) ----------------------------------------

    def active_exceptions(
        self, agent_id: str, refs: tuple[str, ...] | list[str]
    ) -> dict[str, datetime]:
        """Active (unexpired, unrevoked) exceptions for (agent_id, ref in refs).

        Auto-revoke is THIS read-time check (`expires_at > now()`): an expired
        grant is simply absent — no background job. Returns {ref: tz-aware expiry}
        (latest expiry per ref when several grants overlap)."""
        stmt = select(TemporaryException).where(
            TemporaryException.agent_id == agent_id,
            TemporaryException.principle_ref.in_(tuple(refs)),
            TemporaryException.revoked.is_(False),
            TemporaryException.expires_at > _now_naive(),
        )
        active: dict[str, datetime] = {}
        with self.session_factory() as session:
            for row in session.scalars(stmt):
                expiry = _utc_aware(row.expires_at)
                if row.principle_ref not in active or expiry > active[row.principle_ref]:
                    active[row.principle_ref] = expiry
        return active

    # The pipeline's ExceptionLookup Protocol spells this `active_for` — same
    # signature, one implementation (the read-time auto-revoke above).
    active_for = active_exceptions

    def revoke(self, exception_id: UUID) -> None:
        """The explicit kill switch alongside read-time expiry."""
        with self.session_factory() as session:
            row = session.get(TemporaryException, exception_id)
            if row is None:
                raise KeyError(f"unknown exception: {exception_id}")
            row.revoked = True
            session.commit()

    # --- governance reviews (POL-14) -------------------------------------------

    async def open_review(self, action_id: UUID, agent_id: str, *, summary: str = "") -> UUID:
        """Open an async NON-blocking review (the action proceeds), audited."""
        row = GovernanceReview(action_id=action_id, agent_id=agent_id, summary=summary)
        with self.session_factory() as session:
            session.add(row)
            session.commit()
            review_id = row.id
        await self._audit.append_event(
            "review_opened",
            {
                "review_id": str(review_id),
                "action_id": str(action_id),
                "agent_id": agent_id,
            },
        )
        return review_id

    def list_reviews(self, status: str | None = None) -> list[GovernanceReview]:
        stmt = select(GovernanceReview).order_by(GovernanceReview.opened_at)
        if status is not None:
            stmt = stmt.where(GovernanceReview.status == status)
        with self.session_factory() as session:
            return list(session.scalars(stmt))

    def close_review(self, review_id: UUID) -> None:
        with self.session_factory() as session:
            row = session.get(GovernanceReview, review_id)
            if row is None:
                raise KeyError(f"unknown review: {review_id}")
            row.status = "closed"
            row.closed_at = _now_naive()
            session.commit()
