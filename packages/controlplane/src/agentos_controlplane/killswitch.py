"""RUN-01/02 — operator kill switch. In-memory current state (fast hot-path lookup) backed by the
kill_switch table (durability) + the audit chain (immutable history). Single-process Phase-4 model;
distributed invalidation is Phase-7 reconciler territory.

The free-text operator `reason` lives in the in-memory cache + the TABLE only; the audit-event body
carries SHORT IDENTIFIERS (target/scope/set_by) so the 4d secret-gate on `append_event` can never
block an emergency kill. `status()` checks the fleet flag FIRST — a fleet kill shadows everyone.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from agentos_controlplane.store.models import EmergencyShutdown, KillSwitch

_FLEET = "*"


@dataclass(frozen=True)
class KillStatus:
    scope: str  # "agent" | "fleet" | "emergency"
    reason: str


class KillSwitchStore:
    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._killed: dict[str, str] = {}  # active target -> reason (in-memory hot-path cache)
        self._emergency = False  # RUN-07: is the live fleet halt an EMERGENCY stop?
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(KillSwitch).where(KillSwitch.active.is_(True))).all():
                self._killed[row.target] = row.reason or ""
            # RUN-07: an OPEN incident means the reloaded fleet halt is an emergency stop — a
            # restart must not silently downgrade it to a routine fleet kill.
            self._emergency = (
                s.scalar(
                    select(EmergencyShutdown).where(EmergencyShutdown.resumed_at.is_(None)).limit(1)
                )
                is not None
            )

    def status(self, agent_id: str) -> KillStatus | None:
        if _FLEET in self._killed:
            # The scope the pipeline renders as f"{scope}_killed" — so an emergency stop reads
            # emergency_killed and a routine fleet kill still reads fleet_killed (no hot-path code).
            return KillStatus("emergency" if self._emergency else "fleet", self._killed[_FLEET])
        if agent_id in self._killed:
            return KillStatus("agent", self._killed[agent_id])
        return None

    async def kill(self, agent_id: str, *, set_by: str, reason: str = "") -> None:
        await self._set(agent_id, "agent", set_by, reason)

    async def kill_fleet(self, *, set_by: str, reason: str = "") -> None:
        await self._set(_FLEET, "fleet", set_by, reason)

    async def clear(self, agent_id: str, *, set_by: str) -> None:
        await self._clear(agent_id, "agent", set_by)

    async def clear_fleet(self, *, set_by: str) -> None:
        await self._clear(_FLEET, "fleet", set_by)

    async def emergency_shutdown(self, *, justification: str, set_by: str) -> str:
        """RUN-07 — stop the WHOLE fleet with a mandatory justification. Returns the incident id.

        Reuses the RUN-02 fleet flag, so the pipeline's stage-0 check halts every agent with no new
        hot-path code. The justification is REQUIRED: an empty/whitespace one is rejected and nothing
        is halted (an unexplained fleet stop is not an auditable control).
        """
        text = (justification or "").strip()
        if not text:
            raise ValueError("emergency shutdown requires a non-empty justification")
        incident_id = uuid4()
        # Durable incident record FIRST: the justification must survive even if a later step fails.
        with self._sf() as s:
            s.add(EmergencyShutdown(id=incident_id, justification=text, declared_by=set_by))
            s.commit()
        self._emergency = True  # distinguishes an emergency stop from a routine fleet kill
        # The fleet flag itself (in-memory first, then durable, then audited) — the RUN-02 path.
        await self._set(_FLEET, "emergency", set_by, text)
        # Short identifiers + the incident id only; the justification text stays in the table.
        await self._audit.append_event(
            "emergency_shutdown",
            {"incident_id": str(incident_id), "scope": "fleet", "set_by": set_by},
        )
        return str(incident_id)

    async def resume_fleet(self, *, set_by: str) -> None:
        """RUN-07 — explicit operator resume: close the open incident and clear the fleet halt."""
        with self._sf() as s:
            row = self._open_incident(s)
            incident_id = str(row.id) if row is not None else None
            if row is not None:
                row.resumed_at = datetime.now(timezone.utc).replace(tzinfo=None)
                row.resumed_by = set_by
                s.commit()
        await self._audit.append_event(
            "emergency_resume",
            {"incident_id": incident_id or "", "scope": "fleet", "set_by": set_by},
        )
        await self._clear(_FLEET, "emergency", set_by)  # durable-first un-halt (existing path)
        self._emergency = False

    def active_incident(self) -> str | None:
        """The open incident id, or None. Read from the table (operator-facing, not the hot path)."""
        with self._sf() as s:
            row = self._open_incident(s)
            return str(row.id) if row is not None else None

    @staticmethod
    def _open_incident(session) -> EmergencyShutdown | None:
        return session.scalar(
            select(EmergencyShutdown)
            .where(EmergencyShutdown.resumed_at.is_(None))
            .order_by(EmergencyShutdown.declared_at.desc())
            .limit(1)
        )

    def list_active(self) -> list[dict]:
        return [
            {"target": t, "scope": "fleet" if t == _FLEET else "agent", "reason": r}
            for t, r in sorted(self._killed.items())
        ]

    async def _set(self, target, scope, set_by, reason):
        self._killed[target] = reason  # in-memory first (hot path)
        with self._sf() as s:  # upsert current state
            row = s.get(KillSwitch, target)
            if row is None:
                s.add(KillSwitch(target=target, active=True, reason=reason, set_by=set_by))
            else:
                row.active, row.reason, row.set_by = True, reason, set_by
            s.commit()
        # audit event body = short identifiers only (no free-text reason -> the 4d secret-gate on
        # append_event can never block an emergency kill).
        await self._audit.append_event(
            "kill_switch_set", {"target": target, "scope": scope, "set_by": set_by}
        )

    async def _clear(self, target, scope, set_by):
        # Table-FIRST (mirror _set): flip the durable row + audit BEFORE dropping the
        # in-memory kill. A failed clear then leaves the agent killed in BOTH memory and
        # table — the same fail-toward-contained direction as kill — instead of un-killing
        # live while durability still says active.
        with self._sf() as s:
            row = s.get(KillSwitch, target)
            if row is not None:
                row.active, row.set_by = False, set_by
                s.commit()
        await self._audit.append_event(
            "kill_switch_cleared", {"target": target, "scope": scope, "set_by": set_by}
        )
        self._killed.pop(target, None)  # un-kill the hot path only after durable steps succeed
