"""RUN-01/02 — operator kill switch. In-memory current state (fast hot-path lookup) backed by the
kill_switch table (durability) + the audit chain (immutable history). Single-process Phase-4 model;
distributed invalidation is Phase-7 reconciler territory.

The free-text operator `reason` lives in the in-memory cache + the TABLE only; the audit-event body
carries SHORT IDENTIFIERS (target/scope/set_by) so the 4d secret-gate on `append_event` can never
block an emergency kill. `status()` checks the fleet flag FIRST — a fleet kill shadows everyone.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from agentos_controlplane.store.models import KillSwitch

_FLEET = "*"


@dataclass(frozen=True)
class KillStatus:
    scope: str  # "agent" | "fleet"
    reason: str


class KillSwitchStore:
    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._killed: dict[str, str] = {}  # active target -> reason (in-memory hot-path cache)
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(KillSwitch).where(KillSwitch.active.is_(True))).all():
                self._killed[row.target] = row.reason or ""

    def status(self, agent_id: str) -> KillStatus | None:
        if _FLEET in self._killed:
            return KillStatus("fleet", self._killed[_FLEET])
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
