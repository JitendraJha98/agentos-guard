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

from agentos_controlplane.secret_scan import scan
from agentos_controlplane.store.models import EmergencyShutdown, KillSwitch

_FLEET = "*"
# The fleet flag's reason for an EMERGENCY stop. It is also the durable marker the scope is derived
# from, so `_emergency` is never a sticky bool that can outlive the halt it describes.
_EMERGENCY_PREFIX = "emergency shutdown (incident "
_MAX_JUSTIFICATION = 2000


def _emergency_reason(incident_id) -> str:
    return f"{_EMERGENCY_PREFIX}{incident_id})"


class EmergencyActiveError(RuntimeError):
    """An OPEN emergency incident blocks a routine RUN-02 fleet operation (surfaced as a 409).

    The only way out of an emergency stop is `resume_fleet` — otherwise the routine clear path is a
    second, unjustified, un-acknowledged exit that leaves the incident row open while the fleet runs.
    """


def _check_set_by(set_by: str) -> None:
    """Reject a secret-shaped operator id BEFORE anything is halted.

    `set_by` rides verbatim into two hash-covered audit bodies (`kill_switch_set`,
    `emergency_shutdown`); a secret there trips the AUD-04 gate MID-flight, which used to leave the
    fleet halted with ZERO audit records and the operator holding a bare 500. Failing first is loud
    and changes nothing. (The JUSTIFICATION is never checked this way — it must never veto a stop.)
    """
    if scan(set_by or ""):
        raise ValueError("set_by looks secret-bearing; use a plain operator identifier")


@dataclass(frozen=True)
class KillStatus:
    scope: str  # "agent" | "fleet" | "emergency"
    reason: str


@dataclass(frozen=True)
class ShutdownResult:
    """RUN-07 — what the operator gets back. `degraded` names the durability/audit steps that FAILED
    while the fleet was nonetheless halted, so "halted but unaudited" is distinguishable from "not
    halted at all" (a bare 500 for both invited a retry, i.e. a duplicate incident)."""

    incident_id: str
    degraded: tuple[str, ...] = ()


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
            # RUN-07: an OPEN incident is AUTHORITATIVE for containment, not just for labelling.
            # The incident row and the kill_switch flag are two separate commits, so a crash (or a
            # failed durable step) between them can leave a declared emergency with no fleet flag —
            # a restart would then come up "emergency declared, nothing halted". Re-asserting the
            # halt here fails toward CONTAINED and makes the incident table the source of truth.
            row = self._open_incident(s)
            if row is not None:
                self._killed[_FLEET] = _emergency_reason(row.id)
        # Derived, never a sticky bool: the scope is whatever the live fleet reason says it is.
        self._emergency = self._killed.get(_FLEET, "").startswith(_EMERGENCY_PREFIX)

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
        # A routine fleet kill must not OVERWRITE a live emergency halt: that would relabel it
        # `fleet` while the incident stays open — the exact forensic downgrade RUN-07 exists to
        # prevent. Refuse (409); the emergency halt already stops everything anyway.
        self._require_no_open_incident()
        await self._set(_FLEET, "fleet", set_by, reason)

    async def clear(self, agent_id: str, *, set_by: str) -> None:
        await self._clear(agent_id, "agent", set_by)

    async def clear_fleet(self, *, set_by: str) -> None:
        await self._clear(_FLEET, "fleet", set_by)

    async def emergency_shutdown(self, *, justification: str, set_by: str) -> ShutdownResult:
        """RUN-07 — stop the WHOLE fleet with a mandatory justification.

        Reuses the RUN-02 fleet flag, so the pipeline's stage-0 check halts every agent with no new
        hot-path code. The justification is REQUIRED: an empty/whitespace one is rejected and nothing
        is halted (an unexplained fleet stop is not an auditable control) — but it is NEVER rejected
        for its content or its LENGTH, because a last-resort control that refuses to fire over input
        formatting is not a control. An over-long justification is truncated, not refused.
        """
        _check_set_by(set_by)  # fails BEFORE anything is halted, so it changes nothing
        text = (justification or "").strip()
        if not text:
            raise ValueError("emergency shutdown requires a non-empty justification")
        text = text[:_MAX_JUSTIFICATION]  # head kept, tail dropped — never a refusal
        # Single-incident model: a second declaration is refused so that a resume can never un-halt
        # the fleet while another operator's incident is still open. This is the ONLY DB read before
        # containment, so a blip on it must not block the stop — fall through and halt (at worst a
        # duplicate incident row, which resume_fleet closes along with every other open one).
        try:
            open_id = self.active_incident()
        except Exception:
            open_id = None
        if open_id is not None:
            raise EmergencyActiveError(f"emergency incident {open_id} is already open")

        incident_id = uuid4()
        # CONTAINMENT FIRST. The in-memory fleet flag is what the pipeline's stage-0 check reads and
        # it costs no I/O, so a DB blip can never block the stop. Every durable/audit step below is
        # best-effort and reported via `degraded` instead of raising: raising left the operator
        # unable to tell "halted but unaudited" from "not halted", and invited a retry.
        self._killed[_FLEET] = _emergency_reason(incident_id)
        self._emergency = True
        degraded: list[str] = []
        # Durable incident record: the justification must survive a restart (and _load re-asserts
        # the halt from it).
        try:
            with self._sf() as s:
                s.add(EmergencyShutdown(id=incident_id, justification=text, declared_by=set_by))
                s.commit()
        except Exception:
            degraded.append("incident")
        # The fleet flag itself (durable, then audited) — the RUN-02 path. The flag's `reason` is a
        # SHORT IDENTIFIER, never the justification: the pipeline's stage-0 deny copies `kv.reason`
        # into the DECISION record, so free text here would land in a hash-covered audit body — a
        # secret-bearing justification would then trip the AUD-04 gate and downgrade the deny to
        # `control_plane_failure_fail_closed`, losing `emergency_killed`. The justification stays in
        # the emergency_shutdown table; the id points at it.
        try:
            await self._set(_FLEET, "emergency", set_by, _emergency_reason(incident_id))
        except Exception:
            degraded.append("kill_switch")
        # Short identifiers + the incident id only; the justification text stays in the table.
        try:
            await self._audit.append_event(
                "emergency_shutdown",
                {"incident_id": str(incident_id), "scope": "fleet", "set_by": set_by},
            )
        except Exception:
            degraded.append("audit")
        return ShutdownResult(str(incident_id), tuple(degraded))

    async def resume_fleet(self, *, set_by: str) -> None:
        """RUN-07 — explicit operator resume: close EVERY open incident, then clear the fleet halt.

        Closing them ALL is what makes the un-halt safe: the fleet must never come back while a
        declared incident is still open (that used to happen when two incidents overlapped, and the
        `order_by(declared_at)` tie-break on SQLite's one-second timestamps picked arbitrarily).
        """
        _check_set_by(set_by)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self._sf() as s:
            rows = s.scalars(
                select(EmergencyShutdown)
                .where(EmergencyShutdown.resumed_at.is_(None))
                .order_by(EmergencyShutdown.declared_at)
            ).all()
            incident_ids = [str(r.id) for r in rows]
            for row in rows:
                row.resumed_at, row.resumed_by = now, set_by
            if rows:
                s.commit()
        for incident_id in incident_ids or [""]:
            await self._audit.append_event(
                "emergency_resume",
                {"incident_id": incident_id, "scope": "fleet", "set_by": set_by},
            )
        await self._clear(_FLEET, "emergency", set_by)  # durable-first un-halt (existing path)

    def active_incident(self) -> str | None:
        """The open incident id, or None. Read from the table (operator-facing, not the hot path)."""
        with self._sf() as s:
            row = self._open_incident(s)
            return str(row.id) if row is not None else None

    def _require_no_open_incident(self) -> None:
        incident = self.active_incident()
        if incident is not None:
            raise EmergencyActiveError(
                f"emergency incident {incident} is open — resume_fleet is the only way out"
            )

    @staticmethod
    def _open_incident(session) -> EmergencyShutdown | None:
        return session.scalar(
            select(EmergencyShutdown)
            .where(EmergencyShutdown.resumed_at.is_(None))
            .order_by(EmergencyShutdown.declared_at.desc())
            .limit(1)
        )

    def list_active(self) -> list[dict]:
        # The fleet row reports `emergency` while an emergency halt is live: the dashboard renders
        # its per-row action off this scope, and an emergency row must offer RESUME, never the
        # routine "clear fleet" button.
        fleet_scope = "emergency" if self._emergency else "fleet"
        return [
            {"target": t, "scope": fleet_scope if t == _FLEET else "agent", "reason": r}
            for t, r in sorted(self._killed.items())
        ]

    async def _set(self, target, scope, set_by, reason):
        self._killed[target] = reason  # in-memory first (hot path)
        if target == _FLEET:
            self._emergency = scope == "emergency"  # recomputed here, never sticky
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
        if target == _FLEET:
            # resume_fleet closes the incident BEFORE it gets here, so only it can un-halt an
            # emergency; the routine RUN-02 clear path is refused (409) while one is open.
            self._require_no_open_incident()
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
        if target == _FLEET:
            self._emergency = False  # the flag can never outlive the halt it describes
