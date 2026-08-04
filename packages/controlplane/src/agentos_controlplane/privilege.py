"""RUN-04 — privilege rings. Sensitive targets require a capability tier; an agent holding a lower
ring is denied before the action runs.

Hot-path shape mirrors RUN-01/02's KillSwitchStore: the per-action lookup is IN-MEMORY (no DB read),
backed by tables for durability and reloaded at construction. Administrative changes are audited
(`privilege_ring_set`, short identifiers only). Writes are DURABLE-FIRST: the row is committed
before the in-memory map moves, so a failed persist can never leave a target quietly LESS restricted
than the operator believes (fail-toward-contained, the Slice-4e lesson). The map is then updated
IMMEDIATELY after the commit and BEFORE the audit append, so memory always equals the committed
table in BOTH directions — a raising audit write (AUD-04 secret gate, unknown kind, audit DB
failure) can only lose the event, never leave the hot path LOOSER than the table (a tightening that
the gate does not enforce, or an agent whose revoked tier survives in the live process).

Ring semantics across a delegation chain: the ring an action is checked against may be supplied by
the caller (`check(..., held_ring=...)`) as the chain MINIMUM, so a low-ring principal cannot reach a
gated target through a high-ring delegate. The pipeline passes the resolved TRST-04 authority's ring.

Registered-sensitivity model: only registered targets are gated; an unregistered target is ring 0 and
remains governed by the constitution floor. That keeps this stage additive — wiring it cannot break an
existing deployment.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from agentos_controlplane.store.models import AgentPrivilege, TargetPrivilege


@dataclass(frozen=True)
class PrivilegeVerdict:
    """Returned ONLY when the action is refused: the agent holds less than the target requires."""

    target: str
    required: int
    held: int


class PrivilegeRingStore:
    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._agent_rings: dict[str, int] = {}
        self._target_rings: dict[str, int] = {}
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(AgentPrivilege)).all():
                self._agent_rings[row.agent_id] = row.ring
            for row in s.scalars(select(TargetPrivilege)).all():
                self._target_rings[row.target] = row.required_ring

    # ---- hot path (in-memory only) ----
    def ring_for(self, agent_id: str) -> int:
        return self._agent_rings.get(agent_id, 0)

    def required_ring(self, target: str) -> int:
        return self._target_rings.get(target, 0)

    def check(
        self, agent_id: str, target: str, *, held_ring: int | None = None
    ) -> PrivilegeVerdict | None:
        """None == permitted. A verdict == refused (held ring < target requirement).

        `held_ring` overrides the agent's own tier with an ALREADY-CAPPED one (the delegation
        chain minimum). None == use the agent's own ring.
        """
        required = self._target_rings.get(target, 0)
        if required <= 0:
            return None  # unregistered / ungated target
        held = self._agent_rings.get(agent_id, 0) if held_ring is None else held_ring
        if held >= required:
            return None
        return PrivilegeVerdict(target=target, required=required, held=held)

    # ---- administration (audited) ----
    async def set_agent_ring(self, agent_id: str, ring: int, *, set_by: str) -> None:
        await self._set("agent", agent_id, ring, set_by)

    async def set_target_ring(self, target: str, required_ring: int, *, set_by: str) -> None:
        await self._set("target", target, required_ring, set_by)

    async def _set(self, scope: str, key: str, ring: int, set_by: str) -> None:
        if ring < 0:
            raise ValueError("privilege ring must be >= 0")
        # DURABLE FIRST, then the in-memory cache IN THE SAME BREATH as the commit: a failed persist
        # must never leave the hot path believing a LOWER requirement (or a HIGHER agent tier) than
        # the table records — in EITHER direction. Updating memory after the audit append instead
        # would break exactly that on a TIGHTENING whose audit write raises (committed row, stale
        # looser cache). Directional discipline mirrors KillSwitchStore._set/_clear.
        with self._sf() as s:
            if scope == "agent":
                row = s.get(AgentPrivilege, key)
                if row is None:
                    s.add(AgentPrivilege(agent_id=key, ring=ring, set_by=set_by))
                else:
                    row.ring, row.set_by = ring, set_by
            else:
                row = s.get(TargetPrivilege, key)
                if row is None:
                    s.add(TargetPrivilege(target=key, required_ring=ring, set_by=set_by))
                else:
                    row.required_ring, row.set_by = ring, set_by
            s.commit()
            if scope == "agent":
                self._agent_rings[key] = ring
            else:
                self._target_rings[key] = ring
        # `scope` (not `kind`) names the discriminator: `kind` is a reserved chain field the audit
        # writer computes itself, so a body carrying it is rejected fail-closed. Short identifiers
        # only — same discipline as kill_switch_set. A raising append leaves the change durable and
        # enforced but UNRECORDED; the exception propagates to the operator.
        await self._audit.append_event(
            "privilege_ring_set", {"scope": scope, "key": key, "ring": ring, "set_by": set_by}
        )

    def list_rings(self) -> dict[str, dict[str, int]]:
        return {
            "agents": dict(sorted(self._agent_rings.items())),
            "targets": dict(sorted(self._target_rings.items())),
        }
