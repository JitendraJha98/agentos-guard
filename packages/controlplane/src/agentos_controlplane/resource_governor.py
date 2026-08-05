"""RUN-05 — the concrete ResourceGovernor: per-agent execution budgets.

Hot-path shape mirrors `PrivilegeRingStore`/`KillSwitchStore`: `limits_for` is called on EVERY
executed action, so it is an IN-MEMORY lookup; the table is durability and reloads at construction.
An agent with no row returns None, which is what lets the SDK take its zero-overhead path (no
tracemalloc, no wait_for) for the overwhelmingly common unbudgeted case.

Administration commits FIRST, then updates the cache, THEN audits — the 9b review lesson. A failed
persist must never leave the hot path believing a MORE generous budget than the table records, and
updating the cache only after the audit append would break exactly that on a TIGHTENING whose audit
write raises: committed row, stale unbudgeted cache, a silently disabled control.

What the stored budget actually GUARANTEES differs per dimension and is documented on the SDK's
`GovernanceResourceExceeded`: `network` prevents (the handler never runs), a `wall_s` overrun is
cancelled only when the cancellation can land and is otherwise DETECTED AFTER COMPLETION, and
`memory_mb` is detected at completion (and skipped when governed calls overlap). This module persists
and audits the budget; it does not upgrade those guarantees.
"""

from __future__ import annotations

import math

from sqlalchemy import select

from agentos_contract import AgentAction, Decision
from agentos_sdk.enforce import ResourceLimits

from agentos_controlplane.store.models import ResourceLimit

_NETWORK_MODES = frozenset({"allow", "deny"})


class ResourceGovernorStore:
    """Satisfies the SDK's `ResourceGovernor` Protocol structurally (no SDK import at the seam)."""

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit
        self._limits: dict[str, ResourceLimits] = {}
        self._load()

    def _load(self) -> None:
        with self._sf() as s:
            for row in s.scalars(select(ResourceLimit)).all():
                self._limits[row.agent_id] = ResourceLimits(
                    wall_s=row.wall_s, memory_mb=row.memory_mb, network=row.network
                )

    # ---- hot path (in-memory only) ----
    def limits_for(self, agent_id: str) -> ResourceLimits | None:
        """None == unbudgeted, and the SDK skips the whole measurement path for it."""
        return self._limits.get(agent_id)

    # ---- administration (audited) ----
    async def set_limits(
        self,
        agent_id: str,
        *,
        wall_s: float | None = None,
        memory_mb: float | None = None,
        network: str = "allow",
        set_by: str,
    ) -> None:
        """Assign `agent_id`'s budget. This REPLACES THE WHOLE BUDGET: every omitted dimension is
        CLEARED, so `set_limits(a, wall_s=2.0, set_by=...)` after a wall+memory+deny assignment leaves
        `memory_mb` NULL and `network` back at "allow" — tightening one dimension this way relaxes the
        others. Pass every dimension you want enforced. The audit event records the whole replaced
        budget, so the clearing is visible in the evidence.
        """
        if network not in _NETWORK_MODES:
            raise ValueError(f"network must be one of {sorted(_NETWORK_MODES)}, got {network!r}")
        # A non-positive or non-finite budget is never a legitimate assignment: wall_s=0 would refuse
        # every call, memory_mb=0 would flag every one, `inf` silently DISABLES the dimension, and
        # `nan` both disables the comparison and makes the event loop's timer raise a bare ValueError
        # (not a GovernanceDenied — it escapes every governed catch site). A typo must not become an
        # outage or a silently disabled control.
        if wall_s is not None and (not math.isfinite(wall_s) or wall_s <= 0):
            raise ValueError("wall_s must be a finite number > 0 when set")
        if memory_mb is not None and (not math.isfinite(memory_mb) or memory_mb <= 0):
            raise ValueError("memory_mb must be a finite number > 0 when set")
        # DURABLE FIRST, then the cache IN THE SAME BREATH as the commit, then the audit append.
        with self._sf() as s:
            row = s.get(ResourceLimit, agent_id)
            if row is None:
                s.add(
                    ResourceLimit(
                        agent_id=agent_id,
                        wall_s=wall_s,
                        memory_mb=memory_mb,
                        network=network,
                        set_by=set_by,
                    )
                )
            else:
                row.wall_s, row.memory_mb, row.network, row.set_by = (
                    wall_s,
                    memory_mb,
                    network,
                    set_by,
                )
            s.commit()
            self._limits[agent_id] = ResourceLimits(
                wall_s=wall_s, memory_mb=memory_mb, network=network
            )
        # Short identifiers + numbers only, and no key named `kind`/`seq`/`prev_hash` — those are
        # reserved chain fields the writer computes itself, so a body carrying one is rejected
        # fail-closed. A raising append leaves the budget durable and enforced but UNRECORDED; the
        # exception propagates to the operator.
        await self._audit.append_event(
            "resource_limit_set",
            {
                "agent_id": agent_id,
                "wall_s": wall_s,
                "memory_mb": memory_mb,
                "network": network,
                "set_by": set_by,
            },
        )

    async def record_breach(
        self, action: AgentAction, decision: Decision, *, limit: str, budget: float, observed: float
    ) -> None:
        """Audit one budget violation. Short identifiers + numbers ONLY — no target, no payload, so
        the AUD-04 secret gate can never block a breach from being recorded (the same discipline as
        `kill_switch_set`). The redacted detail belongs to the DECISION record."""
        await self._audit.append_event(
            "resource_limit_exceeded",
            {
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "action_type": action.type.value,
                "limit": limit,
                "budget": budget,
                "observed": round(float(observed), 4),
            },
        )
