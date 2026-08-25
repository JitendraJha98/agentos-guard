"""The minimal operator resolve API (API-03) — a FastAPI router over the ApprovalStore.

The API holds no in-process state: it reads and writes the SAME persisted rows
`wait_resolved` polls (D3), so a resolve from this API — in-process today, the
Phase-5 out-of-process service tomorrow — unblocks any parked waiter. Resolution
auditing (`approval_resolved` / `exception_granted` events) happens inside the
store, not here, so every writer is audited identically.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm.exc import StaleDataError

from agentos_controlplane.amendments import AmendmentStore
from agentos_controlplane.approvals import AlreadyResolvedError, ApprovalStore
from agentos_controlplane.auth import make_require_token, resolve_api_token
from agentos_controlplane.circuit_breaker import CircuitBreakerStore
from agentos_controlplane.budget import BudgetLedger
from agentos_controlplane.compliance import export_evidence_bundle, parse_time_bound
from agentos_controlplane.conflicts import ConflictEngine
from agentos_controlplane.economics import CostRecorder
from agentos_controlplane.forensics import EvidenceGraph
from agentos_controlplane.framework_discovery import FrameworkDetector
from agentos_controlplane.graph import AgentGraphStore
from agentos_controlplane.health import HealthStore
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.killswitch import EmergencyActiveError, KillSwitchStore
from agentos_controlplane.merkle import MerkleError, MerkleIntegrityError, MerkleSealer
from agentos_controlplane.registry import Registry
from agentos_controlplane.resources import ConstitutionError, ResourceStore, VersionConflict
from agentos_controlplane.rogue import RogueDetector
from agentos_controlplane.shadow import ShadowAgentStore
from agentos_controlplane.supply_chain import KnownBad, SupplyChainChecker
from agentos_controlplane.validation import ValidationStore
from agentos_controlplane.store.models import ApprovalRequest, GovernanceReview

# TEST-07: the longest `days` window the trend route accepts. Not a tidiness bound —
# `datetime.now() - timedelta(days=999999999)` raises OverflowError, so an unbounded `days` turns
# one query parameter into a 500 on a gated operator route. Ten years is past any plausible
# retention, so anything beyond it is a typo rather than a question.
_MAX_WINDOW_DAYS = 3650
# OBS-04: the same bound, in the unit the health route asks for. Same reasoning — an unbounded
# `hours` raises OverflowError building the timedelta, turning one query parameter into a 500.
_MAX_WINDOW_HOURS = _MAX_WINDOW_DAYS * 24


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


class ProposeAmendmentIn(BaseModel):
    """POL-10 — an amendment proposal. Bounded like every operator/agent input in this module.

    `source` is the WHOLE proposed constitution rather than a diff: a diff would have to be applied
    to whatever the constitution says at ratification time, so what a human ratified would not be
    what took effect.
    """

    model_config = {"extra": "forbid"}

    title: str = Field(min_length=1, max_length=255)
    rationale: str = Field(default="", max_length=4096)
    proposed_by: str = Field(min_length=1, max_length=255)
    source: dict


class RatifyAmendmentIn(BaseModel):
    """POL-10 — the human half. `ratified_by` is required because "human-ratified" is the entire
    claim this transition makes, and an unattributed ratification is not one."""

    model_config = {"extra": "forbid"}

    ratified_by: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=512)


class ResolveAmendmentIn(BaseModel):
    model_config = {"extra": "forbid"}

    status: Literal["rejected", "withdrawn"]
    resolved_by: str = Field(min_length=1, max_length=128)
    note: str | None = Field(default=None, max_length=512)


class EmergencyShutdownRequest(BaseModel):
    """RUN-07 — a fleet emergency stop. Unlike KillRequest's optional `reason`, the justification is
    REQUIRED: `min_length=1` makes an empty one a 422 at the boundary (whitespace-only survives it
    and is refused by the store, also as a 422).

    There is deliberately NO `max_length` on the justification: a last-resort control must never
    refuse to fire because its own explanation was too long (an incident responder pasting a stack
    trace or detector dump). The store truncates what it persists instead.
    """

    model_config = {"extra": "forbid"}

    set_by: str = Field(max_length=128)  # bounded operator input -> 422
    justification: str = Field(min_length=1)


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
        try:
            await kill_store.kill_fleet(set_by=body.set_by, reason=body.reason or "")
        except EmergencyActiveError as exc:  # never relabel a live emergency halt as routine
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {"target": "*", "scope": "fleet", "active": True}

    @router.post("/kill/fleet/clear")
    async def clear_fleet(body: ClearRequest) -> dict:
        try:
            await kill_store.clear_fleet(set_by=body.set_by)
        except EmergencyActiveError as exc:  # the routine clear is not a way out of an emergency
            raise HTTPException(status_code=409, detail=str(exc)) from None
        return {"target": "*", "scope": "fleet", "active": False}

    # RUN-07: the emergency stop rides the SAME fleet flag (so the pipeline halts every agent with
    # no new hot-path code) but requires a justification and records a resumable incident.
    @router.post("/kill/emergency-shutdown")
    async def emergency_shutdown(body: EmergencyShutdownRequest) -> dict:
        try:
            result = await kill_store.emergency_shutdown(
                justification=body.justification, set_by=body.set_by
            )
        except ValueError as exc:  # whitespace-only / secret-shaped set_by -> 422, halts nothing
            raise HTTPException(status_code=422, detail=str(exc)) from None
        except EmergencyActiveError as exc:  # one open incident at a time
            raise HTTPException(status_code=409, detail=str(exc)) from None
        # `degraded` names durability/audit steps that failed while the fleet WAS halted, so the
        # operator can always tell a halted-but-degraded stop from one that never fired.
        return {
            "incident_id": result.incident_id,
            "scope": "fleet",
            "active": True,
            "degraded": list(result.degraded),
        }

    @router.post("/kill/emergency-resume")
    async def emergency_resume(body: ClearRequest) -> dict:
        try:
            await kill_store.resume_fleet(set_by=body.set_by)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        return {"scope": "fleet", "active": False}

    return router


class CircuitResetRequest(BaseModel):
    """RUN-06 — the breaker an operator is clearing, named STRUCTURALLY. `scope` is explicit (never
    inferred from punctuation in the id) and `target` is required for the tool scope only."""

    model_config = {"extra": "forbid"}

    scope: Literal["agent", "tool"]
    agent_id: str = Field(max_length=255)
    target: str = Field(default="", max_length=255)
    set_by: str = Field(max_length=128)  # bounded operator input -> 422


def build_circuit_router(breaker: CircuitBreakerStore) -> APIRouter:
    """RUN-06 — the operator escape hatch: an automatic trip must be VISIBLE and CLEARABLE, exactly
    like the kill switch. Without it a stuck breaker (an agent whose steady-state outcome keeps
    re-opening it) could only be cleared by a code-level call, and a restart deliberately reloads the
    OPEN state."""
    router = APIRouter()

    @router.get("/circuit")
    def list_open_breakers() -> list[dict]:
        return breaker.list_open()

    @router.post("/circuit/reset")
    async def reset_breaker(body: CircuitResetRequest) -> dict:
        await breaker.reset(body.scope, body.agent_id, body.target, set_by=body.set_by)
        return {"scope": body.scope, "agent_id": body.agent_id, "target": body.target,
                "state": "closed"}

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


def build_resource_router(resources: ResourceStore, known_bad: "KnownBad | None" = None) -> APIRouter:
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

    @router.get("/aboms/{agent_id}/supply-chain")
    def scan_supply_chain(agent_id: str) -> list[dict]:
        """SEC-08 — cross-reference the agent's ABOM against the known-bad set."""
        checker = SupplyChainChecker(resources, known_bad)
        return [f.to_dict() for f in checker.scan_agent(agent_id)]

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


def build_inventory_router(
    inventory: InventoryStore,
    detector: FrameworkDetector | None = None,
    shadow: ShadowAgentStore | None = None,
    rogue: RogueDetector | None = None,
    graph: AgentGraphStore | None = None,
    sealer: MerkleSealer | None = None,
    cost: CostRecorder | None = None,
    budget: BudgetLedger | None = None,
    # CMP-06: appended last, like every collaborator before it.
    session_factory=None,
    # TEST-07: likewise appended last.
    validation: ValidationStore | None = None,
    # OBS-04: likewise appended last.
    health: HealthStore | None = None,
    # AUD-09 / OBS-05: likewise appended last.
    forensics: EvidenceGraph | None = None,
    # POL-11: likewise appended last.
    conflicts: ConflictEngine | None = None,
    # POL-10: likewise appended last.
    amendments: AmendmentStore | None = None,
) -> APIRouter:
    """DISC-01/02 — read API over the authoritative agent inventory, plus the DISC-03 framework
    inventory, the DISC-04 shadow-agent sightings, the DISC-05 rogue-agent findings, the DISC-06
    live agent graph, the AUD-06 sealed audit epochs, the ECON-01 cost roll-up, the ECON-02
    budgets and the CMP-06 evidence export: further collaborators on the SAME router rather than
    new ones, so the gated surface over "what is actually out there" — and what happened, what it
    cost, and what it may cost — stays one place."""
    router = APIRouter()

    @router.get("/inventory")
    def list_inventory() -> list[dict]:
        return [vars(d) for d in inventory.list_inventory()]

    @router.get("/inventory/{agent_id}")
    def get_inventory(agent_id: str) -> list[dict]:
        return [vars(d) for d in inventory.get_inventory(agent_id)]

    @router.get("/discovery/frameworks")
    def list_frameworks() -> list[dict]:
        """DISC-03 — the frameworks observed in this deployment, per observing instance."""
        if detector is None:
            raise HTTPException(status_code=404, detail="framework discovery is not wired")
        return detector.list_frameworks()

    @router.post("/discovery/scan")
    async def scan_frameworks() -> list[dict]:
        """DISC-03 — run a discovery pass NOW and return the resulting inventory.

        The WRITE half of the surface: without a caller the table stays empty and the read route
        above is hollow. Deliberately operator-driven (an ops schedule can poll it) and behind the
        same gate — a scan reads `importlib.metadata` and appends to the audit chain, and touches
        the per-action hot path nowhere. Idempotent: an unchanged environment appends no event.
        """
        if detector is None:
            raise HTTPException(status_code=404, detail="framework discovery is not wired")
        await detector.scan()
        return detector.list_frameworks()

    @router.get("/discovery/shadow-agents")
    def list_shadow_agents() -> list[dict]:
        """DISC-04 — actors seen acting without registration.

        Read-only by design: the rows are written by the pipeline's identity short-circuit, which
        is the only place that knows an actor acted unregistered. There is no write route because
        there is no operator action to take here — the action was already denied.
        """
        if shadow is None:
            raise HTTPException(status_code=404, detail="shadow detection is not wired")
        return shadow.list_shadow_agents()

    @router.get("/discovery/rogue-agents")
    def list_rogue_findings(include_resolved: bool = False) -> list[dict]:
        """DISC-05 — registered agents observed outside their declared scope.

        ADVISORY: read-only, and there is no deny route to pair with it. A declaration gap is
        evidence, not proof — a manifest goes stale — so an operator judges it and escalates with
        Phase-9 containment if warranted. Resolved findings are filtered out by default rather
        than deleted; the audit chain keeps the sighting regardless.
        """
        if rogue is None:
            raise HTTPException(status_code=404, detail="rogue detection is not wired")
        return rogue.list_findings(include_resolved=include_resolved)

    @router.get("/discovery/graph")
    def agent_graph() -> dict:
        """DISC-06 — the live agent graph: nodes + edges, delegation lineage included.

        A read over the materialized view only — the rebuild is the `GraphReconciler`'s batch
        pass, so this route adds no materialization work. It is not free of the hot path though:
        the view lives in the database the AuditWriter appends to, which is why the read is
        bounded (`max_nodes` / `max_edges`) rather than serializing every row a prober can create.
        """
        if graph is None:
            raise HTTPException(status_code=404, detail="the agent graph is not wired")
        view = graph.view()
        return {"nodes": view.nodes, "edges": view.edges}

    @router.get("/audit/epochs")
    def list_epochs() -> dict:
        """AUD-06 — the sealed Merkle epochs and their anchor status, newest first."""
        if sealer is None:
            raise HTTPException(status_code=404, detail="merkle sealing is not wired")
        return sealer.list_epochs()

    @router.get("/audit/disclose/{seq}")
    def disclose(seq: int) -> dict:
        """AUD-06 — a partial-disclosure bundle for ONE audit record: the record, its inclusion
        proof, and the anchored root. Gated: which actions an agent took is not public."""
        if sealer is None:
            raise HTTPException(status_code=404, detail="merkle sealing is not wired")
        try:
            return sealer.disclose(seq)
        except MerkleIntegrityError as exc:
            # 409, not 404: the record EXISTS and its evidence does not check out. A 404 here would
            # tell an operator's monitoring that tampering under a sealed root is the same event as
            # asking for a seq that was never written.
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except MerkleError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @router.get("/compliance/export/{framework}")
    def export_bundle(
        framework: str,
        start: str | None = None,
        end: str | None = None,
        verify_chain: bool = False,
    ) -> dict:
        """CMP-06 — the one-click evidence bundle: this framework's mapping, the evidence derived
        for this range, the in-range audit records, and their inclusion proofs against an anchored
        root.

        Gated like the AUD-06 disclosure route beside it: an evidence bundle is a curated disclosure
        of who did what, and deciding who receives it is the operator's call rather than a URL's.

        A 422 means this request cannot produce an HONEST bundle — an unparseable bound, an unknown
        framework, or a store whose contents the mapping refuses to describe. Every one of those is
        answered with a refusal rather than a smaller bundle, because the alternative to a bad range
        is the whole log and the alternative to a bad framework is an empty artifact that reads as
        "no evidence exists". A 409 is the different, louder failure the disclosure route already
        draws: the records exist and their evidence does not check out.

        `verify_chain` is OFF by default here and nowhere else. That pass reads EVERY audit record
        whatever range was asked for, so leaving it on would make one gated GET cost a full
        materialization of the audit table — the memory event `_MAX_RECORDS` exists to prevent,
        reintroduced by the one field it does not bound. Off, the bundle reports its chain fields as
        null with a note saying the pass did not run; the per-record proofs, which are the evidence,
        are unaffected either way.
        """
        if session_factory is None:
            raise HTTPException(status_code=404, detail="evidence export is not wired")
        try:
            return export_evidence_bundle(
                framework,
                session_factory,
                start=parse_time_bound(start),
                end=parse_time_bound(end),
                verify_whole_chain=verify_chain,
            )
        except MerkleIntegrityError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @router.get("/economics/costs")
    def cost_totals(limit: int = 200, offset: int = 0) -> list[dict]:
        """ECON-01 — per-agent cost roll-up. Gated: what an agent costs is commercial information.

        Tokens and dollars are reported side by side with the count of actions each covers, because
        the dollar sum omits every unpriced action and an operator reading it as the whole bill
        would under-count exactly the models they have not supplied rates for.

        Paged for the same reason the per-agent route is: the aggregation reads the WHOLE cost
        table, which grows with every governed action the fleet ever takes, and an unbounded scan
        on a gated read route is still a scan of everything.

        THE `gpu_process_*` FIGURES ARE NOT ADDITIVE ACROSS AGENTS. They are process-level
        observations made while that agent was acting — an upper bound on what it was responsible
        for, never a division of a shared number. One process can host several agents, and the
        INT-07 gateway governs agents that run in no process of its own, so three agents under one
        8 GiB allocation each report `gpu_process_memory_mib_max: 8192`; a dashboard summing that
        column shows 24576 MiB on an 8192 MiB box. `gpu_device_shared_actions` is a COUNT and not a
        quantity for the same reason, taken further: a host-wide GPU figure cannot be attributed to
        one agent at all, so this route reports how often one was observed and never how large it
        was. NULL in any of these means nothing measured a GPU, which is not the same as zero.
        """
        if cost is None:
            raise HTTPException(status_code=404, detail="cost attribution is not wired")
        return cost.totals(limit=max(1, min(limit, 1000)), offset=max(0, offset))

    @router.get("/economics/costs/{agent_id}")
    def cost_for_agent(agent_id: str, limit: int = 200, offset: int = 0) -> list[dict]:
        """ECON-01 — the actions behind one agent's total (the per-ACTION half of the requirement).

        Paged, and the page bound is exposed rather than hidden: the read is capped (the table
        grows with every governed action), so an operator reconciling a busy agent against an
        invoice MUST be able to walk past the first page — otherwise this route and the roll-up
        above report different money for the same agent with nothing to explain the gap.
        """
        if cost is None:
            raise HTTPException(status_code=404, detail="cost attribution is not wired")
        return cost.for_agent(agent_id, limit=max(1, min(limit, 1000)), offset=max(0, offset))

    @router.get("/economics/providers")
    def cost_by_provider(limit: int = 200, offset: int = 0) -> list[dict]:
        """ECON-03 — downstream (non-model) consumption per (agent, provider).

        The provider on each row is the action's own target, so this reports which third-party
        services an agent is actually consuming from facts the PEP recorded — nothing here infers a
        vendor from a hostname, because a guessed vendor lands in a report an operator reconciles
        line-by-line against a real invoice.

        Gated and paged for the same reasons as the cost roll-up: which vendors an agent calls is
        commercial information, and the aggregation reads the whole cost table.
        """
        if cost is None:
            raise HTTPException(status_code=404, detail="cost attribution is not wired")
        return cost.by_provider(limit=max(1, min(limit, 1000)), offset=max(0, offset))

    @router.get("/economics/budgets")
    def list_budgets() -> list[dict]:
        """ECON-02 — the configured spending limits and what has been spent against them.

        Unpaged deliberately, unlike the cost routes above: this table holds one row per agent an
        operator explicitly budgeted, not one per action, so it does not grow with fleet activity.
        """
        if budget is None:
            raise HTTPException(status_code=404, detail="budgets are not wired")
        return budget.list_budgets()

    @router.put("/economics/budgets/{agent_id}")
    def set_budget(agent_id: str, body: dict) -> dict:
        """ECON-02 — set an agent's spending limit.

        Gated like every route on this router, and that gate is load-bearing here rather than
        merely consistent: raising a budget is how an over-budget agent is unblocked, so an agent
        that could call this route would have no budget at all.

        A malformed limit is refused rather than coerced. A negative limit or an unknown period is a
        typo, and a typo that lands as a stored budget is a spend control that looks configured and
        enforces nothing.
        """
        if budget is None:
            raise HTTPException(status_code=404, detail="budgets are not wired")
        try:
            limit = int(body["limit_micro_usd"])
            period = str(body.get("period", "day"))
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422, detail="limit_micro_usd (int) is required"
            ) from exc
        if limit < 0 or period not in {"day", "month", "total"}:
            raise HTTPException(status_code=422, detail="invalid limit or period")
        try:
            budget.set_budget(agent_id, limit_micro_usd=limit, period=period)
        except (StaleDataError, IntegrityError) as exc:
            # 409, not 500 and not a silent overwrite: another operator moved this budget between
            # our read and our write. The caller retries against the value that actually won —
            # a lost raise is an agent that stays blocked, or keeps spending, for no logged reason.
            raise HTTPException(
                status_code=409, detail="budget changed concurrently; re-read and retry"
            ) from exc
        return {"agent_id": agent_id, "limit_micro_usd": limit, "period": period}

    @router.get("/validation/trend")
    def validation_trend(
        agent_id: str | None = None,
        days: int | None = Query(default=None, ge=1, le=_MAX_WINDOW_DAYS),
    ) -> list[dict]:
        """TEST-07 — attack-success-rate per agent and attack class, over a window.

        Gated: how well an agent's guard is holding, broken down by attack class, is a map of where
        to attack it. A read-only route over what the EVALUATE-ONLY harness already produced — it
        starts no run and executes no attack payload (spec D-1).

        Every row carries `total` and `runs` beside the rate, because this is the surface a
        dashboard reads and a dashboard is exactly where a rate gets plotted without its
        denominator. An `attack_success_rate` of null means the window contained runs that tested
        nothing; it is not a zero.

        `days` is validated rather than coerced. A negative window would put `since` in the FUTURE
        and answer 200 with an empty trend — indistinguishable from "this guard has never been
        validated" — and an unbounded one raises OverflowError building the timedelta. Both are 422:
        a window that means something other than what was asked for is worse than a refusal.
        """
        if validation is None:
            raise HTTPException(status_code=404, detail="validation tracking is not wired")
        since = None if days is None else datetime.now(timezone.utc) - timedelta(days=days)
        return validation.trend(agent_id=agent_id, since=since)

    @router.get("/validation/runs/{agent_id}")
    def validation_runs(agent_id: str) -> list[dict]:
        """TEST-07 — the runs behind one agent's trend, newest first, with the attacks that slipped.

        The diagnosis half: a trend that moves tells an operator something broke, and only the run
        and its attack ids tell them what. Identifiers and counts only — never an attack payload.
        """
        if validation is None:
            raise HTTPException(status_code=404, detail="validation tracking is not wired")
        return validation.runs_for(agent_id)

    @router.get("/health/agents")
    def fleet_health(
        hours: int = Query(default=24, ge=1, le=_MAX_WINDOW_HOURS),
    ) -> list[dict]:
        """OBS-04 — per-agent liveness, error rate and circuit-breaker state.

        `last_seen_at` is a FACT, not a verdict: an idle agent and a dead one look identical from
        here and only the operator's own expectation separates them, so nothing on this route
        claims to. A null one means "not within `window_hours`", which is why the window is
        returned beside it — widening `hours` is what tells "idle for a week" apart from "never
        seen at all".

        The failure rate counts EXECUTION failures over EXECUTED actions, and both counts travel
        with it. A governance block is not an error; folding blocks in would make the
        best-governed agent in the fleet look like the worst one, and the fix an operator reaches
        for to make that chart green is to loosen the guard.

        Gated like every route on this router: which agents are quiet, which are being blocked and
        which are held by a breaker is a map of where a fleet is weakest right now.

        `hours` is validated rather than coerced, for the same reasons as the TEST-07 trend's
        `days`. A non-positive window puts its start in the FUTURE and answers 200 with an empty
        fleet — indistinguishable from "every agent is silent" — and an unbounded one raises
        OverflowError building the timedelta. Both are 422.
        """
        if health is None:
            raise HTTPException(status_code=404, detail="health monitoring is not wired")
        return health.fleet(window=timedelta(hours=hours))

    @router.get("/forensics/chain/{action_id}")
    def evidence_chain(action_id: str) -> dict:
        """AUD-09 — the causal chain leading to one action, reconstructed at query time.

        Gated, and the most revealing read in the product: a chain says which agent set which other
        agent in motion. It carries `lineage` for a reason — `identity_verified` authenticates who
        ACTED, not that `parent_action_id` names a real delegation, so this is what the fleet
        CLAIMED about its own causation rather than proof of it. `truncated` says whether a cycle or
        the depth cap cut it short; both are reachable by the agent under investigation.
        """
        if forensics is None:
            raise HTTPException(status_code=404, detail="the evidence graph is not wired")
        return forensics.ancestors(action_id).as_dict()

    @router.get("/forensics/conversation/{conversation_id}")
    def conversation(conversation_id: str) -> dict:
        """OBS-05 — one conversation reconstructed across tools and delegations.

        An unknown id returns an EMPTY chain rather than a 404: during an incident "nothing matched"
        is an answer, while a 404 reads as "this route is wrong".
        """
        if forensics is None:
            raise HTTPException(status_code=404, detail="the evidence graph is not wired")
        return forensics.conversation(conversation_id).as_dict()

    @router.get("/conflicts")
    def list_conflicts() -> dict:
        """POL-11 — emergent capability conflicts across delegation chains.

        FINDINGS, NOT DECISIONS. Nothing here denies an action; the constitution remains the only
        thing that does, and an engine deciding on its own authority would be a second enforcer
        beside the policy floor.

        `unauthorized_lineage` says a claimed delegation edge is NOT CORROBORATED by the ledger —
        weaker than false, because the ledger is in-process and FIFO-evicted, so an absent entry is
        routine rather than evidence the delegation never happened.
        """
        if conflicts is None:
            raise HTTPException(status_code=404, detail="the conflict engine is not wired")
        return conflicts.conflicts()

    @router.get("/conflicts/closure/{action_id}")
    def permission_closure(action_id: str) -> dict:
        """POL-11 — what the chain reaching this action effectively confers.

        Scope narrows at every hop and never widens: a union would let a chain manufacture a
        capability nobody in it held. Carries the same claimed-lineage qualifier the chain does.
        """
        if conflicts is None:
            raise HTTPException(status_code=404, detail="the conflict engine is not wired")
        return conflicts.closure(action_id)

    @router.get("/amendments")
    def list_amendments(status: str | None = None) -> list[dict]:
        """POL-10 — proposed and resolved amendments to the Constitution."""
        if amendments is None:
            raise HTTPException(status_code=404, detail="amendments are not wired")
        return amendments.list_amendments(status=status)

    @router.post("/amendments")
    async def propose_amendment(body: ProposeAmendmentIn) -> dict:
        """POL-10 — propose a change to the Constitution.

        Gated but AGENT-usable: proposing is the half of POL-10 an agent is meant to do. Ratifying is
        not, and it is a separate route for exactly that reason. A proposal is INERT — nothing on the
        decision path reads it — so this route changes no outcome.

        The proposal is compiled before it is stored, so an uncompilable amendment fails here in
        front of the proposer rather than later in front of the ratifier, who cannot fix it.
        """
        if amendments is None:
            raise HTTPException(status_code=404, detail="amendments are not wired")
        try:
            amendment_id = await amendments.propose(
                body.title, body.rationale, body.proposed_by, body.source
            )
        except ConstitutionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": amendment_id, "status": "proposed"}

    @router.post("/amendments/{amendment_id}/ratify")
    async def ratify_amendment(amendment_id: UUID, body: RatifyAmendmentIn) -> dict:
        """POL-10 — the human half, and the ONLY route in this product that changes what the
        Constitution says.

        A system that could ratify its own amendments could rewrite the rules it is governed by, so
        `ratified_by` is required and the previous constitution text is retained rather than replaced.
        """
        if amendments is None:
            raise HTTPException(status_code=404, detail="amendments are not wired")
        try:
            version = await amendments.ratify(amendment_id, body.ratified_by, note=body.note)
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown amendment") from None
        except AlreadyResolvedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except ConstitutionError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": str(amendment_id), "status": "ratified", "constitution_version": version}

    @router.post("/amendments/{amendment_id}/resolve")
    async def resolve_amendment(amendment_id: UUID, body: ResolveAmendmentIn) -> dict:
        """POL-10 — reject or withdraw. Terminal, audited, and constitutionally inert."""
        if amendments is None:
            raise HTTPException(status_code=404, detail="amendments are not wired")
        try:
            await amendments.resolve_without_ratifying(
                amendment_id, body.status, body.resolved_by, note=body.note
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="unknown amendment") from None
        except AlreadyResolvedError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"id": str(amendment_id), "status": body.status}

    @router.get("/constitution/history")
    def constitution_history() -> list[dict]:
        """POL-10 — what the Constitution has said, when, and on whose authority.

        A version with `amendment: null` was an operator's DIRECT write — a different act from a
        ratified amendment, and reported as such so a reader can tell "nobody ratified this" from
        "we lost the record".
        """
        if amendments is None:
            raise HTTPException(status_code=404, detail="amendments are not wired")
        return amendments.constitution_history()

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
    breaker_store: CircuitBreakerStore | None = None,
    api_token: str | None = None,
    registry: Registry | None = None,
    # Also enables the CMP-06 export route (see build_inventory_router): the store IS the audit log
    # the bundle is evidence from, so there is no second collaborator to supply for it.
    session_factory=None,
    dashboard: bool = False,
    # DISC-03: appended LAST so no existing positional caller shifts.
    framework_detector: FrameworkDetector | None = None,
    # DISC-04: likewise appended last.
    shadow_store: ShadowAgentStore | None = None,
    # DISC-05: likewise appended last.
    rogue_detector: RogueDetector | None = None,
    # DISC-06: likewise appended last.
    graph_store: AgentGraphStore | None = None,
    # AUD-06: likewise appended last.
    sealer: MerkleSealer | None = None,
    # ECON-01: likewise appended last.
    cost: CostRecorder | None = None,
    # ECON-02: likewise appended last.
    budget: BudgetLedger | None = None,
    # TEST-07: likewise appended last.
    validation: ValidationStore | None = None,
    # OBS-04: likewise appended last.
    health: HealthStore | None = None,
    # AUD-09 / OBS-05: likewise appended last.
    forensics: EvidenceGraph | None = None,
    # POL-11: likewise appended last.
    conflicts: ConflictEngine | None = None,
    # POL-10: likewise appended last.
    amendments: AmendmentStore | None = None,
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
    # DISC-03: the framework-discovery read route rides this SAME router and gate; absent a
    # framework_detector it answers 404 rather than opening an ungated surface. DISC-04's
    # shadow-agent route does the same — who is probing the fleet unregistered is never public.
    # DISC-05's rogue-agent route likewise: which agents are outside their declared scope is not
    # public information either. DISC-06's graph route most of all — who talks to whom is a map of
    # the fleet's blast radius. AUD-06's disclosure route likewise: an operator chooses what to
    # disclose and to whom, so the bundle is never a public endpoint. ECON-01's cost roll-up too:
    # what an agent spends maps onto which workloads a deployment runs and how heavily. ECON-02's
    # budget routes need the gate most of all — they WRITE, and raising a budget is how an
    # over-budget agent is unblocked, so an ungated one would be a governance bypass. CMP-06's
    # export is the same call as AUD-06's disclosure taken in bulk: a curated statement of who did
    # what, addressed to one recipient the operator chose. TEST-07's validation trend belongs here
    # for the same reason as DISC-06's graph: how well an agent's guard is holding, per attack
    # class, is a map of where to attack it. OBS-04's health read closes the set: which agents are
    # quiet, which are being blocked and which are held by a breaker is a map of where a fleet is
    # weakest right now.
    # Twelve feature surfaces ride the inventory router, so `inventory_store=None` unmounts ALL of
    # them at once — a caller who supplied, say, `graph_store` would get a silent 404 on the very
    # route it was passed for. Supplying a dependent store is unambiguous intent to serve it, so
    # the mismatch is reported rather than swallowed. Passing NOTHING dependent stays silent: a
    # deliberately minimal control plane is a valid composition, not a mistake.
    if inventory_store is None:
        orphaned = sorted(
            name for name, dep in (
                ("framework_detector", framework_detector), ("shadow_store", shadow_store),
                ("rogue_detector", rogue_detector), ("graph_store", graph_store),
                ("sealer", sealer), ("cost", cost), ("budget", budget),
                ("validation", validation), ("health", health), ("forensics", forensics),
                ("conflicts", conflicts), ("amendments", amendments),
            ) if dep is not None
        )
        if orphaned:
            logging.getLogger(__name__).warning(
                "agentos-guard: %s supplied without `inventory_store`, so their routes are NOT "
                "mounted and will answer 404. The inventory router carries every one of these "
                "surfaces — pass `inventory_store` to serve them.",
                ", ".join(orphaned),
            )
    if inventory_store is not None:
        app.include_router(
            build_inventory_router(
                inventory_store,
                framework_detector,
                shadow_store,
                rogue_detector,
                graph_store,
                sealer,
                cost,
                budget,
                session_factory,
                validation,
                health,
                forensics,
                conflicts,
                amendments,
            ),
            dependencies=guard,
        )
    # RUN-06: the breaker router rides the same gate; absent a breaker_store the /circuit routes are
    # not wired (GET /circuit -> 404), keeping existing create_app callers working.
    if breaker_store is not None:
        app.include_router(build_circuit_router(breaker_store), dependencies=guard)
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
