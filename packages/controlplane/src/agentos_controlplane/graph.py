"""DISC-06 — the live agent graph.

Nodes are agents and the components they use; edges are `uses` (agent -> component) and `delegates`
(agent -> agent, lineage derived from `parent_action_id`). This is the "what talks to what" map the
Phase-13 permission calculus will walk to compute transitive permissions.

THE DELEGATION EDGE IS THE POINT. The audit body names the parent ACTION, never the parent AGENT, so
an edge exists only because this pass resolves who performed that parent action. Two consequences
are deliberate, not oversights:
  * a `parent_action_id` pointing at an action by the SAME agent is that agent's OWN lineage and
    draws no edge — otherwise every multi-step agent would look like a delegation hub;
  * a parent this pass cannot resolve is SKIPPED. This runs on a schedule against a log that may be
    truncated or partially retained, and a crash here would rot every derived view behind it.

## Only VERIFIED identity draws anything

`agent_id`, `action_id` and `parent_action_id` are all client-settable, and the pipeline's identity
short-circuit audits an unknown caller's action VERBATIM before denying it (runner.py's own comment:
"action.agent_id is attacker-chosen and goes raw into the hash-covered decision body"). Taken as
fact, that let a caller holding no credential name a real agent as its delegator and serve itself a
capability map it never earned. So a record is evidence only if the identity stage itself said so —
a reason with stage `identity` and code `identity_verified`. Fail-closed: a record that predates the
reason, a kill-switch deny (which runs AHEAD of identity) and a fail-safe record all draw nothing.

## Hostile identifiers must not bloat, block or ABORT the pass

`graph_node.name` is String(255). SQLite does not enforce that; Postgres — the production target
(D-14) — raises StringDataRightTruncation, which aborts materialize() and, because the same audit
row is re-read on every pass, never converges again. Names are therefore bounded + sanitized at the
source with DISC-05's `bounded` (a digest travels with anything it had to alter, so two ids can
never merge into one node), and the DISTINCT-agent dimension is capped like DISC-04's shadow store:
past `max_nodes` a new id folds into the single `<overflow>` bucket, so an id-rotating prober cannot
grow the table without limit. The read is bounded too — `view()` materializes every row it selects
into ONE JSON response.

## Incremental by construction

This pass shares its database, and therefore its write lock, with the AuditWriter. Re-reading the
whole audit log inside one long write transaction stalled and then FAILED concurrent audit appends,
and a failed append drives the pipeline's fail-safe — observation degrading enforcement, fleet-wide,
as the steady state. A persisted watermark (`graph_watermark`) means a sweep costs O(new records);
records are consumed in seq-ordered batches, each its own short transaction; and the upserts are
deduped per batch, so the statement count is O(distinct nodes+edges), not O(records).

Incrementalism costs one thing, and it is bounded deliberately: lineage is resolved through an
in-process cache of recent action_id -> agent_id rather than by rebuilding the whole map each pass.
A parent audited before the cache existed is simply unresolvable, which is the documented skip
above. Ordering is safe — a parent action's decision is appended before the child action exists.

## SOURCE OF TRUTH AND ITS LIMIT

The audit body carries action_id / agent_id / action_type / parent_action_id, but NOT `target` —
redaction deliberately keeps tool names out of the hash-covered body. So audit-derived component
nodes are CAPABILITY-CLASS nodes (tool, model, mcp, memory), and per-NAME component nodes come from
the InventoryStore's DECLARED rows, which do hold names. That fidelity difference is recorded on the
row (`source`, with inventory's own precedence declared > observed > observed_class, never
downgraded) rather than left implicit: a placeholder named 'tool' is otherwise byte-identical to a
genuine component named 'tool', and collapsing exactly that distinction is what made DISC-05 flag
every declaring agent in the fleet. Only DECLARED inventory rows are projected — the `observed_class`
rows are this same audit evidence, minus the identity filter, and counting them again double-counted
every edge.

This is a BATCH pass, never the per-action hot path.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentos_controlplane.inventory import DECLARED, OBSERVED, OBSERVED_CLASS
from agentos_controlplane.rogue import bounded
from agentos_controlplane.shadow import OVERFLOW_ID
from agentos_controlplane.store.models import AuditRecord, GraphEdge, GraphNode, GraphWatermark

# action_type -> the capability class it exercises (audit bodies carry no target).
_CLASS_BY_ACTION = {
    "tool_call": "tool",
    "model_invocation": "model",
    "mcp_call": "mcp",
    "memory_access": "memory",
    "delegation": "delegation",
}

_AGENT = "agent"
# The `graph_node` / `graph_edge` column widths — bounded at the source, as in rogue.py.
_MAX_NAME = 255
_MAX_KIND = 32
# How many DISTINCT agent nodes exist before the rest fold into one bucket, and how much ONE read
# may return. Sized like `ShadowAgentStore._max_rows`.
_MAX_NODES = 1000
_MAX_EDGES = 5000
# Audit records consumed per write transaction: the lock the AuditWriter needs is held in short
# bursts rather than for the whole sweep.
_BATCH = 500
# Recent action_id -> agent_id, so a child can still resolve its delegator once the pass stopped
# rebuilding the full map. Bounded: the map is keyed by caller-chosen ids.
_LINEAGE = 10_000
# The single `graph_watermark` row.
WATERMARK_ID = "graph"

# Fidelity precedence, mirroring `inventory._RANK` — a row is never downgraded.
_RANK = {OBSERVED_CLASS: 0, OBSERVED: 1, DECLARED: 2}


@dataclass(frozen=True)
class GraphView:
    nodes: list[dict]
    edges: list[dict]


def _verified(body: dict) -> bool:
    """Did the identity stage itself vouch for this record's `agent_id`?

    The pipeline appends this reason once identity has verified and BEFORE any later stage can
    deny, so it means "this caller is who it says", not "this action was allowed".
    """
    reasons = body.get("reasons")
    if not isinstance(reasons, list):
        return False
    return any(
        isinstance(r, dict)
        and r.get("stage") == "identity"
        and r.get("code") == "identity_verified"
        for r in reasons
    )


def _add_node(acc: dict, kind: str, name: str, source: str) -> None:
    key = (kind, name)
    current = acc.get(key)
    if current is None or _RANK[source] > _RANK[current]:
        acc[key] = source


def _add_edge(acc: dict, key: tuple, source: str, count: int) -> None:
    current, seen = acc.get(key, (source, 0))
    acc[key] = (source if _RANK[source] > _RANK[current] else current, seen + count)


class AgentGraphStore:
    def __init__(
        self,
        session_factory,
        *,
        inventory=None,
        max_nodes: int = _MAX_NODES,
        max_edges: int = _MAX_EDGES,
        batch: int = _BATCH,
    ) -> None:
        self._sf = session_factory
        self._inventory = inventory
        self._max_nodes = max_nodes
        self._max_edges = max_edges
        self._batch = batch
        self._actor: dict[str, str] = {}

    def materialize(self) -> int:
        """Consume the audit records past the watermark (+ the declared inventory when wired).
        Returns the number of NEW nodes/edges, so a converged graph reports 0 and the reconciler's
        "changed" count stays meaningful.

        Idempotent in the strong sense: a re-run over unchanged evidence adds no rows AND bumps no
        counter — each audit record is consumed exactly once, so `observations` counts actions.
        """
        # Read the inventory BEFORE opening a graph session. `list_inventory()` opens its OWN
        # session, and a second session over a shared connection (SQLite/StaticPool, which is how
        # the reconciler's worker thread reaches this store) closes by rolling back the connection's
        # transaction — discarding this pass's already-flushed rows. Read first, write after.
        declared = (
            [c for c in self._inventory.list_inventory() if c.source == DECLARED]
            if self._inventory is not None
            else []
        )
        # The manifest goes FIRST: it is the authoritative half, so it takes the node budget ahead
        # of any claimed id, and the audit half that follows must then be unable to downgrade what
        # it finds (the `_RANK` rule) rather than merely happening to run before a repair.
        applied = self._project(declared)
        while True:
            batch, drained = self._consume()
            applied += batch
            if drained:
                break
        return applied

    def view(self) -> GraphView:
        """The materialized graph, BOUNDED at the query — the route serializes every row it selects
        into one JSON response, and an unauthenticated prober is one of the levers that grows the
        table (the shadow / rogue / dashboard `.limit()` precedent). Edges are ordered by
        `observations` so a truncated read keeps the hot paths rather than an arbitrary slice."""
        with self._sf() as s:
            nodes = [
                {"kind": n.kind, "name": n.name, "source": n.source}
                for n in s.scalars(
                    select(GraphNode)
                    .order_by(GraphNode.kind, GraphNode.name)
                    .limit(self._max_nodes)
                ).all()
            ]
            edges = [
                {
                    "src": {"kind": e.src_kind, "name": e.src_name},
                    "dst": {"kind": e.dst_kind, "name": e.dst_name},
                    "relation": e.relation,
                    "observations": e.observations,
                    "source": e.source,
                }
                for e in s.scalars(
                    select(GraphEdge)
                    .order_by(
                        GraphEdge.observations.desc(),
                        GraphEdge.relation,
                        GraphEdge.src_name,
                        GraphEdge.dst_name,
                    )
                    .limit(self._max_edges)
                ).all()
            ]
            return GraphView(nodes=nodes, edges=edges)

    # ----------------------------------------------------------------- the audit half

    def _consume(self) -> tuple[int, bool]:
        """One batch: read past the watermark, apply it, advance the watermark, commit. Returns
        (new rows, whether the log is drained). The watermark advances even when every record in
        the batch was filtered out, so the pass always makes progress."""
        with self._sf() as s:
            rows = s.scalars(
                select(AuditRecord)
                .where(AuditRecord.seq > self._watermark(s))
                .order_by(AuditRecord.seq)
                .limit(self._batch)
            ).all()
            if not rows:
                return 0, True
            decisions: list[tuple[str, str, str | None]] = []
            for r in rows:
                body = r.body
                if "kind" in body:  # an event record (an observation), not a decision
                    continue
                if not _verified(body):  # claimed identity is not identity
                    continue
                agent_id = body.get("agent_id")
                action_type = body.get("action_type")
                action_id = body.get("action_id")
                if not agent_id or not action_type:
                    continue
                if action_id:
                    self._remember(self._key(action_id), agent_id)
                decisions.append((agent_id, action_type, body.get("parent_action_id")))
            applied = self._apply(s, decisions)
            self._advance(s, rows[-1].seq)
            s.commit()
            return applied, len(rows) < self._batch

    def _apply(self, s: Session, decisions: list[tuple[str, str, str | None]]) -> int:
        """Project one batch of decisions onto nodes and edges — deduped first, so the write is
        one statement per DISTINCT node/edge rather than per record, and `observations` grows by
        the number of records that actually named the edge."""
        if not decisions:
            return 0
        work: list[tuple[str, str | None, str | None]] = []
        raw_agents: set[str] = set()
        for agent_id, action_type, parent in decisions:
            raw_agents.add(agent_id)
            delegator = self._actor.get(self._key(parent)) if parent else None
            if delegator == agent_id:  # own lineage, not delegation
                delegator = None
            if delegator:
                raw_agents.add(delegator)
            work.append((agent_id, _CLASS_BY_ACTION.get(action_type), delegator))

        names = self._agent_names(s, raw_agents)
        nodes: dict[tuple[str, str], str] = {}
        edges: dict[tuple, tuple[str, int]] = {}
        for agent_id, klass, delegator in work:
            actor = names[agent_id]
            _add_node(nodes, _AGENT, actor, OBSERVED)
            if klass:
                _add_node(nodes, klass, klass, OBSERVED_CLASS)
                _add_edge(edges, (_AGENT, actor, klass, klass, "uses"), OBSERVED_CLASS, 1)
            # Re-checked after resolution: two distinct ids can both fold into the overflow
            # bucket, and a self-edge there would invent a delegation.
            if delegator and names[delegator] != actor:
                _add_node(nodes, _AGENT, names[delegator], OBSERVED)
                _add_edge(
                    edges, (_AGENT, names[delegator], _AGENT, actor, "delegates"), OBSERVED, 1
                )
        return self._flush(s, nodes, edges)

    # ----------------------------------------------------------------- the inventory half

    def _project(self, declared) -> int:
        """The per-NAME half the audit body cannot supply, in its own short transaction. DECLARED
        rows only (see the module docstring), and a declaration is not activity — the edge is
        created with zero observations so "declared but never exercised" stays visible."""
        if not declared:
            return 0
        with self._sf() as s:
            names = self._agent_names(s, {c.agent_id for c in declared})
            nodes: dict[tuple[str, str], str] = {}
            edges: dict[tuple, tuple[str, int]] = {}
            for c in declared:
                actor = names[c.agent_id]
                kind, name = bounded(c.kind, _MAX_KIND), bounded(c.name, _MAX_NAME)
                _add_node(nodes, _AGENT, actor, DECLARED)
                _add_node(nodes, kind, name, DECLARED)
                _add_edge(edges, (_AGENT, actor, kind, name, "uses"), DECLARED, 0)
            applied = self._flush(s, nodes, edges)
            s.commit()
            return applied

    # ----------------------------------------------------------------- shared machinery

    def _agent_names(self, s: Session, raw_ids: set[str]) -> dict[str, str]:
        """Raw agent_id -> the node name it is recorded under: bounded + sanitized, or the
        `<overflow>` bucket once `max_nodes` distinct agents already exist.

        `bounded` gives a distinct raw id a distinct name (an altered one carries a digest of the
        full original), so the budget can never be spent twice on the same agent. Sorted, so which
        ids win the last slots is deterministic rather than dict-order.
        """
        room: int | None = None
        resolved: dict[str, str] = {}
        for raw in sorted(raw_ids):
            name = bounded(raw, _MAX_NAME)
            if (
                s.scalar(
                    select(GraphNode.id).where(GraphNode.kind == _AGENT, GraphNode.name == name)
                )
                is not None
            ):
                resolved[raw] = name
                continue
            if room is None:
                room = self._max_nodes - (
                    s.scalar(
                        select(func.count()).select_from(GraphNode).where(GraphNode.kind == _AGENT)
                    )
                    or 0
                )
            if room > 0:
                room -= 1
                resolved[raw] = name
            else:
                resolved[raw] = OVERFLOW_ID
        return resolved

    def _flush(self, s: Session, nodes: dict, edges: dict) -> int:
        applied = 0
        for (kind, name), source in nodes.items():
            applied += self._upsert_node(s, kind, name, source)
        for key, (source, count) in edges.items():
            applied += self._upsert_edge(s, key, source, count)
        return applied

    @staticmethod
    def _key(action_id) -> str:
        """`action_id` / `parent_action_id` are client-set, so the cache key is bounded too — a
        real id is a 36-char UUID, and truncation is lossless for every one of them."""
        return str(action_id)[:_MAX_NAME]

    def _remember(self, action_id: str, agent_id: str) -> None:
        """Bounded lineage cache — oldest entry out. Only VERIFIED actors are remembered, so an
        unverified parent can never be resolved into a delegator."""
        self._actor[action_id] = agent_id
        if len(self._actor) > _LINEAGE:
            del self._actor[next(iter(self._actor))]

    @staticmethod
    def _watermark(s: Session) -> int:
        row = s.get(GraphWatermark, WATERMARK_ID)
        # -1, not 0: the audit chain's genesis record is seq 0.
        return row.seq if row is not None else -1

    @staticmethod
    def _advance(s: Session, seq: int) -> None:
        row = s.get(GraphWatermark, WATERMARK_ID)
        if row is None:
            s.add(GraphWatermark(id=WATERMARK_ID, seq=seq))
        else:
            row.seq = seq

    @staticmethod
    def _upsert_node(s: Session, kind: str, name: str, source: str) -> int:
        row = s.scalar(select(GraphNode).where(GraphNode.kind == kind, GraphNode.name == name))
        if row is None:
            s.add(GraphNode(id=uuid4(), kind=kind, name=name, source=source))
            return 1
        if _RANK[source] > _RANK.get(row.source, -1):
            row.source = source
        return 0

    @staticmethod
    def _upsert_edge(s: Session, key: tuple, source: str, count: int) -> int:
        sk, sn, dk, dn, relation = key
        row = s.scalar(
            select(GraphEdge).where(
                GraphEdge.src_kind == sk,
                GraphEdge.src_name == sn,
                GraphEdge.dst_kind == dk,
                GraphEdge.dst_name == dn,
                GraphEdge.relation == relation,
            )
        )
        if row is None:
            s.add(
                GraphEdge(
                    id=uuid4(),
                    src_kind=sk,
                    src_name=sn,
                    dst_kind=dk,
                    dst_name=dn,
                    relation=relation,
                    observations=count,
                    source=source,
                )
            )
            return 1
        row.observations += count
        if _RANK[source] > _RANK.get(row.source, -1):
            row.source = source
        return 0
