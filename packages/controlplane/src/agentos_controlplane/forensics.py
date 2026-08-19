"""AUD-09 / OBS-05 — the evidence graph: what caused what, reconstructed at query time.

NO SEPARATE GRAPH DATABASE, by requirement and by preference. The lineage is already in the audit
log — Phase 2 (INT-05) persists `parent_action_id` and `conversation_id` in every decision body for
exactly this — so reconstruction reads the same rows the hash chain already covers. A second
datastore would be a second thing to keep consistent with the evidence, and the inconsistency would
be discovered during an incident, which is the worst possible time to learn the graph and the log
disagree.

WHAT A CHAIN PROVES, AND WHAT IT DOES NOT. `identity_verified` authenticates who ACTED. It does not
prove that `parent_action_id` names a real delegation: that field is supplied by the CALLER. So a
reconstructed chain is a record of what agents CLAIMED about their own causation — tamper-evident,
genuinely useful, and not proof of causation.

That distinction is why every answer here carries `lineage` in its payload rather than in this
docstring. The word "evidence" invites an investigator to attribute blame, and attributing blame on
an unverified field is the one mistake a forensic tool must not encourage. Closing it needs the
TRST-04 authority cross-check (Phase 13).

BOUNDED AND CYCLE-SAFE, both load-bearing rather than defensive. `parent_action_id` is caller-supplied,
so A -> B -> A is reachable by a hostile or buggy agent, and an unbounded walk never returns — a
denial of service against the tool an operator reaches for DURING an incident, triggerable by the
agent under investigation. Depth is capped, visited ids are tracked, and truncation is REPORTED: a
chain that stops early without saying so reads as a complete account of what happened.

AN ITERATIVE WALK, NOT A RECURSIVE CTE. SQLite 3.45.3 and Postgres both support `WITH RECURSIVE`, but
`body` is a generic JSON column and the extraction function differs between them — a query that
silently works on the dev backend and breaks on the production target (D-14) is worse than an honest
loop. Depth is capped at 50, so this is at most 50 indexed reads on a forensic path that is not the
hot path.

REDACTION IS INHERITED, NOT RE-APPLIED. AUD-04 redacts at write time, so these bodies are already
redacted. This module adds no un-redacted read path: a conversation reconstruction is the most
sensitive read in the product, and it must not become the way around the redactor.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select

from agentos_controlplane.store.models import AuditRecord

# A delegation chain deeper than this is a runaway or an attack; either way the honest answer is a
# truncated chain that SAYS it is truncated.
_MAX_DEPTH = 50
# One conversation's reconstruction. `conversation_id` is caller-supplied, so an agent chooses how
# much this returns — a gated route is still a route.
_MAX_RECORDS = 2000

LINEAGE_CLAIM = (
    "Lineage here is CLAIMED, not proven. Each record's identity was verified, so who ACTED is "
    "authenticated; `parent_action_id` is supplied by the calling agent, so who CAUSED it is that "
    "agent's own assertion. This is a tamper-evident record of what the fleet claimed about itself, "
    "not proof of causation — a forged edge renders identically to a genuine one. Cross-checking a "
    "claimed edge against delegation authority (TRST-04) is Phase 13."
)


@dataclass(frozen=True)
class Chain:
    """A reconstruction, its bound, and what it is worth.

    `lineage` is not decoration and callers must not strip it: it is the difference between "here is
    what happened" and "here is what the fleet said happened", and only one of those is a thing an
    investigator may act on.
    """

    records: tuple[dict, ...]
    truncated: bool
    depth_limit: int = _MAX_DEPTH
    lineage: str = LINEAGE_CLAIM

    def as_dict(self) -> dict:
        return {
            "records": list(self.records),
            "truncated": self.truncated,
            "depth_limit": self.depth_limit,
            "lineage": self.lineage,
        }


def _row(record: AuditRecord) -> dict:
    """One audit row as the forensic view of it.

    `seq` comes from the COLUMN and the rest from the body, which the record hash covers. The body
    is passed through as-is: it was redacted at write time (AUD-04) and re-deriving anything here
    would mean a second opinion about evidence.
    """
    body = record.body or {}
    return {
        "seq": record.seq,
        "record_hash": record.record_hash,
        "action_id": body.get("action_id"),
        "agent_id": body.get("agent_id"),
        "action_type": body.get("action_type"),
        "outcome": body.get("outcome"),
        "parent_action_id": body.get("parent_action_id"),
        "conversation_id": body.get("conversation_id"),
        "body": body,
    }


class EvidenceGraph:
    """Reconstructs causal chains (AUD-09) and conversations (OBS-05) from the audit log.

    `graph` is the optional Phase-10 `AgentGraphStore`: supplied, `components_for` answers which
    tools/models/MCP servers the agents in a chain touched. Absent, the chain still reconstructs —
    an operator who has not wired the graph should not lose the forensic read.
    """

    def __init__(self, session_factory, graph=None) -> None:
        self._sf = session_factory
        self._graph = graph

    def ancestors(self, action_id: str) -> Chain:
        """The causal chain leading to `action_id`, nearest first.

        Walks `parent_action_id` upward. Terminates on: no parent, a parent no record claims, the
        depth cap, or a REVISIT — and the revisit case is the one that matters, because a cycle is
        something an agent can simply assert.
        """
        records: list[dict] = []
        seen: set[str] = set()
        truncated = False
        current = str(action_id)

        with self._sf() as session:
            while current is not None:
                if current in seen:
                    # A cycle, claimed by whoever wrote parent_action_id. Stopping here is what
                    # keeps this a query rather than a hang, and reporting it is what keeps the
                    # partial answer from reading as the whole one.
                    truncated = True
                    break
                if len(records) >= _MAX_DEPTH:
                    truncated = True
                    break
                seen.add(current)
                row = self._by_action_id(session, current)
                if row is None:
                    break
                records.append(row)
                current = row["parent_action_id"]

        return Chain(records=tuple(records), truncated=truncated)

    def conversation(self, conversation_id: str) -> Chain:
        """Every record in one conversation, in the chain's OWN order.

        Ordered by `seq`, never by `created_at`: `seq` is covered by the record hash, while
        `created_at` is not and has one-second granularity on SQLite. Ordering forensic evidence by
        an unauthenticated, low-resolution column would let two records be presented in an order the
        evidence does not support — and the order is the causal claim a reader takes from it.

        Spans every action type by construction, which is what OBS-05 means by "across tools and
        delegations": the filter is the conversation, not the kind of action.
        """
        with self._sf() as session:
            rows = session.scalars(
                select(AuditRecord)
                .where(AuditRecord.body["conversation_id"].as_string() == str(conversation_id))
                .order_by(AuditRecord.seq.asc())
                .limit(_MAX_RECORDS + 1)
            ).all()

        truncated = len(rows) > _MAX_RECORDS
        return Chain(records=tuple(_row(r) for r in rows[:_MAX_RECORDS]), truncated=truncated)

    def components_for(self, agent_ids) -> list[dict]:
        """Which components the given agents touched, from the Phase-10 graph (DISC-06).

        Returns [] when no graph store was wired — the absence of an optional collaborator is not a
        forensic finding, and an operator without the graph still gets their chain.
        """
        if self._graph is None:
            return []
        wanted = {str(a) for a in agent_ids}
        view = self._graph.view()
        return [
            edge
            for edge in view.edges
            if edge.get("src", {}).get("name") in wanted
        ]

    @staticmethod
    def _by_action_id(session, action_id: str):
        record = session.scalars(
            select(AuditRecord)
            .where(AuditRecord.body["action_id"].as_string() == action_id)
            .order_by(AuditRecord.seq.asc())
            .limit(1)
        ).first()
        return None if record is None else _row(record)
