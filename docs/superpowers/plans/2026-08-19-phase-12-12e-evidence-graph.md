# Phase 12 · Slice 12e — Evidence Graph & Conversation Tracing (AUD-09, OBS-05) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with `-m "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"`. TDD per task, one
> commit each. Gates green at every commit. Run the WHOLE suite before committing.

**Goal (AUD-09, OBS-05):** Reconstruct causal chains and full conversations **at query time**, by
joining the audit log to the Phase-10 agent graph — with no separate graph database.

**Architecture:** A depth-bounded, cycle-safe recursive CTE over `audit_record`, walking
`parent_action_id` (persisted in the body since Phase 2, INT-05) and grouping on `conversation_id`.
Verified available on this machine's SQLite 3.45.3 and on the Postgres production target, so one
query serves both.

**Tech Stack:** SQLAlchemy 2.0 Core (`WITH RECURSIVE`), FastAPI, pytest. No new dependency, no
migration — every column this reads already exists.

## THE HONESTY REQUIREMENT (spec D-2)

Phase 10's DISC-06 established that `identity_verified` authenticates who **acted** — it does not
prove that `parent_action_id` names a real delegation. The actor half is closed; the lineage half is
**claimed by the caller**.

AUD-09 calls its output *evidence*, and that raises the stakes rather than lowering them. An
investigator reading a reconstructed chain as proven causation would attribute an action to an agent
on the strength of a field that agent's own caller supplied — in exactly the setting where being
wrong is most costly. So **every chain this module returns carries the qualifier in its payload**, not
in our documentation. Closing the gap needs the TRST-04 authority cross-check (Phase 13), named as
such.

## The two structural hazards, neither hypothetical

- **Cycles.** `parent_action_id` is caller-supplied, so A→B→A is reachable by a hostile or buggy
  agent. An unbounded recursive CTE on a cycle **does not terminate**; it is a denial of service
  against the forensic tool you reach for during an incident.
- **Depth.** A long legitimate delegation chain is unbounded by nature.

Both are capped, and truncation is **reported** rather than silent — the same no-silent-caps rule the
DISC-04/05/06 stores follow.

## File structure
- Create `.../agentos_controlplane/forensics.py` — `EvidenceGraph`.
- Modify `.../api.py` — two gated read routes.
- Tests: `tests/unit/test_forensics.py`, `tests/integration/test_forensics_api.py`.

---

### Task 1: `EvidenceGraph` — the bounded, cycle-safe walk

**Files:** create `.../agentos_controlplane/forensics.py`; test `tests/unit/test_forensics.py`.

```python
"""AUD-09 / OBS-05 — the evidence graph: what caused what, reconstructed at query time.

NO SEPARATE GRAPH DATABASE, by requirement and by preference. The lineage is already in the audit
log — `parent_action_id` and `conversation_id` have been persisted in every decision body since
Phase 2 (INT-05) — so a recursive CTE answers the question against the same rows the hash chain
already covers. A second datastore would mean a second thing to keep consistent with the evidence,
and an inconsistency between them would be discovered during an incident.

WHAT A CHAIN PROVES, AND WHAT IT DOES NOT. `identity_verified` authenticates who ACTED. It does not
prove that `parent_action_id` names a real delegation: that field is supplied by the caller, so a
reconstructed chain is a record of what agents CLAIMED about their own causation. That is genuinely
useful — it is what the fleet believed about itself, hash-chained and tamper-evident — and it is not
proof of causation. This module says so on every answer it returns, because the word "evidence"
invites an investigator to attribute blame, and attributing blame on an unverified field is the one
mistake a forensic tool must not encourage. Closing it needs the TRST-04 authority cross-check
(Phase 13).

BOUNDED AND CYCLE-SAFE, both load-bearing. `parent_action_id` is caller-supplied, so A -> B -> A is
reachable, and an unbounded recursive CTE on a cycle never returns — a denial of service against the
tool you reach for during an incident, triggerable by the agent under investigation. Depth is capped
and visited ids are tracked; truncation is reported rather than silent, because a chain that stops
early without saying so reads as a complete account of what happened.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select

from agentos_controlplane.store.models import AuditRecord

# A delegation chain deeper than this is either a runaway or an attack; either way the honest answer
# is a truncated chain that SAYS it is truncated.
_MAX_DEPTH = 50
# One conversation's reconstruction. Bounded for the same reason every other read here is: a gated
# route is still a route, and `conversation_id` is caller-supplied.
_MAX_RECORDS = 2000

LINEAGE_CLAIM = (
    "Lineage here is CLAIMED, not proven. Each record's identity was verified, so who ACTED is "
    "authenticated; `parent_action_id` is supplied by the calling agent, so who CAUSED it is that "
    "agent's own assertion. This is a tamper-evident record of what the fleet claimed about itself, "
    "not proof of causation. Cross-checking a claimed edge against delegation authority (TRST-04) "
    "is Phase 13."
)


@dataclass(frozen=True)
class Chain:
    """A causal chain, its bound, and what it is worth."""

    records: tuple[dict, ...]
    truncated: bool
    depth_limit: int
    lineage: str = LINEAGE_CLAIM
```

`EvidenceGraph(session_factory, graph=None)` exposes:

- **`ancestors(action_id)`** — walk `parent_action_id` upward from one action. Implemented as a
  recursive CTE bounded by `_MAX_DEPTH`, with the visited set tracked so a cycle terminates. Returns
  a `Chain`.
- **`conversation(conversation_id)`** — every record sharing that `conversation_id`, in `seq` order,
  capped at `_MAX_RECORDS` with `truncated` reported. This is OBS-05: a conversation crosses tools
  and delegations, and `seq` is the one ordering the chain itself authenticates.
- **`components_for(agent_ids)`** — the Phase-10 graph join, when a graph store was supplied: which
  tools/models/MCP servers those agents touched. Optional collaborator, `None`-default, so an
  operator without the graph wired still gets the chain.

**Implementation note on the CTE.** SQLite and Postgres both accept:

```sql
WITH RECURSIVE walk(action_id, parent_action_id, depth) AS (
    SELECT ... FROM audit_record WHERE json_extract(body,'$.action_id') = :root
    UNION ALL
    SELECT ... FROM audit_record r JOIN walk w
      ON json_extract(r.body,'$.action_id') = w.parent_action_id
    WHERE w.depth < :max_depth
)
SELECT * FROM walk
```

but **`body` is a generic JSON column** (SQLite TEXT-JSON, Postgres JSONB), and the extraction
function differs between them. Rather than embed backend-specific SQL, **prefer an iterative
Python walk with an explicit visited set and depth counter** unless you can express the CTE
portably — the walk is O(depth) queries, depth is capped at 50, and this is a forensic read, not a
hot path. Whichever you choose, the cycle and depth tests below are the contract. State which you
chose and why in your report.

- [ ] **Step 1: Write the failing tests**

```python
def test_a_chain_reconstructs_the_causal_path(graph_store) -> None:
    """A -> B -> C: asking about C returns C, B, A."""


def test_a_CYCLE_terminates_and_is_reported_as_truncated(store, audit) -> None:
    """REGRESSION GUARD, and the reason this module bounds anything at all.

    `parent_action_id` is caller-supplied, so an agent can claim A's parent is B while B's parent is
    A. An unbounded walk never returns — a denial of service against the tool an operator reaches for
    DURING an incident, triggerable by the agent under investigation. The test builds a real cycle
    and asserts the call returns, bounded, and says it was truncated.
    """
    _link_in_a_cycle(store)          # A.parent = B, B.parent = A

    chain = EvidenceGraph(store).ancestors(action_a)

    assert chain.truncated is True
    assert len(chain.records) <= EvidenceGraph._MAX_DEPTH


def test_a_chain_deeper_than_the_cap_is_truncated_and_says_so(store, audit) -> None:
    """A chain that stops early without saying so reads as a complete account of what happened."""


def test_every_chain_carries_the_claimed_lineage_qualifier(store, audit) -> None:
    """SPEC D-2, asserted rather than documented. `identity_verified` authenticates who ACTED, not
    that parent_action_id names a real delegation — and an investigator reading a chain as proven
    causation would attribute blame on a field the accused agent's own caller supplied."""
    chain = EvidenceGraph(store).ancestors(action_id)

    assert "CLAIMED, not proven" in chain.lineage
    assert "TRST-04" in chain.lineage


def test_a_conversation_reconstructs_across_tools_AND_delegations(store, audit) -> None:
    """OBS-05 says "across tools and delegations" — a conversation confined to one action type would
    satisfy the words and miss the point."""
    # seed a conversation containing tool_call, delegation and model_invocation records
    convo = EvidenceGraph(store).conversation(cid)

    assert {r["action_type"] for r in convo.records} >= {"tool_call", "delegation"}


def test_a_conversation_is_ordered_by_the_chains_OWN_sequence(store, audit) -> None:
    """`seq` is hash-covered; `created_at` is not, and SQLite's has one-second granularity. Ordering
    a forensic reconstruction by an unauthenticated, low-resolution column would let two records be
    presented in an order the evidence does not support."""


def test_an_unknown_action_or_conversation_is_an_empty_chain_not_an_error(store) -> None:
    """During an incident, "nothing matched" is an answer; a traceback is not."""


def test_the_conversation_read_is_bounded(store, audit) -> None:
    """`conversation_id` is caller-supplied, so an agent chooses how much this returns."""


def test_the_bodies_are_the_REDACTED_ones_the_chain_already_holds(store, audit) -> None:
    """AUD-04 redaction happens at write time, so a reconstruction inherits it. This asserts the
    forensic surface adds no un-redacted read path — the most sensitive read in the product must not
    be the way around the redactor."""
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes.**
- [ ] **Step 5: Commit** `feat(controlplane): bounded, cycle-safe evidence graph over the audit log (AUD-09, OBS-05)`.

---

### Task 2: gated read routes + full gate

**Files:** modify `.../api.py`; test `tests/integration/test_forensics_api.py`.

Append `forensics: "EvidenceGraph | None" = None` LAST to `build_inventory_router` and `create_app`:

```python
    @router.get("/forensics/chain/{action_id}")
    def evidence_chain(action_id: str) -> dict:
        """AUD-09 — the causal chain leading to one action. Gated: a causal chain is the most
        revealing read in the product, and its `lineage` field says what it is worth."""

    @router.get("/forensics/conversation/{conversation_id}")
    def conversation(conversation_id: str) -> dict:
        """OBS-05 — one conversation reconstructed across tools and delegations."""
```

Both return the `Chain` shape **including `lineage` and `truncated`** — a route that returned only
`records` would strip exactly the two fields that keep the answer honest. Assert that in the API
test, not just the unit test.

- [ ] **Step 1: Failing tests** — 200 with `lineage` + `truncated` present; 401 without a token; 404
  when unwired while `/inventory` still 200; an unknown id → 200 with an empty `records` (not 404 —
  "no chain" is an answer).
- [ ] **Step 2: Run → fails.** **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate on the WHOLE suite + `-m floor_invariant`,
  `-m regression_lock`, `-m latency`, coverage, alembic single head.
- [ ] **Step 5: Commit** `feat(controlplane): gated evidence-graph and conversation-tracing routes (AUD-09, OBS-05)`.

## Self-review

AUD-09's three constraints are each honored and tested: the join happens **at query time** over the
audit log plus the Phase-10 graph, there is **no separate graph database**, and the walk follows
`parent_action_id` / `conversation_id` which have been persisted since Phase 2.

The two structural hazards have tests rather than arguments: a real cycle is built and the call must
return bounded and truncated, and an over-deep chain must say it was cut. Both matter because the
input is caller-supplied and the tool is one an operator reaches for *during* an incident — the worst
possible time for it to hang.

The honesty property is in the payload, not the docs: every chain carries `lineage` naming what is
claimed versus proven and pointing at the Phase-13 work that would close it, and the API test asserts
the route does not strip it. Conversations are ordered by hash-covered `seq` rather than by
`created_at`, which is neither authenticated nor better than one-second resolution, and the bodies are
the AUD-04-redacted ones the chain already holds — the forensic surface adds no way around the
redactor.
