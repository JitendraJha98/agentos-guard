# Phase 13 · Slice 13b — Transitive Permission Closure & Conflict Detection (POL-11) — Plan

**Goal (POL-11):** Compute **transitive permissions across delegation chains** and **flag emergent
capability conflicts** — capabilities that appear, disappear, or contradict along a chain in ways no
single hop reveals.

**Architecture:** A read-side `ConflictEngine` over the TRST-04 delegation ledger and the Phase-12
evidence graph. It walks chains, intersecting scope at every hop, and reports findings. It never
denies (spec D-4).

## Why intersection, and why the direction matters

TRST-04 already holds the one-hop rule: `effective_scope(child) = parent_scope ∩ child_scope`. The
closure is that rule applied along the path. The direction is the entire security property — a
**union** would let a chain *manufacture* a capability no participant held, which is exactly the
laundering TRST-04 exists to prevent. A property test asserts the closure is a subset of every
participant's scope, over randomly generated chains, because that is the invariant a future
refactor is most likely to invert.

## What "emergent conflict" means here, concretely

Three findings, each a thing no single hop can show:

1. **`divergent_paths`** — two delegation paths reach the same agent conferring *different* effective
   scope. The agent's capability then depends on which path a caller used, which is not a permission
   model anyone can reason about.
2. **`capability_lost`** — an agent holds a capability directly but every path that reaches it
   intersects it away. Not a vulnerability; an operator confusion, and the one that produces "why is
   this agent being denied something I granted it" tickets.
3. **`unauthorized_lineage`** — a claimed `parent_action_id` edge whose child was never granted
   authority by that parent. **This is where Phase 12's claimed-lineage gap closes, as far as it
   honestly can** (spec D-5): the finding says the claim is *contradicted* by the ledger, not that it
   is proven false — a ledger miss is not proof of absence, and the in-process ledger is
   non-persistent (a limit TRST-04 already documents).

## File structure
- Create `.../agentos_controlplane/conflicts.py` — `ConflictEngine`.
- Modify `.../api.py` — a gated read route.
- Tests: `tests/unit/test_conflicts.py`, `tests/integration/test_conflicts_api.py`.

No migration: this reads the delegation ledger and the audit log, both of which exist.

---

### Task 1: `ConflictEngine`

```python
"""POL-11 — transitive permissions across delegation chains, and the conflicts they emerge into.

WHY A CLOSURE AND NOT A LOOKUP. One hop is already answered: TRST-04 intersects parent and child
scope at delegation time. What no single hop can answer is what an agent FIVE hops down actually
holds, or whether two routes to the same agent agree about it. Those are properties of the chain, and
an operator granting a capability at the top has no way to see them.

INTERSECTION, ALONG THE WHOLE PATH. `effective_scope` narrows at every hop and never widens. A union
would let a chain manufacture a capability nobody in it held — trust laundering by composition, which
is the escalation TRST-04 was written to stop. The property test over random chains exists because
this is the invariant a refactor is most likely to invert while every example test still passes.

IT REPORTS; IT DOES NOT DENY (spec D-4). POL-11 says "flags". The floor invariant (POL-05/TRST-02) is
that the constitution decides and everything else may only restrict — an engine that denied on its
own would be a second enforcer beside the policy floor, which is exactly what ECON-02 was written to
avoid. A test asserts an action's outcome is unchanged by the presence of a finding.

BOUNDED AND CYCLE-SAFE, for the reason 12e's walk is: the delegation edges are caller-supplied, a
cycle is assertable, and this is a tool an operator reaches for while trying to understand an
incident.
"""
```

`ConflictEngine(delegation_ledger, session_factory=None, graph=None)` exposes:

- **`effective_scope(chain: Sequence[str]) -> frozenset[str]`** — fold `intersect_scope` along the
  path. Reuses `agentos_pipeline.delegation.intersect_scope` rather than reimplementing it, so the
  one-hop and many-hop rules cannot drift.
- **`closure(agent_id) -> dict`** — every path reaching `agent_id`, each with its effective scope,
  bounded by depth and by path count, with truncation reported.
- **`conflicts(limit=200) -> list[dict]`** — the three findings above, each carrying `kind`, the
  agents involved, and the capabilities that differ. Every finding is a **dict with a `kind`**, so a
  consumer can filter without string-matching prose.

Bounds mirror 12e: `_MAX_DEPTH = 50`, `_MAX_PATHS = 200`, visited-set cycle termination, truncation
reported rather than silent.

- [ ] Failing tests:

```python
def test_effective_scope_narrows_along_the_chain(ledger) -> None:
    """A -> B -> C where each grants a subset: C holds the intersection, not B's grant."""


@pytest.mark.parametrize("seed", range(25))
def test_the_closure_is_a_subset_of_every_participant(seed, ledger) -> None:
    """THE invariant, over random chains rather than a chosen example.

    A union anywhere in the fold lets a chain manufacture a capability nobody in it held — trust
    laundering by composition. Example tests pass right through that; a subset property does not.
    """
    chain, scopes = _random_chain(seed)

    result = ConflictEngine(ledger).effective_scope(chain)

    for agent in chain:
        assert result <= scopes[agent] or WILDCARD in scopes[agent]


def test_divergent_paths_to_one_agent_are_flagged(ledger) -> None:
    """Two routes conferring different scope means the agent's capability depends on which route a
    caller took — not a permission model anyone can reason about."""


def test_a_capability_intersected_away_is_reported_as_lost_not_as_absent(ledger) -> None:
    """The "why is this agent denied something I granted it" finding. An operator who granted at the
    top cannot see the hop that removed it."""


def test_a_claimed_lineage_edge_with_no_authority_is_CONTRADICTED_not_disproven(ledger, store) -> None:
    """Spec D-5, and the honest ceiling on Phase 12's gap.

    The finding says the ledger does not corroborate the claim. It does not say the delegation did
    not happen: the ledger is in-process and non-persistent (TRST-04's own documented limit), so an
    absent entry is not proof of absence. The wording is asserted, because "unverified" and "false"
    are different accusations and only one of them is supportable.
    """
    finding = _find(ConflictEngine(ledger, store).conflicts(), "unauthorized_lineage")

    assert "not corroborated" in finding["detail"]
    assert "proof" not in finding["detail"].lower() or "not proof" in finding["detail"].lower()


def test_a_conflict_finding_denies_nothing(wired_pipeline, ledger) -> None:
    """SPEC D-4. An engine that denied would be a second enforcer beside the constitution."""
    before = asyncio.run(wired_pipeline.evaluate(_action()))
    _create_divergent_paths(ledger)
    after = asyncio.run(wired_pipeline.evaluate(_action()))

    assert after.outcome is before.outcome


def test_a_delegation_cycle_terminates_and_reports_truncation(ledger) -> None:
    """Delegation edges are caller-supplied, so a cycle is assertable — and this is a tool an
    operator reaches for DURING an incident."""


def test_the_closure_is_bounded_by_paths_as_well_as_depth(ledger) -> None:
    """A shallow fan-out produces exponentially many paths without ever exceeding the depth cap."""
```

- [ ] Implement. Run → passes.
- [ ] Commit `feat(controlplane): transitive permission closure + conflict findings (POL-11)`.

---

### Task 2: gated read route + full gate

Append `conflicts: "ConflictEngine | None" = None` LAST to `build_inventory_router` and `create_app`.

```python
    @router.get("/conflicts")
    def list_conflicts() -> dict:
        """POL-11 — emergent capability conflicts across delegation chains.

        Findings, not decisions: nothing here denies an action, and the constitution remains the only
        thing that does. `unauthorized_lineage` says a claimed delegation edge is NOT CORROBORATED by
        the ledger — which is weaker than false, because the ledger is in-process and an absent entry
        is not proof of absence."""

    @router.get("/conflicts/closure/{agent_id}")
    def permission_closure(agent_id: str) -> dict:
        """POL-11 — what this agent effectively holds, by every path that reaches it."""
```

- [ ] Failing tests: 200 with findings; the closure route returns paths with effective scope; 401
  without a token; 404 unwired while `/inventory` still 200; truncation surfaces in the payload.
- [ ] Implement. **Full gate on the WHOLE suite** + the three markers + coverage + single head.
- [ ] Commit `feat(controlplane): gated conflict + permission-closure API (POL-11)`.

## Self-review

POL-11 asks for two things: transitive permissions computed across delegation chains, and emergent
capability conflicts flagged. The closure folds TRST-04's own `intersect_scope` along the path — reusing
it rather than reimplementing, so one-hop and many-hop rules cannot drift — and the subset property is
tested over random chains, because that is the invariant a refactor inverts while examples still pass.

Three findings each name something no single hop can show, and the third is where Phase 12's
claimed-lineage gap closes as far as it honestly can: `unauthorized_lineage` reports that the ledger
does **not corroborate** a claimed edge, not that the delegation did not happen. The distinction is
asserted in a test, because "unverified" and "false" are different accusations and only one is
supportable from an in-process, non-persistent ledger.

The engine reports and never denies, asserted by evaluating an action before and after a conflict
exists. And the walk is bounded and cycle-safe on both depth and path count, because delegation edges
are caller-supplied and a fan-out explodes the path count long before it reaches the depth cap.
