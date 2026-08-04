"""TRST-04 — bounded delegation trust budget + scope intersection.

The two properties the requirement names, and the attacks they defeat:

  * **Bounded budget** — trust propagates across a delegation edge and DECAYS;
    it can only shrink along a chain. The attack this kills is trust laundering:
    a distrusted agent delegating to a trusted one to borrow its authority.

  * **Scope intersection, never union** — a delegate may do what BOTH parties
    may do. The attack this kills is privilege escalation by delegation: A
    lacks `db.drop`, B has it, so A delegates to B and the capability appears
    from nowhere. Union would grant it; intersection cannot.
"""

from __future__ import annotations

import pytest

from agentos_pipeline.delegation import (
    ALL,
    Authority,
    DelegationDenied,
    DelegationLedger,
    cap_ring,
    delegate,
    intersect_scope,
    permits,
)


def _root(trust: float = 1.0, scope=ALL, ring: int | None = None) -> Authority:
    return Authority(agent_id="root", trust=trust, scope=scope, ring=ring)


# --------------------------------------------------------------- scope algebra


def test_intersection_keeps_only_shared_capabilities():
    assert intersect_scope(frozenset({"a", "b"}), frozenset({"b", "c"})) == frozenset({"b"})


def test_intersection_is_never_a_union():
    """The requirement's explicit 'never a union'."""
    parent, child = frozenset({"read"}), frozenset({"db.drop"})
    got = intersect_scope(parent, child)
    assert got == frozenset()
    assert "db.drop" not in got, "delegation conjured a capability the parent never had"


def test_wildcard_parent_confers_the_childs_own_scope_and_no_more():
    assert intersect_scope(ALL, frozenset({"read"})) == frozenset({"read"})


def test_wildcard_child_is_bounded_by_the_parent():
    assert intersect_scope(frozenset({"read"}), ALL) == frozenset({"read"})


def test_two_wildcards_stay_wildcard():
    assert intersect_scope(ALL, ALL) == ALL


def test_permits_honours_the_wildcard():
    assert permits(ALL, "anything")
    assert permits(frozenset({"read"}), "read")
    assert not permits(frozenset({"read"}), "write")


# --------------------------------------------------------- the bounded budget


def test_trust_decays_across_a_delegation_edge():
    child = delegate(_root(1.0), "b", child_trust=1.0, child_scope=ALL, decay=0.8)
    assert child.trust == pytest.approx(0.8)
    assert child.depth == 1


def test_trust_is_monotonically_non_increasing_down_a_chain():
    a = _root(1.0)
    chain = [a]
    for i in range(5):  # 5 == DEFAULT_MAX_DEPTH; the budget-exhaustion case is its own test
        chain.append(
            delegate(chain[-1], f"n{i}", child_trust=1.0, child_scope=ALL, decay=0.8)
        )
    trusts = [n.trust for n in chain]
    assert trusts == sorted(trusts, reverse=True)
    assert trusts[-1] < trusts[0]


def test_a_distrusted_agent_cannot_launder_trust_through_a_trusted_delegate():
    """THE anti-escalation property: the delegate is capped by its delegator.

    A fully-trusted sub-agent acting on behalf of a distrusted principal must not
    act with the sub-agent's own trust — otherwise delegation is a trust-washing
    machine and the whole reputation engine (TRST-03) is bypassable in one hop.
    """
    distrusted = _root(0.1)
    delegate_auth = delegate(distrusted, "trusted", child_trust=1.0, child_scope=ALL, decay=1.0)
    assert delegate_auth.trust <= distrusted.trust


def test_a_child_never_exceeds_its_own_trust_either():
    """min() of both: a trusted parent cannot promote an untrusted child."""
    child = delegate(_root(1.0), "weak", child_trust=0.2, child_scope=ALL, decay=1.0)
    assert child.trust == pytest.approx(0.2)


def test_scope_only_narrows_down_a_chain():
    a = Authority("a", 1.0, frozenset({"read", "write", "admin"}))
    b = delegate(a, "b", child_trust=1.0, child_scope=frozenset({"read", "write"}), decay=1.0)
    c = delegate(b, "c", child_trust=1.0, child_scope=frozenset({"read", "admin"}), decay=1.0)
    assert b.scope == frozenset({"read", "write"})
    assert c.scope == frozenset({"read"}), "admin re-entered a chain that had dropped it"


def test_a_deep_chain_exhausts_the_budget_and_is_denied():
    """A bounded budget must terminate — an unbounded chain is a resource/authority hole."""
    node = _root(1.0)
    with pytest.raises(DelegationDenied) as exc:
        for i in range(20):
            node = delegate(node, f"n{i}", child_trust=1.0, child_scope=ALL, decay=0.8, max_depth=5)
    assert "depth" in str(exc.value).lower()


def test_delegating_an_empty_scope_is_denied():
    """A delegation that confers nothing is an escalation attempt or a misconfig — never a silent no-op."""
    parent = Authority("a", 1.0, frozenset({"read"}))
    with pytest.raises(DelegationDenied) as exc:
        delegate(parent, "b", child_trust=1.0, child_scope=frozenset({"db.drop"}), decay=1.0)
    assert "scope" in str(exc.value).lower()


def test_decay_must_be_a_bounded_fraction():
    """decay > 1 would make delegation GROW trust — the inverse of the requirement."""
    for bad in (1.5, -0.1):
        with pytest.raises(ValueError):
            delegate(_root(), "b", child_trust=1.0, child_scope=ALL, decay=bad)


# ------------------------------------------------- the privilege ring (RUN-04)


def test_ring_is_capped_to_the_chain_minimum():
    """THE anti-escalation property for privilege rings, the mirror of the trust budget: a low-ring
    principal must not reach a ring-gated target through a high-ring delegate."""
    child = delegate(_root(1.0, ring=0), "b", child_trust=1.0, child_ring=3, decay=1.0)
    assert child.ring == 0, "a ring-0 principal borrowed a ring-3 delegate's privilege"


def test_a_high_ring_parent_never_promotes_a_low_ring_child():
    """min() of both halves, exactly like trust."""
    assert delegate(_root(1.0, ring=3), "b", child_trust=1.0, child_ring=1, decay=1.0).ring == 1


def test_ring_is_monotonically_non_increasing_down_a_chain():
    a = _root(1.0, ring=3)
    b = delegate(a, "b", child_trust=1.0, child_ring=2, decay=1.0)
    c = delegate(b, "c", child_trust=1.0, child_ring=5, decay=1.0)
    assert [a.ring, b.ring, c.ring] == [3, 2, 2], "a deeper link minted privilege"


def test_ring_is_none_when_rings_are_not_in_play():
    """Unwired (no ring lookup) == None, so the pipeline falls back to the agent's own ring and
    behavior is unchanged for deployments that do not use RUN-04."""
    assert _root().ring is None
    assert delegate(_root(), "b", child_trust=1.0).ring is None


def test_cap_ring_treats_an_absent_ring_as_the_identity():
    assert cap_ring(None, 2) == 2
    assert cap_ring(2, None) == 2
    assert cap_ring(None, None) is None
    assert cap_ring(3, 1) == 1


def test_a_negative_ring_is_rejected():
    with pytest.raises(ValueError):
        Authority(agent_id="a", trust=1.0, ring=-1)


# ------------------------------------------------------------------ the ledger


def test_ledger_lets_a_child_action_inherit_its_parents_authority():
    ledger = DelegationLedger()
    root = Authority("a", 1.0, frozenset({"read", "write"}))
    ledger.record("action-1", root)
    assert ledger.authority_for("action-1") == root


def test_ledger_returns_none_for_an_unknown_parent():
    """Unknown lineage must not silently mint root authority."""
    assert DelegationLedger().authority_for("never-seen") is None


def test_ledger_is_bounded_and_evicts_fifo():
    ledger = DelegationLedger(max_entries=3)
    for i in range(5):
        ledger.record(f"a{i}", _root())
    assert ledger.authority_for("a0") is None, "unbounded ledger: a hostile flood grows memory"
    assert ledger.authority_for("a4") is not None
