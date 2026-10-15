"""Phase 15 — SEC-13 correlation and TRST-04 lineage survive being split across instances.

The in-memory correlator and ledger are per process. With two replicas behind a load balancer an
attacker could send `rename_table` to one and `drop_table` to the other, and neither replica ever
saw the sequence. These tests run the shared implementations on real Postgres (and SQLite where the
behaviour must match), including a parity property test against the in-memory originals.
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, func, select

from _opa import find_opa
from _pg import fresh_pg_url, pg_available
from agentos_contract import ActionContext, ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import Registry
from agentos_controlplane.shared_lineage import SharedDelegationLedger, SharedSequenceCorrelator
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import CorrelationEvent
from agentos_pipeline.delegation import (
    ALL,
    Authority,
    DelegationDenied,
    DelegationLedger,
    DelegationResolver,
)
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline
from agentos_pipeline.sequence import SequenceCorrelator

needs_pg = pytest.mark.skipif(not pg_available(), reason="pgserver/psycopg not installed")

SEQUENCES = [
    {"principle_ref": "3.5", "intent_classes": ["RESOURCE_RENAME", "DATA_DESTRUCTION"]},
    {"principle_ref": "9.1", "intent_classes": ["A", "B", "C"]},
    {"principle_ref": "9.2", "intent_classes": ["C"]},
]


def _sqlite_sf():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _pg_sf():
    engine = create_engine(fresh_pg_url())
    create_all(engine)
    return create_session_factory(engine)


BACKENDS = [pytest.param(_sqlite_sf, id="sqlite"), pytest.param(_pg_sf, id="postgres", marks=needs_pg)]


@pytest.mark.parametrize("make_sf", BACKENDS)
def test_shared_correlator_matches_the_in_memory_one_exactly(make_sf) -> None:
    """Property test: 400 random observations over 3 keys, including untagged actions and more
    tagged ones than the window holds. Every return value must equal the in-memory correlator's."""
    rng = random.Random(1234)
    classes = ["A", "B", "C", "RESOURCE_RENAME", "DATA_DESTRUCTION", None, ""]
    memory = SequenceCorrelator(window=4)
    shared = SharedSequenceCorrelator(make_sf(), window=4)
    for _ in range(400):
        key = rng.choice(["k1", "k2", "k3"])
        cls = rng.choice(classes)
        assert shared.observe(key, cls, SEQUENCES) == memory.observe(key, cls, SEQUENCES)


@pytest.mark.parametrize("make_sf", BACKENDS)
def test_the_window_is_trimmed_per_key(make_sf) -> None:
    sf = make_sf()
    c = SharedSequenceCorrelator(sf, window=3)
    for i in range(20):
        c.observe("k", "A", SEQUENCES)
        c.observe("other", "B", SEQUENCES)
    with sf() as s:
        counts = dict(
            s.execute(
                select(CorrelationEvent.key, func.count()).group_by(CorrelationEvent.key)
            ).all()
        )
    assert counts == {"k": 3, "other": 3}


def test_long_keys_are_digested_not_truncated_into_a_shared_window() -> None:
    """Two 300-char conversation ids sharing their first 255 chars must NOT share a window."""
    c = SharedSequenceCorrelator(_sqlite_sf())
    prefix = "x" * 255
    c.observe(prefix + "-one", "RESOURCE_RENAME", SEQUENCES)
    assert c.observe(prefix + "-two", "DATA_DESTRUCTION", SEQUENCES) == ()
    assert c.observe(prefix + "-one", "DATA_DESTRUCTION", SEQUENCES) == ("3.5",)


@needs_pg
def test_a_sequence_split_across_two_instances_is_still_caught() -> None:
    url = fresh_pg_url()
    create_all(create_engine(url))
    a = SharedSequenceCorrelator(create_session_factory(create_engine(url)))
    b = SharedSequenceCorrelator(create_session_factory(create_engine(url)))
    assert a.observe("conv", "RESOURCE_RENAME", SEQUENCES) == ()
    assert b.observe("conv", "DATA_DESTRUCTION", SEQUENCES) == ("3.5",)
    # ...whereas two in-memory correlators (the old deployment) miss it entirely:
    m1, m2 = SequenceCorrelator(), SequenceCorrelator()
    m1.observe("conv", "RESOURCE_RENAME", SEQUENCES)
    assert m2.observe("conv", "DATA_DESTRUCTION", SEQUENCES) == ()


def test_window_must_be_positive() -> None:
    with pytest.raises(ValueError):
        SharedSequenceCorrelator(_sqlite_sf(), window=0)


# ---- TRST-04 lineage ----


class _Scopes:
    def __init__(self, scopes):
        self._s = scopes

    def scope_for(self, agent_id):
        return self._s.get(agent_id, ALL)


def _ledger(sf, **kw):
    return SharedDelegationLedger(sf, Authority, **kw)


def _act(agent, parent=None):
    return AgentAction(
        agent_id=agent,
        type=ActionType.delegation,
        target="delegate",
        payload={},
        context=ActionContext(parent_action_id=parent),
    )


@needs_pg
def test_a_child_resolved_on_another_instance_inherits_its_parents_cap() -> None:
    url = fresh_pg_url()
    create_all(create_engine(url))
    scopes = _Scopes({"low": frozenset({"read"}), "high": frozenset({"read", "write"})})
    ra = DelegationResolver(scopes, ledger=_ledger(create_session_factory(create_engine(url))))
    rb = DelegationResolver(scopes, ledger=_ledger(create_session_factory(create_engine(url))))
    root = _act("low")
    ra.resolve(root, own_trust=0.2)  # a distrusted principal, resolved on instance A
    child = rb.resolve(_act("high", parent=root.id), own_trust=0.95)  # its delegate, on B
    assert child.trust <= 0.2  # capped by the delegator, not its own 0.95
    assert child.scope == frozenset({"read"})  # intersection, never union
    assert child.depth == 1


@pytest.mark.parametrize("make_sf", BACKENDS)
def test_unknown_lineage_still_fails_closed(make_sf) -> None:
    from uuid import uuid4

    r = DelegationResolver(_Scopes({}), ledger=_ledger(make_sf()))
    with pytest.raises(DelegationDenied):
        r.resolve(_act("x", parent=uuid4()), own_trust=0.9)


@pytest.mark.parametrize("make_sf", BACKENDS)
def test_a_pruned_parent_is_unknown_lineage_not_a_root(make_sf) -> None:
    sf = make_sf()
    clock = [datetime.now(timezone.utc)]
    ledger = _ledger(sf, retention=timedelta(hours=1), now=lambda: clock[0])
    r = DelegationResolver(_Scopes({}), ledger=ledger)
    root = _act("a")
    r.resolve(root, own_trust=0.5)
    clock[0] += timedelta(hours=2)
    assert ledger.prune() == 1
    with pytest.raises(DelegationDenied):
        r.resolve(_act("b", parent=root.id), own_trust=0.9)


@pytest.mark.parametrize("make_sf", BACKENDS)
def test_prune_keeps_what_is_inside_retention(make_sf) -> None:
    ledger = _ledger(make_sf(), retention=timedelta(hours=1))
    ledger.record("x", Authority(agent_id="a", trust=0.5, scope=ALL, depth=0, ring=2))
    assert ledger.prune() == 0
    got = ledger.authority_for("x")
    assert got == Authority(agent_id="a", trust=0.5, scope=ALL, depth=0, ring=2)


@pytest.mark.parametrize("make_sf", BACKENDS)
def test_ledger_parity_with_in_memory(make_sf) -> None:
    """Random delegation forests resolve to identical authorities with either ledger."""
    rng = random.Random(7)
    scopes = _Scopes({f"a{i}": frozenset(rng.sample(["r", "w", "x", "d"], 2)) for i in range(6)})
    mem = DelegationResolver(scopes, ledger=DelegationLedger())
    shr = DelegationResolver(scopes, ledger=_ledger(make_sf()))
    roots: list = []
    for _ in range(60):
        parent = rng.choice(roots) if roots and rng.random() < 0.7 else None
        act = _act(f"a{rng.randrange(6)}", parent=parent.id if parent else None)
        trust = round(rng.random(), 3)
        outcomes = []
        for resolver in (mem, shr):
            try:
                outcomes.append(resolver.resolve(act, trust))
            except DelegationDenied as exc:
                outcomes.append(type(exc))
        assert outcomes[0] == outcomes[1]
        roots.append(act)


# ---- the wedge demo, end to end, split across two pipeline instances ----


@needs_pg
@pytest.mark.skipif(find_opa() is None, reason="no OPA binary")
def test_rename_then_drop_split_across_two_pipelines_is_denied(constitution_wasm) -> None:
    from conftest import _engine

    url = fresh_pg_url()
    create_all(create_engine(url))
    sf_a = create_session_factory(create_engine(url))
    registry = Registry(sf_a)
    token = registry.register("agent-x")

    def pipeline(sf):
        return Pipeline(
            identity=IdentityStage(registry.identity),
            policy=_engine(constitution_wasm),
            scorers=[PromptInjectionScorer()],
            audit=AuditWriter(sf, signer=registry.identity),
            posture=PostureMap(),
            sequences=constitution_wasm.bundle.sequences,
            correlator=SharedSequenceCorrelator(sf),
        )

    a, b = pipeline(sf_a), pipeline(create_session_factory(create_engine(url)))

    def act(target):
        return AgentAction(
            agent_id="agent-x",
            type=ActionType.tool_call,
            target=target,
            payload={"url": "https://api.example.com/db"},
            context=ActionContext(conversation_id="wedge-split"),
            identity_token=token,
        )

    assert asyncio.run(a.evaluate(act("rename_table"))).outcome is Outcome.allow
    second = asyncio.run(b.evaluate(act("drop_table")))
    assert second.outcome is Outcome.deny
    assert "3.5" in {r.principle_ref for r in second.reasons if r.stage == "policy"}
