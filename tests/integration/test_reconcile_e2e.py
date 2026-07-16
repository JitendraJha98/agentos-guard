"""API-04 end-to-end: the four real reconcilers converge real derived state.

`test_reconcile.py` tests the loop's mechanics against fakes. This drives the
actual reconcilers — constitution compile, trust refresh, graph materialization,
cache warming — over a real store, and asserts the property that makes
reconciliation worth having: it REPAIRS drift, then converges.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.reconcile import (
    CacheReconciler,
    ConstitutionReconciler,
    GraphReconciler,
    ReconciliationLoop,
    TrustReconciler,
)
from agentos_controlplane.registry import DEFAULT_TRUST_SCORE, Registry
from agentos_controlplane.reputation import ReputationEngine
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import PolicyResource

CONSTITUTION = {
    "schema_version": 1,
    "name": "recon-test",
    "lists": {"egress_allowlist": ["api.example.com"]},
    "principles": [
        {
            "id": "1.1",
            "title": "Egress allowlist",
            "statement": "An agent may only make outbound requests to allowlisted hosts.",
            "applies_to": ["tool_call"],
            "effect": "deny",
            "when": {"field": "egress.host", "op": "not_in", "list_ref": "egress_allowlist"},
        }
    ],
}


@pytest.fixture()
def wired():
    # StaticPool: the loop runs reconcilers via asyncio.to_thread (blocking DB I/O
    # must stay off the event loop), and SQLite's default pool is per-thread — a
    # worker thread would otherwise open its own EMPTY :memory: database. Real
    # backends (Postgres, file-SQLite) share the pool across threads natively.
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    sf = create_session_factory(engine)
    return {
        "sf": sf,
        "resources": ResourceStore(sf),
        "registry": Registry(sf),
        "audit": AuditWriter(sf),
        "reputation": ReputationEngine(sf),
        "inventory": InventoryStore(sf),
    }


class _FakeCache:
    def __init__(self):
        self.invalidations = 0

    def invalidate(self, agent_id=None):
        self.invalidations += 1


# ----------------------------------------------------- constitution reconciler


def test_constitution_reconciler_repairs_a_missing_compiled_policy(wired):
    """The drift that matters: a Constitution the control plane cannot enforce."""
    resources, sf = wired["resources"], wired["sf"]
    con, _ = resources.apply_constitution("recon-test", CONSTITUTION)

    # Simulate the drift: the compiled Policy row is lost.
    with sf() as s:
        s.execute(delete(PolicyResource).where(PolicyResource.constitution_version == con.version))
        s.commit()
    assert resources.get_policy(con.version) is None

    reconciler = ConstitutionReconciler(resources)
    assert reconciler.reconcile() == 1, "reconciler did not repair the missing policy"
    assert resources.get_policy(con.version) is not None
    assert reconciler.reconcile() == 0, "reconciler is not idempotent — it churns"


def test_constitution_reconciler_is_a_noop_when_converged(wired):
    resources = wired["resources"]
    resources.apply_constitution("recon-test", CONSTITUTION)
    assert ConstitutionReconciler(resources).reconcile() == 0


def test_reapplying_a_constitution_whose_policy_is_missing_repairs_it(wired):
    """Regression lock: this partial state used to raise AttributeError.

    `_fetch_version` returned (constitution, None) when the compiled half was gone,
    so apply_constitution reported success on an UNENFORCEABLE version and then
    dereferenced the None policy — the exact drift API-04 exists to repair.
    """
    resources, sf = wired["resources"], wired["sf"]
    con, _ = resources.apply_constitution("recon-test", CONSTITUTION)
    with sf() as s:
        s.execute(delete(PolicyResource).where(PolicyResource.constitution_version == con.version))
        s.commit()

    con2, pol2 = resources.apply_constitution("recon-test", CONSTITUTION)

    assert pol2 is not None and pol2.constitution_version == con.version
    assert resources.get_policy(con.version) is not None


def test_get_latest_policy_is_stable_within_one_second(wired):
    """Regression lock: created_at had SECOND resolution and no tiebreaker, so two
    applies in the same second tied and `latest` could return the OLDER policy —
    a stale GET /policies/latest and a cache warmed to the wrong constitution."""
    resources = wired["resources"]
    resources.apply_constitution("recon-test", CONSTITUTION)
    second = dict(CONSTITUTION)
    second["principles"] = CONSTITUTION["principles"] + [
        {
            "id": "2.1",
            "title": "Destructive intent requires approval",
            "statement": "Destructive actions require human approval.",
            "effect": "require_approval",
            "when": {"field": "intent.class", "op": "eq", "value": "DATA_DESTRUCTION"},
        }
    ]
    _, newest = resources.apply_constitution("recon-test", second)

    assert resources.get_latest_policy().constitution_version == newest.constitution_version


# ------------------------------------------------------------ trust reconciler


def test_trust_reconciler_refreshes_reputation_into_the_pipeline_path(wired):
    registry, audit, reputation = wired["registry"], wired["audit"], wired["reputation"]
    registry.register("bad")

    async def offend():
        for _ in range(3):
            action = AgentAction(
                agent_id="bad",
                type=ActionType.tool_call,
                target="http_get",
                payload={"url": "https://x.example.com/", "content": ""},
            )
            await audit.append(
                action,
                Decision(action_id=action.id, outcome=Outcome.deny, risk_score=0.9, trust_score=0.5, reasons=[]),
            )

    asyncio.run(offend())

    reconciler = TrustReconciler(reputation)
    assert reconciler.reconcile() == 1  # one agent's score moved
    assert registry.load_trust("bad") < DEFAULT_TRUST_SCORE

    assert reconciler.reconcile() == 0, "converged fleet still reports churn"


# ------------------------------------------------------------ graph reconciler


def test_graph_reconciler_materializes_observed_activity(wired):
    registry, audit, inventory = wired["registry"], wired["audit"], wired["inventory"]
    registry.register("a1")

    async def act():
        action = AgentAction(
            agent_id="a1",
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://x.example.com/", "content": ""},
        )
        await audit.append(
            action,
            Decision(action_id=action.id, outcome=Outcome.allow, risk_score=0.0, trust_score=0.5, reasons=[]),
        )

    asyncio.run(act())

    GraphReconciler(inventory).reconcile()
    assert any(c.agent_id == "a1" for c in inventory.get_inventory("a1"))


# ------------------------------------------------------------ cache reconciler


def test_cache_reconciler_invalidates_only_on_a_version_change(wired):
    """Invalidating every pass would defeat the cache; never invalidating enforces
    the WRONG constitution. Fire exactly on change."""
    resources = wired["resources"]
    cache = _FakeCache()
    reconciler = CacheReconciler(resources, [cache])

    resources.apply_constitution("recon-test", CONSTITUTION)
    assert reconciler.reconcile() == 1
    assert cache.invalidations == 1

    assert reconciler.reconcile() == 0, "cache invalidated with no version change"
    assert cache.invalidations == 1

    changed = dict(CONSTITUTION)
    changed["principles"] = CONSTITUTION["principles"] + [
        {
            "id": "2.1",
            "title": "Destructive intent requires approval",
            "statement": "Destructive actions require human approval.",
            "effect": "require_approval",
            "when": {"field": "intent.class", "op": "eq", "value": "DATA_DESTRUCTION"},
        }
    ]
    resources.apply_constitution("recon-test", changed)
    assert reconciler.reconcile() == 1, "a new constitution version did not warm the cache"
    assert cache.invalidations == 2


# ------------------------------------------------------------- the loop, wired


def test_the_full_loop_runs_all_four_reconcilers_and_converges(wired):
    resources = wired["resources"]
    resources.apply_constitution("recon-test", CONSTITUTION)
    wired["registry"].register("a1")

    loop = ReconciliationLoop(
        [
            ConstitutionReconciler(resources),
            TrustReconciler(wired["reputation"]),
            GraphReconciler(wired["inventory"]),
            CacheReconciler(resources, [_FakeCache()]),
        ]
    )

    first = asyncio.run(loop.run_once())
    assert [r.name for r in first] == ["constitution", "trust", "graph", "cache"]
    assert all(r.ok for r in first), [r.error for r in first if not r.ok]

    second = asyncio.run(loop.run_once())
    assert all(r.changed == 0 for r in second), (
        f"loop never converges: {[(r.name, r.changed) for r in second if r.changed]}"
    )
