"""The concrete ResourceGovernor: the `resource_limit` table + audited administration (RUN-05, 9c/2).

Shape mirrors `PrivilegeRingStore` (9b): the hot-path `limits_for` lookup is IN-MEMORY, the table is
durability and reloads at construction, and administration commits FIRST, then updates the cache,
THEN audits — so after a successful commit the hot path and the table can never disagree.

The breach event carries short identifiers + numbers ONLY. That is asserted with a canary planted in
the action payload: if `record_breach` ever grows a `target` or a payload field, the canary shows up
in the hash-covered audit body and this test fails.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.resource_governor import ResourceGovernorStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, ResourceLimit

CANARY = "SECRET-CANARY-9c"


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def governor(store) -> ResourceGovernorStore:
    return ResourceGovernorStore(store, AuditWriter(store))


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def _action() -> AgentAction:
    """Carries the canary in its payload — the thing the breach body must NOT reproduce."""
    return AgentAction(
        agent_id="a",
        type=ActionType.tool_call,
        target=f"tool_named_{CANARY}",
        payload={"url": f"https://{CANARY}.example.com/path", "content": CANARY},
        identity_token="tok",
    )


def _decision(action: AgentAction) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=Outcome.allow,
        reasons=[Reason(stage="policy", code="allowlisted")],
    )


# --- the table + event kinds -------------------------------------------------


def test_resource_limit_row_round_trips(store) -> None:
    with store() as s:
        s.add(ResourceLimit(agent_id="a", wall_s=1.5, memory_mb=64.0, network="deny", set_by="op"))
        s.commit()
    with store() as s:
        row = s.get(ResourceLimit, "a")
    assert row.wall_s == 1.5 and row.memory_mb == 64.0
    assert row.network == "deny" and row.set_by == "op"
    assert row.updated_at is not None  # server_default fires


def test_null_numerics_mean_no_limit_and_network_defaults_to_allow(store) -> None:
    with store() as s:
        s.add(ResourceLimit(agent_id="b"))
        s.commit()
    with store() as s:
        row = s.get(ResourceLimit, "b")
    assert row.wall_s is None and row.memory_mb is None
    assert row.network == "allow"


def test_both_event_kinds_are_registered() -> None:
    assert "resource_limit_set" in EVENT_KINDS
    assert "resource_limit_exceeded" in EVENT_KINDS


# --- administration ----------------------------------------------------------


def test_no_row_means_no_limits(governor: ResourceGovernorStore) -> None:
    """The zero-overhead default: an agent with no budget row returns None, and the SDK skips
    tracemalloc/wait_for entirely."""
    assert governor.limits_for("a") is None


def test_set_limits_updates_the_hot_path_and_audits(store, governor) -> None:
    asyncio.run(
        governor.set_limits("a", wall_s=1.5, memory_mb=64.0, network="deny", set_by="op")
    )
    limits = governor.limits_for("a")
    assert limits is not None
    assert limits.wall_s == 1.5 and limits.memory_mb == 64.0 and limits.network == "deny"

    bodies = _events(store, "resource_limit_set")
    assert len(bodies) == 1
    assert bodies[0]["agent_id"] == "a" and bodies[0]["wall_s"] == 1.5
    assert bodies[0]["network"] == "deny" and bodies[0]["set_by"] == "op"
    assert verify_chain(store).ok


def test_set_limits_is_idempotent_on_an_existing_row(store, governor) -> None:
    """A second assignment UPDATES the row rather than colliding on the primary key."""
    asyncio.run(governor.set_limits("a", wall_s=1.0, set_by="op"))
    asyncio.run(governor.set_limits("a", wall_s=2.0, network="deny", set_by="op2"))

    assert governor.limits_for("a").wall_s == 2.0
    assert governor.limits_for("a").network == "deny"
    with store() as s:
        rows = list(s.scalars(select(ResourceLimit)))
    assert len(rows) == 1 and rows[0].wall_s == 2.0 and rows[0].set_by == "op2"
    assert len(_events(store, "resource_limit_set")) == 2


def test_limits_are_per_agent(governor: ResourceGovernorStore) -> None:
    asyncio.run(governor.set_limits("a", network="deny", set_by="op"))
    assert governor.limits_for("a").network == "deny"
    assert governor.limits_for("b") is None  # budgeting one agent never budgets another


def test_a_fresh_store_reloads_the_limits(store) -> None:
    """Durability: a restarted control plane keeps enforcing the budgets (_load)."""
    first = ResourceGovernorStore(store, AuditWriter(store))
    asyncio.run(
        first.set_limits("a", wall_s=1.5, memory_mb=64.0, network="deny", set_by="op")
    )

    fresh = ResourceGovernorStore(store, AuditWriter(store))
    reloaded = fresh.limits_for("a")
    assert reloaded is not None
    assert reloaded.wall_s == 1.5 and reloaded.memory_mb == 64.0 and reloaded.network == "deny"


# --- validation --------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"network": "bogus"},
        {"network": "DENY"},  # case matters: a typo must not silently become "allow"
        {"wall_s": 0},
        {"wall_s": -1},
        {"memory_mb": 0},
        {"memory_mb": -1},
    ],
)
def test_invalid_budgets_are_rejected_and_change_nothing(store, governor, kwargs) -> None:
    with pytest.raises(ValueError):
        asyncio.run(governor.set_limits("a", set_by="op", **kwargs))

    assert governor.limits_for("a") is None
    with store() as s:
        assert s.get(ResourceLimit, "a") is None
    assert _events(store, "resource_limit_set") == []


# --- the breach event: short identifiers + numbers only ----------------------


def test_record_breach_audits_short_identifiers_and_numbers_only(store, governor) -> None:
    action = _action()
    asyncio.run(
        governor.record_breach(
            action, _decision(action), limit="wall_s", budget=1.5, observed=1.5
        )
    )
    bodies = _events(store, "resource_limit_exceeded")
    assert len(bodies) == 1
    body = bodies[0]
    assert body["action_id"] == str(action.id)
    assert body["agent_id"] == "a"
    assert body["action_type"] == "tool_call"
    assert body["limit"] == "wall_s" and body["budget"] == 1.5 and body["observed"] == 1.5
    # No target, no payload — the redacted detail belongs to the DECISION record, so the AUD-04
    # secret gate here can never block a breach from being recorded.
    assert "target" not in body and "payload" not in body
    assert verify_chain(store).ok


def test_the_breach_body_carries_no_canary_anywhere(store, governor) -> None:
    """The proof, not the promise: the action's target AND payload both carry a canary, so any
    field that leaks either one into the hash-covered body fails this test."""
    action = _action()
    asyncio.run(
        governor.record_breach(
            action, _decision(action), limit="memory_mb", budget=64.0, observed=128.5
        )
    )
    body = _events(store, "resource_limit_exceeded")[0]
    assert CANARY not in str(body)
    assert all(CANARY not in str(v) for v in body.values())


def test_observed_is_rounded_so_the_body_stays_a_short_number(store, governor) -> None:
    action = _action()
    asyncio.run(
        governor.record_breach(
            action, _decision(action), limit="memory_mb", budget=1.0, observed=2.123456789
        )
    )
    assert _events(store, "resource_limit_exceeded")[0]["observed"] == 2.1235


# --- ordering: commit, then cache, then audit --------------------------------


class _CommitRaises:
    """A session factory whose sessions explode on commit (a durability failure)."""

    def __init__(self, inner):
        self._inner = inner

    def __call__(self):
        return self

    def __enter__(self):
        self._s = self._inner().__enter__()
        return _Sess(self._s)

    def __exit__(self, *exc):
        return False


class _Sess:
    def __init__(self, s):
        self._s = s

    def __getattr__(self, name):
        return getattr(self._s, name)

    def commit(self):
        raise RuntimeError("durability failure")


class _AuditRaises:
    async def append_event(self, kind: str, body: dict) -> None:
        raise RuntimeError("audit failure")


def test_a_failed_persist_leaves_the_cache_unchanged(store) -> None:
    """Durable-first: nothing committed, so the hot path must keep enforcing the DURABLE budget
    rather than a relaxation that never landed."""
    governor = ResourceGovernorStore(store, AuditWriter(store))
    asyncio.run(governor.set_limits("a", wall_s=1.0, network="deny", set_by="op"))

    governor._sf = _CommitRaises(store)  # noqa: SLF001 — the point of the test
    with pytest.raises(RuntimeError):
        asyncio.run(governor.set_limits("a", network="allow", set_by="op"))  # a RELAXATION

    assert governor.limits_for("a").network == "deny"  # still the committed budget
    assert governor.limits_for("a").wall_s == 1.0
    assert len(_events(store, "resource_limit_set")) == 1  # no event claimed a change


def test_a_failed_audit_leaves_the_cache_matching_the_committed_table(store) -> None:
    """The 9b review lesson: the cache is updated between the commit and the audit append, so an
    audit failure can only lose the EVENT — never leave the hot path looser than the table.

    If the cache moved only after the audit write, this TIGHTENING would commit `network=deny` to
    the table while the live process kept running unbudgeted: a silently disabled control.
    """
    governor = ResourceGovernorStore(store, AuditWriter(store))
    governor._audit = _AuditRaises()  # noqa: SLF001
    with pytest.raises(RuntimeError):
        asyncio.run(governor.set_limits("a", wall_s=1.5, network="deny", set_by="op"))

    with store() as s:
        assert s.get(ResourceLimit, "a").network == "deny"  # committed
    limits = governor.limits_for("a")
    assert limits is not None and limits.network == "deny"  # hot path == table
    assert limits.wall_s == 1.5
    assert _events(store, "resource_limit_set") == []  # only the event is missing


def test_a_failed_audit_on_a_relaxation_also_keeps_them_in_step(store) -> None:
    """The other direction: a committed RELAXATION whose audit fails must not leave the hot path
    enforcing a budget the table no longer records (an operator would see it as a silent refusal)."""
    governor = ResourceGovernorStore(store, AuditWriter(store))
    asyncio.run(governor.set_limits("a", network="deny", set_by="op"))

    governor._audit = _AuditRaises()  # noqa: SLF001
    with pytest.raises(RuntimeError):
        asyncio.run(governor.set_limits("a", network="allow", set_by="op"))

    with store() as s:
        assert s.get(ResourceLimit, "a").network == "allow"  # committed
    assert governor.limits_for("a").network == "allow"  # the live process agrees
