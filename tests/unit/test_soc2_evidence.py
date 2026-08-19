"""CMP-05 — SOC 2 evidence DERIVED from the audit log, never asserted.

The failure this file guards is not a crash, it is a misleading report. A criterion that cites an
event kind the system never writes reports zero forever and reads as a control that never fires; a
criterion omitted for having no events reads as "not applicable", which is a different claim from
"nothing happened in this window"; and a time range that silently ignores its bounds lets an auditor
believe a quiet quarter was quiet when the events simply fell outside the query.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.compliance import SOC2_CRITERIA, derive_soc2_evidence
from agentos_controlplane.store.engine import create_all, create_session_factory


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def _seed_events(store, *kinds: str) -> None:
    """Append one lifecycle event of each `kind` through the real writer — no hand-built rows, so
    the counts under test come from records the shipped code paths could actually have written."""
    writer = AuditWriter(store)

    async def _run() -> None:
        for kind in kinds:
            await writer.append_event(kind, {"target": "t", "scope": "agent", "set_by": "op"})

    asyncio.run(_run())


def _seed_decision(store, outcome: Outcome) -> None:
    writer = AuditWriter(store)
    action = AgentAction(
        agent_id="a1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": "hello"},
    )

    asyncio.run(writer.append(action, Decision(action_id=action.id, outcome=outcome)))


# --- the citations themselves ----------------------------------------------


def test_every_cited_event_kind_actually_exists() -> None:
    """A criterion citing a kind the system never writes reports zero forever and reads as a
    control that never fired — the most misleading output this module could produce."""
    for name, criterion in SOC2_CRITERIA.items():
        for kind in criterion["event_kinds"]:
            assert kind in EVENT_KINDS, f"{name} cites an event kind nothing writes: {kind}"


def test_every_cited_outcome_is_a_real_graduated_outcome() -> None:
    values = {o.value for o in Outcome}
    for name, criterion in SOC2_CRITERIA.items():
        for outcome in criterion["outcomes"]:
            assert outcome in values, f"{name} cites an outcome the engine never emits: {outcome}"


def test_every_cited_criterion_point_belongs_to_its_own_family() -> None:
    """A CC7.x point filed under CC6 is a citation error an auditor will catch before we do."""
    for name, criterion in SOC2_CRITERIA.items():
        assert criterion["criteria"], f"{name} cites no criterion point"
        for point in criterion["criteria"]:
            assert re.fullmatch(rf"{name}\.\d+", point), f"{name} cites {point}"


def test_no_criterion_is_evidence_free() -> None:
    """A criterion with neither an event kind nor an outcome behind it can only ever report zero."""
    for name, criterion in SOC2_CRITERIA.items():
        assert criterion["event_kinds"] or criterion["outcomes"], name


# --- the counts -------------------------------------------------------------


def test_an_empty_log_reports_zeros_rather_than_omitting_the_criterion(store) -> None:
    """A missing criterion reads as 'not applicable'; a zero reads as 'no events in this window'.
    Only one of those is true, and an auditor needs to see which."""
    evidence = derive_soc2_evidence(store)

    assert set(evidence) == set(SOC2_CRITERIA)
    assert all(c["total"] == 0 for c in evidence.values())
    assert all(all(n == 0 for n in c["counts"].values()) for c in evidence.values())


def test_counts_come_from_the_log_not_from_assertions(store) -> None:
    _seed_events(store, "kill_switch_set", "kill_switch_cleared")

    evidence = derive_soc2_evidence(store)

    assert evidence["CC7"]["counts"]["kill_switch_set"] == 1
    assert evidence["CC7"]["total"] == 2
    assert evidence["CC6"]["total"] == 0  # a kill switch is not an access-control record


def test_a_refused_action_is_counted_from_the_decision_record(store) -> None:
    """Decision records carry no `kind` — the access-control evidence with by far the most volume
    is the per-action outcome, and reading it needs a second discriminator, not a second table."""
    _seed_decision(store, Outcome.deny)

    evidence = derive_soc2_evidence(store)

    assert evidence["CC6"]["counts"]["deny"] == 1
    assert evidence["CC6"]["total"] == 1


def test_an_allowed_action_is_not_counted_as_an_access_control_event(store) -> None:
    """Counting every governed action as access-control evidence would inflate the one number an
    auditor is most likely to read as "how often did the control fire"."""
    _seed_decision(store, Outcome.allow)

    assert derive_soc2_evidence(store)["CC6"]["total"] == 0


def test_an_event_kind_no_criterion_cites_is_not_counted(store) -> None:
    """The log carries far more kinds than SOC 2 evidence. Sweeping them into a criterion would
    make its total mean nothing."""
    _seed_events(store, "framework_discovered")

    assert all(c["total"] == 0 for c in derive_soc2_evidence(store).values())


# --- the time range ---------------------------------------------------------


def test_the_time_range_actually_filters(store) -> None:
    """A range that silently ignores its bounds would let an auditor believe a quiet quarter was
    quiet when the events simply fell outside the query."""
    _seed_events(store, "kill_switch_set")
    now = datetime.now(timezone.utc)

    assert derive_soc2_evidence(store, start=now + timedelta(days=1))["CC7"]["total"] == 0
    assert derive_soc2_evidence(store, end=now - timedelta(days=1))["CC7"]["total"] == 0
    assert derive_soc2_evidence(store)["CC7"]["total"] == 1


def test_the_range_is_echoed_so_a_zero_can_be_read_against_its_window(store) -> None:
    """A zero is only interpretable beside the window it was counted over."""
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    end = datetime(2026, 4, 1, tzinfo=timezone.utc)

    evidence = derive_soc2_evidence(store, start=start, end=end)

    assert evidence["CC6"]["range"] == {"start": start.isoformat(), "end": end.isoformat()}
    assert derive_soc2_evidence(store)["CC6"]["range"] == {"start": None, "end": None}


def test_a_naive_bound_is_read_as_utc_like_the_column_it_filters(store) -> None:
    """The audit column is UTC (server-side `now()`), so a bound handed in without a timezone has
    to be read as UTC too — reading it as local time would shift every operator's window by their
    own offset and silently change the counts."""
    _seed_events(store, "kill_switch_set")
    past_naive = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)

    assert derive_soc2_evidence(store, start=past_naive)["CC7"]["total"] == 1


def test_an_aware_bound_in_another_zone_is_converted_not_truncated(store) -> None:
    """A caller in UTC+14 passing 'yesterday' must not have its offset dropped."""
    _seed_events(store, "kill_switch_set")
    far_east = timezone(timedelta(hours=14))
    yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).astimezone(far_east)

    assert derive_soc2_evidence(store, start=yesterday)["CC7"]["total"] == 1
