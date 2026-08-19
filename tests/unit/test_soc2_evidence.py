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

import json

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import EVENT_KINDS, AuditWriter
from agentos_controlplane.compliance import (
    SOC2_CRITERIA,
    SOC2_DISCLAIMER,
    SOC2_SCOPE,
    derive_soc2_evidence,
)
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


# Frozen 2026-08-19 against the AICPA Trust Services Criteria (TSP section 100, 2017 criteria).
# Nothing else pins these: `test_every_cited_criterion_point_belongs_to_its_own_family` is a
# `CC\d\.\d+` regex, so renaming a family "Risk Mitigation" or citing CC6.9 — which does not exist,
# the 2017 CC6 series running .1 to .8 — shipped green. Re-verify against the AICPA text before
# editing, and add nothing that has not been checked there: an unverified point reference in an
# auditor-facing artifact is the same failure as an unverified article number.
_VERIFIED_SOC2_CITATIONS = {
    "CC6": ("Logical and Physical Access Controls", ("CC6.1", "CC6.3")),
    "CC7": ("System Operations", ("CC7.2", "CC7.4")),
    "CC8": ("Change Management", ("CC8.1",)),
}


def test_every_family_heading_and_point_matches_the_verified_text() -> None:
    assert {
        name: (c["name"], tuple(c["criteria"])) for name, c in SOC2_CRITERIA.items()
    } == _VERIFIED_SOC2_CITATIONS


# --- D-8: the SOC 2 half must not read as an attestation ---------------------


def test_every_criterion_carries_the_disclaimer_and_the_scope(store) -> None:
    """A SOC 2 report is an attestation ISSUED BY an independent licensed CPA firm. This output
    reproduces AICPA family headings and point references next to counts — the shape of a
    control-effectiveness table out of such a report — so forwarded without a disclaimer it is
    indistinguishable from attested evidence. It travels inside each criterion because the function
    returns a bare {CC6:..., CC7:..., CC8:...} map with no wrapper level to hang it from, so any
    single criterion lifted out still carries it."""
    for name, criterion in derive_soc2_evidence(store).items():
        assert criterion["disclaimer"] == SOC2_DISCLAIMER, name
        assert criterion["scope"] == SOC2_SCOPE, name


def test_the_soc2_evidence_never_claims_conformity(store, assert_no_conformity_claim) -> None:
    """The EU half got this guard because of D-8; the SOC 2 half — touching the more strongly
    gate-kept attestation regime — had none, so an evidence string reading "demonstrates that the
    change-management control OPERATED EFFECTIVELY throughout the period" shipped green. That is
    precisely the determination a SOC 2 Type II auditor makes and this tool must not."""
    _seed_events(store, "kill_switch_set", "privilege_ring_set")
    blob = json.dumps(derive_soc2_evidence(store)).lower()

    assert_no_conformity_claim(blob)
    assert "not a soc 2 report" in blob
    assert "not an opinion" in blob
    assert "out of scope" in blob  # three families of nine, said out loud


def test_the_counted_outcomes_are_named_rather_than_implied() -> None:
    """CC6's prose promised "the per-action decisions that refused or gated access" while the code
    counted two of the six gating outcomes, so deleting `require_approval` from the tuple entirely
    left every test passing. Either the set is complete or the prose names it; this pins the
    second, and pins the omissions to a reason."""
    counted = SOC2_CRITERIA["CC6"]["outcomes"]
    assert set(counted) == {Outcome.deny.value, Outcome.require_approval.value}

    evidence = SOC2_CRITERIA["CC6"]["evidence"]
    for outcome in counted:
        assert f"`{outcome}`" in evidence, outcome
    gating = {o.value for o in Outcome} - {Outcome.allow.value, Outcome.warn.value}
    for uncounted in gating - set(counted):
        assert f"`{uncounted}`" in evidence, f"{uncounted} is silently uncounted"


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

    window = evidence["CC6"]["range"]
    assert (window["start"], window["end"]) == (start.isoformat(), end.isoformat())
    empty = derive_soc2_evidence(store)["CC6"]["range"]
    assert (empty["start"], empty["end"]) == (None, None)


def test_the_uncapped_scan_streams_rather_than_buffering_the_whole_log(store, monkeypatch) -> None:
    """WHITE-BOX on purpose: the difference is invisible on SQLite, which is why the wrong call
    shipped. The scan is deliberately uncapped (a clipped count is a WRONG count reported to
    someone who cannot see it was clipped), and `yield_per` is the whole justification for that.
    `Result.yield_per()` only sets a buffer size on an ALREADY-materialized result; the execution
    OPTION also sets `stream_results`, without which psycopg2 client-side-buffers every `body` in
    the audit table before the first row — no memory bound at all on the production backend."""
    from sqlalchemy.orm import Session

    seen: list[dict] = []
    real = Session.execute

    def spy(self, statement, params=None, **kw):
        seen.append(dict(kw.get("execution_options") or {}))
        return real(self, statement, params, **kw)

    monkeypatch.setattr(Session, "execute", spy)
    derive_soc2_evidence(store)

    assert any(o.get("yield_per") for o in seen), "the scan must pass yield_per as an execution option"


def test_the_window_says_what_it_is_scoped_on_and_what_that_does_not_prove(store) -> None:
    """The one dimension scoping an auditor-facing count is `created_at` — the one field in the
    record the hash chain and the AUD-08 signature do NOT cover (ordering derives from `seq`). An
    auditor reading a count over a window is entitled to know the window itself is administrative
    metadata, and that a whole-second `start` can drop a record written in that same second."""
    note = derive_soc2_evidence(store)["CC6"]["range"]["note"]

    assert "created_at" in note
    assert "seq" in note
    assert "inclusive" in note.lower()


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
