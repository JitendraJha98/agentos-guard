"""RUN-07 — emergency shutdown: incident table, event kinds, store behavior (Slice 9e).

Emergency shutdown EXTENDS the RUN-01/02 kill switch rather than adding a second halt: it sets the
same fleet flag (so the pipeline's stage-0 check halts every agent with no new hot-path code), but
adds a MANDATORY justification, an append-only incident record (the upserted `kill_switch` table
holds only current state), an explicit resume, and a distinguishable `emergency` scope.

The free-text justification lives in the `emergency_shutdown` TABLE only — the audit body carries
short identifiers + the incident id, so a hostile/secret-bearing justification can never trip the
AUD-04 gate and thereby BLOCK an emergency stop.
"""

import asyncio

import pytest
from sqlalchemy import create_engine, select

from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.killswitch import EmergencyActiveError, KillSwitchStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, EmergencyShutdown

# A canary that WOULD trip the AUD-04 secret gate if it ever reached an audit body.
CANARY = "rotate AKIA1234567890ABCDEF now"


@pytest.fixture
def store():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def ks(store) -> KillSwitchStore:
    return KillSwitchStore(store, AuditWriter(store))


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def _all_bodies(store) -> str:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return "\n".join(canonical_json(r.body).decode("utf-8") for r in rows)


# --- Task 1: table round-trip + event kinds --------------------------------------


def test_emergency_shutdown_row_round_trips(store) -> None:
    with store() as s:
        s.add(EmergencyShutdown(justification="prompt-injection incident", declared_by="op"))
        s.commit()
    with store() as s:
        row = s.scalar(select(EmergencyShutdown))
    assert row.justification == "prompt-injection incident"
    assert row.declared_by == "op"
    assert row.declared_at is not None
    assert row.resumed_at is None and row.resumed_by is None  # open incident


def test_both_event_kinds_are_registered(store) -> None:
    audit = AuditWriter(store)
    asyncio.run(audit.append_event("emergency_shutdown", {"incident_id": "i", "scope": "fleet"}))
    asyncio.run(audit.append_event("emergency_resume", {"incident_id": "i", "scope": "fleet"}))
    assert len(_events(store, "emergency_shutdown")) == 1
    assert len(_events(store, "emergency_resume")) == 1
    with pytest.raises(ValueError):  # an unknown kind is still refused
        asyncio.run(audit.append_event("emergency_nonsense", {"x": "y"}))


# --- Task 2: store — emergency_shutdown() / resume_fleet() ----------------------


def test_shutdown_halts_every_agent_with_emergency_scope(ks: KillSwitchStore) -> None:
    """The halt is the RUN-02 fleet flag, so even an agent never seen before is denied — but the
    scope is `emergency`, which the pipeline's f"{scope}_killed" renders as emergency_killed."""
    incident_id = asyncio.run(
        ks.emergency_shutdown(justification="incident 42", set_by="op")
    ).incident_id
    assert incident_id
    status = ks.status("an-agent-never-seen-before")
    assert status is not None and status.scope == "emergency"
    assert ks.active_incident() == incident_id


def test_shutdown_persists_justification_in_the_table_only(ks: KillSwitchStore, store) -> None:
    incident_id = asyncio.run(
        ks.emergency_shutdown(justification="incident 42", set_by="op")
    ).incident_id
    with store() as s:
        row = s.scalar(select(EmergencyShutdown))
    assert str(row.id) == incident_id
    assert row.justification == "incident 42" and row.declared_by == "op"

    event = _events(store, "emergency_shutdown")[0]
    assert event["incident_id"] == incident_id
    assert event["scope"] == "fleet" and event["set_by"] == "op"
    assert "justification" not in event
    assert "incident 42" not in canonical_json(event).decode("utf-8")

    # The FLAG's reason is a short identifier pointing at the incident, NOT the justification: the
    # pipeline's stage-0 deny copies it into the hash-covered DECISION body, so free text there
    # could trip the AUD-04 gate and downgrade the deny away from `emergency_killed`.
    assert ks.status("a").reason == f"emergency shutdown (incident {incident_id})"


@pytest.mark.parametrize("bad", ["", "   ", "\t\n"])
def test_missing_justification_is_rejected_and_nothing_is_halted(
    ks: KillSwitchStore, store, bad: str
) -> None:
    """The justification is MANDATORY: an unexplained fleet stop is not an auditable control, so it
    is refused at the store — and NOTHING is halted, no row written, no event appended."""
    with pytest.raises(ValueError):
        asyncio.run(ks.emergency_shutdown(justification=bad, set_by="op"))
    assert ks.status("a") is None  # nothing halted
    assert ks.active_incident() is None
    with store() as s:
        assert s.scalar(select(EmergencyShutdown)) is None
    assert _events(store, "emergency_shutdown") == []


def test_resume_closes_the_incident_and_restores_service(ks: KillSwitchStore, store) -> None:
    incident_id = asyncio.run(
        ks.emergency_shutdown(justification="incident 42", set_by="op")
    ).incident_id
    asyncio.run(ks.resume_fleet(set_by="op2"))
    assert ks.status("a") is None  # service restored
    assert ks.active_incident() is None  # incident closed
    with store() as s:
        row = s.scalar(select(EmergencyShutdown))
    assert row.resumed_at is not None and row.resumed_by == "op2"
    event = _events(store, "emergency_resume")[0]
    assert event["incident_id"] == incident_id and event["set_by"] == "op2"


def test_routine_fleet_kill_still_reports_fleet_scope(ks: KillSwitchStore) -> None:
    """Regression guard on RUN-02: a routine kill_fleet must STILL read `fleet` (fleet_killed), so
    forensics can tell a routine fleet kill from an emergency stop."""
    asyncio.run(ks.kill_fleet(set_by="op", reason="incident"))
    assert ks.status("a").scope == "fleet"


def test_restart_during_an_open_incident_reloads_halt_and_emergency_scope(store) -> None:
    """A restart must not silently DOWNGRADE an emergency stop to a routine fleet kill."""
    first = KillSwitchStore(store, AuditWriter(store))
    asyncio.run(first.emergency_shutdown(justification="incident 42", set_by="op"))

    second = KillSwitchStore(store, AuditWriter(store))
    status = second.status("some-other-agent")
    assert status is not None and status.scope == "emergency"

    # And after a resume, a fresh store comes back clean.
    asyncio.run(second.resume_fleet(set_by="op"))
    third = KillSwitchStore(store, AuditWriter(store))
    assert third.status("a") is None


def test_secret_bearing_justification_still_shuts_down_and_never_reaches_audit(
    ks: KillSwitchStore, store
) -> None:
    """The whole point of table-only free text: a hostile string must never be able to BLOCK an
    emergency stop by tripping the AUD-04 secret gate."""
    incident_id = asyncio.run(
        ks.emergency_shutdown(justification=CANARY, set_by="op")
    ).incident_id
    assert ks.status("a").scope == "emergency"  # the stop SUCCEEDED
    with store() as s:
        assert s.scalar(select(EmergencyShutdown)).justification == CANARY  # table keeps it
    assert CANARY not in _all_bodies(store)  # no audit event body carries it
    assert "AKIA1234567890ABCDEF" not in _all_bodies(store)
    assert _events(store, "emergency_shutdown")[0]["incident_id"] == incident_id


def test_chain_stays_verifiable_across_shutdown_and_resume(ks: KillSwitchStore, store) -> None:
    from agentos_controlplane.audit_verify import verify_chain

    asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    assert verify_chain(store).ok
    asyncio.run(ks.resume_fleet(set_by="op"))
    assert verify_chain(store).ok


# --- Slice 9e review fixes ------------------------------------------------------


def test_routine_clear_fleet_cannot_lift_an_emergency(ks: KillSwitchStore, store) -> None:
    """The routine RUN-02 clear path must NOT be a second, unjustified way out of an emergency:
    it is refused while an incident is open, so the emergency state and the incident row can never
    diverge (which is what used to let a later routine fleet kill report `emergency`)."""
    incident_id = asyncio.run(
        ks.emergency_shutdown(justification="incident 42", set_by="op")
    ).incident_id

    with pytest.raises(EmergencyActiveError):
        asyncio.run(ks.clear_fleet(set_by="someone"))

    assert ks.status("a").scope == "emergency"  # still halted — nothing was lifted
    assert ks.active_incident() == incident_id  # incident still open
    assert KillSwitchStore(store, AuditWriter(store)).status("a").scope == "emergency"

    # Only the explicit resume gets out, and then the routine paths work normally again.
    asyncio.run(ks.resume_fleet(set_by="op2"))
    assert ks.active_incident() is None
    asyncio.run(ks.kill_fleet(set_by="op", reason="routine"))
    assert ks.status("a").scope == "fleet"  # NOT a sticky `emergency`
    assert KillSwitchStore(store, AuditWriter(store)).status("a").scope == "fleet"


def test_routine_fleet_kill_is_refused_while_an_incident_is_open(ks: KillSwitchStore) -> None:
    """A routine fleet kill must not overwrite (and thereby downgrade) a live emergency halt."""
    asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    with pytest.raises(EmergencyActiveError):
        asyncio.run(ks.kill_fleet(set_by="op", reason="routine"))
    assert ks.status("a").scope == "emergency"


def test_list_active_reports_the_emergency_scope_for_the_fleet_row(ks: KillSwitchStore) -> None:
    """The dashboard renders a 'clear fleet' button off this scope — it must not offer the routine
    clear for an emergency row."""
    asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    assert [k["scope"] for k in ks.list_active() if k["target"] == "*"] == ["emergency"]
    asyncio.run(ks.resume_fleet(set_by="op"))
    asyncio.run(ks.kill_fleet(set_by="op", reason="routine"))
    assert [k["scope"] for k in ks.list_active() if k["target"] == "*"] == ["fleet"]


def test_open_incident_alone_reasserts_the_halt_on_restart(store) -> None:
    """The incident table is AUTHORITATIVE for containment: if the two tables diverge (a crash
    between the two commits), a restart must come up HALTED, not running."""
    with store() as s:  # an open incident, and NO kill_switch row — the divergence
        s.add(EmergencyShutdown(justification="incident 42", declared_by="op"))
        s.commit()
    ks = KillSwitchStore(store, AuditWriter(store))
    status = ks.status("any-agent")
    assert status is not None and status.scope == "emergency"
    assert ks.active_incident() is not None


def test_over_long_justification_still_halts_and_is_truncated(ks: KillSwitchStore, store) -> None:
    """A last-resort control must never refuse to fire over input FORMATTING: an operator pasting a
    stack trace still halts the fleet; only the stored tail is dropped."""
    long_text = "x" * 5000
    incident_id = asyncio.run(
        ks.emergency_shutdown(justification=long_text, set_by="op")
    ).incident_id
    assert ks.status("a").scope == "emergency"  # the stop FIRED
    with store() as s:
        row = s.scalar(select(EmergencyShutdown))
    assert str(row.id) == incident_id
    assert row.justification == "x" * 2000  # head kept, tail dropped


def test_a_second_declaration_while_one_is_open_is_refused(ks: KillSwitchStore, store) -> None:
    """Single-incident model: a second declaration is a 409, so resume can never un-halt the fleet
    while another operator's incident is still open."""
    first = asyncio.run(
        ks.emergency_shutdown(justification="incident A", set_by="alice")
    ).incident_id
    with pytest.raises(EmergencyActiveError):
        asyncio.run(ks.emergency_shutdown(justification="incident B", set_by="bob"))
    assert ks.active_incident() == first
    assert ks.status("a").scope == "emergency"
    with store() as s:
        assert len(s.scalars(select(EmergencyShutdown)).all()) == 1


def test_resume_closes_every_open_incident_before_un_halting(ks: KillSwitchStore, store) -> None:
    """Defence in depth for pre-existing/legacy rows: the fleet must never come back while ANY
    declared incident is still open, so resume closes them all."""
    asyncio.run(ks.emergency_shutdown(justification="incident A", set_by="alice"))
    with store() as s:  # a second open row smuggled in past the single-incident guard
        s.add(EmergencyShutdown(justification="incident B", declared_by="bob"))
        s.commit()

    asyncio.run(ks.resume_fleet(set_by="alice"))
    assert ks.status("a") is None
    assert ks.active_incident() is None  # NO incident left open while the fleet runs
    with store() as s:
        rows = s.scalars(select(EmergencyShutdown)).all()
    assert all(r.resumed_at is not None and r.resumed_by == "alice" for r in rows)
    assert KillSwitchStore(store, AuditWriter(store)).status("a") is None


def test_secret_shaped_set_by_is_refused_before_anything_is_halted(
    ks: KillSwitchStore, store
) -> None:
    """`set_by` rides verbatim into two hash-covered audit bodies, so a secret there would trip the
    AUD-04 gate MID-flight and leave the fleet halted but entirely unaudited. Reject it first."""
    with pytest.raises(ValueError):
        asyncio.run(ks.emergency_shutdown(justification="halt", set_by="AKIAIOSFODNN7EXAMPLE"))
    assert ks.status("a") is None  # nothing halted
    assert ks.active_incident() is None
    with store() as s:
        assert s.scalar(select(EmergencyShutdown)) is None
    assert _events(store, "emergency_shutdown") == []


def test_shutdown_halts_even_when_the_incident_insert_fails(ks: KillSwitchStore) -> None:
    """Containment FIRST: a DB blip on the durable record must not block the stop."""

    def boom():
        raise RuntimeError("db down")

    ks._sf = boom
    result = asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    assert ks.status("a").scope == "emergency"  # HALTED anyway
    assert result.incident_id and result.degraded  # reported as degraded, not raised


def test_shutdown_reports_degraded_when_the_audit_append_fails(ks: KillSwitchStore) -> None:
    """`halted but unaudited` must be distinguishable from `not halted at all` — the operator gets
    the incident id plus a degraded marker instead of a bare exception they would retry."""

    async def boom(*_a, **_k):
        raise RuntimeError("audit down")

    ks._audit.append_event = boom
    result = asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    assert ks.status("a").scope == "emergency"
    assert result.incident_id == ks.active_incident()
    assert "audit" in result.degraded


def test_a_clean_shutdown_reports_no_degradation(ks: KillSwitchStore) -> None:
    result = asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    assert result.degraded == ()
