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
from agentos_controlplane.killswitch import KillSwitchStore
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
    incident_id = asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
    assert incident_id
    status = ks.status("an-agent-never-seen-before")
    assert status is not None and status.scope == "emergency"
    assert ks.active_incident() == incident_id


def test_shutdown_persists_justification_in_the_table_only(ks: KillSwitchStore, store) -> None:
    incident_id = asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
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
    incident_id = asyncio.run(ks.emergency_shutdown(justification="incident 42", set_by="op"))
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
    incident_id = asyncio.run(ks.emergency_shutdown(justification=CANARY, set_by="op"))
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
