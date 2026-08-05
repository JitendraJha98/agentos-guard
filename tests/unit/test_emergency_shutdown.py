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
