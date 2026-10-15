"""Phase 15 — one audit chain, many control-plane instances, real Postgres.

The chain was provably correct for ONE process: an `asyncio.Lock` and a cached head. Two instances
behind a load balancer would each cache their own head; the UNIQUE `seq` stopped a silent fork, but
the second instance's appends then failed forever. These tests run genuinely separate OS processes
against one Postgres database and verify the chain they produce, plus the failure edges: a writer
dying mid-transaction, a sealing failure while holding the lock, and a hostile isolation level.
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import textwrap
import threading

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, func, select, text

from _pg import fresh_pg_url, pg_available
from agentos_controlplane.audit import CHAIN_LOCK_KEY, AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.secret_scan import SecretLeakError
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

pytestmark = pytest.mark.skipif(not pg_available(), reason="pgserver/psycopg not installed")

_WORKER = textwrap.dedent(
    """
    import asyncio, sys
    from cryptography.hazmat.primitives import serialization
    from sqlalchemy import create_engine
    from agentos_controlplane.audit import AuditWriter
    from agentos_controlplane.identity_engine import IdentityEngine
    from agentos_controlplane.store.engine import create_session_factory

    url, pem, name, n = sys.argv[1], sys.argv[2].encode(), sys.argv[3], int(sys.argv[4])
    key = serialization.load_pem_private_key(pem, password=None)
    signer = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5, private_key=key)
    writer = AuditWriter(create_session_factory(create_engine(url)), signer=signer)

    async def main():
        for i in range(n):
            await writer.append_event("side_effect", {"instance": name, "i": i})

    asyncio.run(main())
    """
)


@pytest.fixture
def pg_store():
    url = fresh_pg_url()
    engine = create_engine(url)
    create_all(engine)
    key = Ed25519PrivateKey.generate()
    signer = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5, private_key=key)
    yield url, engine, key, signer
    engine.dispose()


def _pem(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def test_separate_processes_build_one_valid_chain(pg_store) -> None:
    """Four OS processes, 40 appends each, all at once: 160 records, seq 0..159, verifiable."""
    url, engine, key, signer = pg_store
    procs = [
        subprocess.Popen([sys.executable, "-c", _WORKER, url, _pem(key), f"p{i}", "40"])
        for i in range(4)
    ]
    assert [p.wait(timeout=180) for p in procs] == [0, 0, 0, 0]

    sf = create_session_factory(engine)
    with sf() as s:
        seqs = s.scalars(select(AuditRecord.seq).order_by(AuditRecord.seq)).all()
    assert seqs == list(range(160))
    result = verify_chain(sf, public_key_pem=signer.public_key_pem)
    assert result.ok, result.violation
    assert result.signatures_checked == 160
    with sf() as s:
        instances = set(s.scalars(select(AuditRecord.body["instance"].as_string())).all())
    assert instances == {"p0", "p1", "p2", "p3"}  # every process actually got its writes in


def test_two_writers_in_one_process_do_not_trust_a_stale_head(pg_store) -> None:
    """The SQLite-mode head cache is exactly the multi-instance bug: writer B's cached head would
    be stale after writer A appends. In Postgres mode neither caches, so interleaving is safe."""
    url, engine, _, signer = pg_store
    a = AuditWriter(create_session_factory(create_engine(url)), signer=signer)
    b = AuditWriter(create_session_factory(create_engine(url)), signer=signer)

    async def interleave():
        for i in range(10):
            await a.append_event("side_effect", {"w": "a", "i": i})
            await b.append_event("side_effect", {"w": "b", "i": i})

    asyncio.run(interleave())
    assert verify_chain(create_session_factory(engine), public_key_pem=signer.public_key_pem).ok


def test_a_sealing_failure_releases_the_lock_and_writes_nothing(pg_store) -> None:
    """The secret-scan gate raises INSIDE the locked transaction. The rollback must release the
    advisory lock (or every other instance hangs) and leave the head where it was."""
    url, engine, _, signer = pg_store
    writer = AuditWriter(create_session_factory(engine), signer=signer)
    asyncio.run(writer.append_event("side_effect", {"i": 0}))
    with pytest.raises(SecretLeakError):
        asyncio.run(writer.append_event("side_effect", {"leak": "AKIAIOSFODNN7EXAMPLE"}))

    # Another connection can take the lock immediately — it was released.
    with engine.connect() as c:
        assert c.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": CHAIN_LOCK_KEY}).scalar()
        c.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": CHAIN_LOCK_KEY})

    asyncio.run(writer.append_event("side_effect", {"i": 1}))
    with create_session_factory(engine)() as s:
        assert s.scalars(select(AuditRecord.seq).order_by(AuditRecord.seq)).all() == [0, 1]


def test_a_writer_that_dies_holding_the_lock_does_not_wedge_the_chain(pg_store) -> None:
    """An instance crashes mid-append: its connection drops without a commit. The xact lock dies
    with the transaction, and the next writer proceeds — while it is held, the writer WAITS."""
    url, engine, _, signer = pg_store
    writer = AuditWriter(create_session_factory(engine), signer=signer)

    holder = create_engine(url).connect()
    trans = holder.begin()
    holder.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CHAIN_LOCK_KEY})

    done = threading.Event()
    t = threading.Thread(
        target=lambda: (asyncio.run(writer.append_event("side_effect", {"i": 0})), done.set())
    )
    t.start()
    assert not done.wait(1.0)  # blocked behind the "crashed" instance's lock

    trans.rollback()  # the crashed instance's transaction ends...
    holder.invalidate()  # ...and its connection is gone
    assert done.wait(10.0)
    t.join()
    with create_session_factory(engine)() as s:
        assert s.scalar(select(func.count()).select_from(AuditRecord)) == 1


def test_repeatable_read_engine_does_not_break_the_chain(pg_store) -> None:
    """An operator configures REPEATABLE READ globally. A snapshot taken before the lock wait would
    miss the previous holder's commit and collide on `seq`; the writer pins READ COMMITTED."""
    url, engine, key, signer = pg_store
    rr_url = url
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WORKER.replace(
                "create_engine(url)", "create_engine(url, isolation_level='REPEATABLE READ')"
            ), rr_url, _pem(key), f"rr{i}", "25"]
        )
        for i in range(3)
    ]
    assert [p.wait(timeout=180) for p in procs] == [0, 0, 0]
    result = verify_chain(create_session_factory(engine), public_key_pem=signer.public_key_pem)
    assert result.ok and result.records_checked == 75, result.violation


def test_sqlite_mode_is_unchanged(tmp_path) -> None:
    """The single-process path keeps its cached head (the PIPE-04 lever). File-backed on purpose:
    AGENTOS_TEST_DB=postgres reroutes in-memory SQLite URLs, and this test is about SQLite."""
    engine = create_engine(f"sqlite+pysqlite:///{(tmp_path / 'a.db').as_posix()}")
    create_all(engine)
    writer = AuditWriter(create_session_factory(engine))
    assert writer._shared is False
    asyncio.run(writer.append_event("side_effect", {"i": 0}))
    assert writer._head is not None
