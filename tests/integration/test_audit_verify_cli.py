"""AUD-05 CLI integration — `python -m agentos_controlplane.audit_verify` (Slice 4b).

The verifier ships as offline CI tooling. This drives it as a real subprocess against a
FILE-backed SQLite under tmp_path (a subprocess cannot see an in-memory engine), with the
control-plane public-key PEM written to a file. Clean chain -> exit 0 + "OK:"; a tampered
body row -> exit 1 + "FAIL at seq".
"""

import asyncio
import subprocess
import sys

from sqlalchemy import create_engine, select, update

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord


def _build_file_chain(db_path):
    engine = create_engine(f"sqlite+pysqlite:///{db_path}")
    create_all(engine)
    sf = create_session_factory(engine)
    sign = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    w = AuditWriter(sf, signer=sign)
    for _ in range(3):
        a = AgentAction(
            agent_id="a",
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": "https://api.example.com"},
        )
        asyncio.run(w.append(a, Decision(action_id=a.id, outcome=Outcome.allow)))
    engine.dispose()  # release the SQLite file handle before the subprocess opens it
    return sf, sign.public_key_pem


def _run_cli(db_path, pubkey_path):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "agentos_controlplane.audit_verify",
            "--db",
            str(db_path),
            "--pubkey",
            str(pubkey_path),
        ],
        capture_output=True,
        text=True,
    )


def test_cli_exit0_on_clean_chain(tmp_path):
    db = tmp_path / "audit.db"
    _sf, pub = _build_file_chain(db)
    pem = tmp_path / "pub.pem"
    pem.write_text(pub, encoding="utf-8")

    proc = _run_cli(db, pem)
    assert proc.returncode == 0, proc.stderr
    assert "OK:" in proc.stdout


def test_cli_exit1_on_tampered_body(tmp_path):
    db = tmp_path / "audit.db"
    sf, pub = _build_file_chain(db)
    pem = tmp_path / "pub.pem"
    pem.write_text(pub, encoding="utf-8")

    # Attacker edits a body field, leaving record_hash -> caught at record_hash.
    with sf() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body)
        body["outcome"] = "deny"
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(body=body))
        s.commit()

    proc = _run_cli(db, pem)
    assert proc.returncode == 1, proc.stdout
    assert "FAIL at seq" in proc.stdout
