# Phase 4 · Slice 4b — CI Chain Verifier — Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end with a second
> `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task. Gates `floor_invariant` (430) +
> `regression_lock` (10) green at every commit.

**Goal (AUD-05):** A standalone, CI-runnable verifier that re-derives every integrity property of
the audit chain from the stored rows + the public key ONLY — never trusting a stored derived field
— and detects any retroactive edit, exiting non-zero at the first violation. This is what turns the
hash chain + per-record signatures (4a) into an actually-checkable tamper detector; offline,
dependency-light (sqlite3 + cryptography), no Docker.

**Design:** reuse `canonical_json` + `verify_record_signature` from `audit.py` (the
canonicalization-pin invariant — identical bytes to what was hashed/signed; do NOT reimplement).
Stream rows seq-ascending; per row check, in order: (1) genesis, (2) seq continuity, (3) body↔column
agreement, (4) record_hash recompute, (5) prev_hash linkage against the prior RECOMPUTED hash, (6)
per-record Ed25519 signature (when a pubkey is supplied). Checkpoint-anchor validation (step 7) and
truncation-of-the-tail detection land in **Slice 4c** (they need the `chain_checkpoint` table). The
honest guarantee 4b delivers: **any tamper by someone WITHOUT the control-plane private key is caught
at the hash or signature step** — a full consistent rewrite requires the private key (live-compromise
/ key-custody case, addressed by anchoring + KMS later).

## File structure
- Create `packages/controlplane/src/agentos_controlplane/audit_verify.py` — `Violation`,
  `VerifyResult`, `verify_chain(session_factory, public_key_pem=None)`, and a `__main__` CLI.
- Tests: `tests/unit/test_audit_verify.py` (the tamper-class matrix) + a CLI subprocess test.

---

### Task 1: `verify_chain` + the tamper-class matrix
**Files:** create `audit_verify.py`; test `tests/unit/test_audit_verify.py`.

- [ ] **Implement `audit_verify.py`:**
```python
"""AUD-05 — standalone CI audit-chain verifier.

Re-derives every integrity property from the stored rows + the control-plane public key ONLY
(never trusting a stored derived field), streaming seq-ascending, returning the FIRST violation.
Reuses canonical_json + verify_record_signature from audit.py so the bytes are byte-identical to
what was hashed and signed (the canonicalization-pin invariant).

Guarantee: any retroactive edit by someone WITHOUT the control-plane private key is caught — a body
edit breaks record_hash (step 4); recomputing that row's hash breaks the next row's prev_hash link
(step 5); and a forger who cannot re-sign fails the signature check (step 6). A full consistent
rewrite requires the private key (the live-compromise/key-custody case) and the external anchoring
of Slice 4c; checkpoint-anchor + tail-truncation checks are added there.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.audit import canonical_json, verify_record_signature
from agentos_controlplane.store.models import AuditRecord


@dataclass(frozen=True)
class Violation:
    seq: int | None
    check: str
    detail: str


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    records_checked: int
    violation: Violation | None = None


def verify_chain(
    session_factory: sessionmaker[Session], public_key_pem: str | bytes | None = None
) -> VerifyResult:
    """Verify the whole chain. If `public_key_pem` is given, every signed row's Ed25519
    signature is checked under it; unsigned rows skip step 6."""
    with session_factory() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()

    prev_recomputed = None  # the RECOMPUTED record_hash of the previous row
    n = 0
    for expected_seq, row in enumerate(rows):
        # (1) genesis / (2) seq continuity — strict, no gaps/dups/reorder
        if row.seq != expected_seq:
            return VerifyResult(False, n, Violation(row.seq, "seq_continuity",
                f"expected seq {expected_seq}, got {row.seq}"))
        if expected_seq == 0 and row.prev_hash is not None:
            return VerifyResult(False, n, Violation(row.seq, "genesis", "genesis prev_hash must be NULL"))
        # (3) body must agree with the columns (defeats fix-column-leave-body and vice-versa)
        body = row.body
        if body.get("seq") != row.seq or body.get("prev_hash") != row.prev_hash:
            return VerifyResult(False, n, Violation(row.seq, "body_column_agreement",
                "body seq/prev_hash disagree with the row columns"))
        # (4) record_hash recompute — THE retroactive-edit detector
        canonical = canonical_json(body)
        recomputed = hashlib.sha256(canonical).hexdigest()
        if recomputed != row.record_hash:
            return VerifyResult(False, n, Violation(row.seq, "record_hash",
                "recomputed record_hash != stored record_hash"))
        # (5) prev_hash linkage — against the prior RECOMPUTED hash, not the stored one
        if row.prev_hash != prev_recomputed:
            return VerifyResult(False, n, Violation(row.seq, "prev_hash_linkage",
                "prev_hash != prior row's recomputed record_hash"))
        # (6) per-record signature (AUD-08) — catches a forger without the private key
        if public_key_pem is not None and row.signature is not None:
            if not verify_record_signature(public_key_pem, bytes.fromhex(row.signature), canonical):
                return VerifyResult(False, n, Violation(row.seq, "signature",
                    "Ed25519 signature invalid under the provided public key"))
        prev_recomputed = recomputed
        n += 1
    return VerifyResult(True, n, None)
```
- [ ] **Tests** (`tests/unit/test_audit_verify.py`) — build a signed chain, then prove each tamper
  class is caught at the right step. Helper:
```python
import asyncio
import hashlib
import pytest
from sqlalchemy import create_engine, select, update
from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

def _signed_chain():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    sf = create_session_factory(engine)
    sign = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    w = AuditWriter(sf, signer=sign)
    for i in range(3):
        a = AgentAction(agent_id="a", type=ActionType.tool_call, target="http_get",
                        payload={"url": "https://api.example.com"})
        d = Decision(action_id=a.id, outcome=Outcome.allow)
        asyncio.run(w.append(a, d))
    asyncio.run(w.append_event("approval_resolved", {"approval_id": "x", "resolver": "op", "approved": True}))
    return sf, sign.public_key_pem

def _row(sf, seq):
    with sf() as s:
        return s.scalars(select(AuditRecord).where(AuditRecord.seq == seq)).one()

def test_clean_signed_chain_verifies():
    sf, pub = _signed_chain()
    r = verify_chain(sf, public_key_pem=pub)
    assert r.ok and r.records_checked == 4

def test_body_edit_caught_at_record_hash():
    sf, pub = _signed_chain()
    with sf() as s:                      # attacker edits a body field, leaves record_hash
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body); body["outcome"] = "deny"
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(body=body)); s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 1 and r.violation.check == "record_hash"

def test_deleted_middle_row_caught_at_seq_continuity():
    sf, pub = _signed_chain()
    with sf() as s:
        s.execute(AuditRecord.__table__.delete().where(AuditRecord.seq == 1)); s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.check == "seq_continuity"

def test_edit_plus_rehash_breaks_next_prev_hash():
    sf, pub = _signed_chain()
    with sf() as s:                      # edit seq 1 AND recompute its record_hash; leave seq 2's prev_hash
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        body = dict(row.body); body["outcome"] = "deny"
        new_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        s.execute(update(AuditRecord).where(AuditRecord.seq == 1).values(body=body, record_hash=new_hash)); s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 2 and r.violation.check == "prev_hash_linkage"

def test_corrupted_signature_caught_at_signature_step():
    sf, pub = _signed_chain()
    with sf() as s:                      # flip a hex char of seq 2's signature (body untouched)
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 2)).one()
        sig = row.signature
        flipped = ("0" if sig[0] != "0" else "1") + sig[1:]
        s.execute(update(AuditRecord).where(AuditRecord.seq == 2).values(signature=flipped)); s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok and r.violation.seq == 2 and r.violation.check == "signature"

def test_body_column_disagreement_caught():
    sf, pub = _signed_chain()
    with sf() as s:                      # change the seq COLUMN but not body.seq
        s.execute(update(AuditRecord).where(AuditRecord.seq == 2).values(seq=99)); s.commit()
    r = verify_chain(sf, public_key_pem=pub)
    assert not r.ok  # caught at seq_continuity (99 != expected 2) — reordering/renumber class

def test_unsigned_chain_still_hash_verifies_without_pubkey():
    engine = create_engine("sqlite+pysqlite:///:memory:"); create_all(engine)
    sf = create_session_factory(engine)
    w = AuditWriter(sf)  # no signer
    a = AgentAction(agent_id="a", type=ActionType.tool_call, target="http_get", payload={"url": "https://api.example.com"})
    asyncio.run(w.append(a, Decision(action_id=a.id, outcome=Outcome.allow)))
    assert verify_chain(sf).ok  # hash chain verifies; signature step skipped (no pubkey, unsigned rows)
```
- [ ] Green. Commit `feat(controlplane): AUD-05 chain verifier — recompute hashes/links/signatures, first-violation (AUD-05)`.

### Task 2: CLI + integration test
**Files:** `audit_verify.py` (`__main__`); `tests/integration/test_audit_verify_cli.py`.

- [ ] **Add the CLI** to `audit_verify.py`:
```python
def _main(argv: list[str] | None = None) -> int:
    import argparse
    from sqlalchemy import create_engine
    from agentos_controlplane.store.engine import create_session_factory

    p = argparse.ArgumentParser(prog="agentos_controlplane.audit_verify",
                                description="Re-validate the tamper-evident audit chain (AUD-05).")
    p.add_argument("--db", required=True, help="SQLite file path or a SQLAlchemy URL")
    p.add_argument("--pubkey", help="path to the control-plane public-key PEM (enables signature checks)")
    args = p.parse_args(argv)
    url = args.db if "://" in args.db else f"sqlite+pysqlite:///{args.db}"
    sf = create_session_factory(create_engine(url))
    pub = open(args.pubkey, encoding="utf-8").read() if args.pubkey else None
    result = verify_chain(sf, public_key_pem=pub)
    if result.ok:
        print(f"OK: {result.records_checked} records verified")
        return 0
    v = result.violation
    print(f"FAIL at seq {v.seq}: {v.check} — {v.detail}")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
```
- [ ] **Integration test** (`tests/integration/test_audit_verify_cli.py`): build a signed chain in a
  FILE-backed SQLite under `tmp_path` (so the subprocess sees it), write the pubkey PEM to a file,
  then `subprocess.run([sys.executable, "-m", "agentos_controlplane.audit_verify", "--db", <path>,
  "--pubkey", <pem path>])` → exit 0 + "OK:" in stdout; then tamper a body row and assert exit 1 +
  "FAIL at seq" in stdout. (Build the chain via AuditWriter over `create_engine("sqlite+pysqlite:///"+path)`.)
- [ ] Green. Commit `feat(controlplane): audit_verify CLI (python -m ...) + subprocess integration test (AUD-05)`.

### Task 3: full gate
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy
  (verifier is offline tooling, not on the hot path). Report counts. Commit only if incidental fixes
  were needed.

## Self-review
AUD-05: recomputes hashes + links + signatures from rows+pubkey only (no trusted derived field);
first-violation with seq+check; reuses the pinned canonical_json + verify_record_signature; tamper
matrix proves each class (body edit→record_hash, delete→seq_continuity, edit+rehash→prev_hash_linkage,
bad sig→signature, column/body disagreement→caught); CLI exits non-zero on tamper; honest residual
(full re-sign needs the private key → 4c anchoring) documented. Gates green.
