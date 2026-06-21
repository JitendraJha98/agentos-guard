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
            return VerifyResult(
                False,
                n,
                Violation(row.seq, "seq_continuity", f"expected seq {expected_seq}, got {row.seq}"),
            )
        if expected_seq == 0 and row.prev_hash is not None:
            return VerifyResult(
                False, n, Violation(row.seq, "genesis", "genesis prev_hash must be NULL")
            )
        # (3) body must agree with the columns (defeats fix-column-leave-body and vice-versa)
        body = row.body
        if body.get("seq") != row.seq or body.get("prev_hash") != row.prev_hash:
            return VerifyResult(
                False,
                n,
                Violation(
                    row.seq,
                    "body_column_agreement",
                    "body seq/prev_hash disagree with the row columns",
                ),
            )
        # (4) record_hash recompute — THE retroactive-edit detector
        canonical = canonical_json(body)
        recomputed = hashlib.sha256(canonical).hexdigest()
        if recomputed != row.record_hash:
            return VerifyResult(
                False,
                n,
                Violation(row.seq, "record_hash", "recomputed record_hash != stored record_hash"),
            )
        # (5) prev_hash linkage — against the prior RECOMPUTED hash, not the stored one
        if row.prev_hash != prev_recomputed:
            return VerifyResult(
                False,
                n,
                Violation(
                    row.seq, "prev_hash_linkage", "prev_hash != prior row's recomputed record_hash"
                ),
            )
        # (6) per-record signature (AUD-08) — catches a forger without the private key
        if public_key_pem is not None and row.signature is not None:
            if not verify_record_signature(
                public_key_pem, bytes.fromhex(row.signature), canonical
            ):
                return VerifyResult(
                    False,
                    n,
                    Violation(
                        row.seq,
                        "signature",
                        "Ed25519 signature invalid under the provided public key",
                    ),
                )
        prev_recomputed = recomputed
        n += 1
    return VerifyResult(True, n, None)


def _main(argv: list[str] | None = None) -> int:
    import argparse

    from sqlalchemy import create_engine

    from agentos_controlplane.store.engine import create_session_factory

    p = argparse.ArgumentParser(
        prog="agentos_controlplane.audit_verify",
        description="Re-validate the tamper-evident audit chain (AUD-05).",
    )
    p.add_argument("--db", required=True, help="SQLite file path or a SQLAlchemy URL")
    p.add_argument(
        "--pubkey", help="path to the control-plane public-key PEM (enables signature checks)"
    )
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
