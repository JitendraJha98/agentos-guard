"""AUD-05 — standalone CI audit-chain verifier.

Re-derives every integrity property from the stored rows + the control-plane public key ONLY
(never trusting a stored derived field), streaming seq-ascending, returning the FIRST violation.
Reuses canonical_json + verify_record_signature from audit.py so the bytes are byte-identical to
what was hashed and signed (the canonicalization-pin invariant).

Guarantee: any retroactive edit by someone WITHOUT the control-plane private key is caught — a body
edit breaks record_hash (step 4); recomputing that row's hash breaks the next row's prev_hash link
(step 5); and a forger who cannot re-sign fails the signature check (step 6). A full consistent
rewrite requires the private key (the live-compromise/key-custody case) — which Slice-4c external
anchoring catches: the checkpoint binds the ORIGINAL head {seq, record_hash} to an unforgeable
proof, so a rewrite of already-checkpointed history no longer matches (checkpoint_mismatch) and a
chain truncated below a checkpointed seq is detected (checkpoint_truncation).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.audit import canonical_json, verify_record_signature
from agentos_controlplane.checkpoint import (
    CheckpointVerifyUnavailable,
    checkpoint_message,
    verify_checkpoint_proof,
)
from agentos_controlplane.store.models import AuditRecord, ChainCheckpoint


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
    signatures_checked: int = 0  # rows whose Ed25519 signature was actually verified (step 6)
    checkpoints_checked: int = 0  # checkpoints whose anchor proof was actually verified (AUD-05)
    skipped_checkpoints: int = 0  # checkpoints skipped for want of verification material (AUD-05)


def verify_chain(
    session_factory: sessionmaker[Session],
    public_key_pem: str | bytes | None = None,
    tsa_root_pem: str | bytes | None = None,
) -> VerifyResult:
    """Verify the whole chain. If `public_key_pem` is given, every signed row's Ed25519
    signature is checked under it; unsigned rows skip step 6. After the per-row loop, every
    ChainCheckpoint is validated (AUD-05): the head hash recomputed at the checkpointed seq must
    match the bound record_hash (checkpoint_mismatch), the chain must be no shorter than a
    checkpointed seq (checkpoint_truncation), and the anchor proof must verify (checkpoint_proof);
    a checkpoint whose verification material was not supplied is SKIPPED (counted, not failed)."""
    with session_factory() as session:
        rows = session.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()

    prev_recomputed = None  # the RECOMPUTED record_hash of the previous row
    n = 0
    sigs = 0  # rows whose signature was actually verified (the full-rewrite defense)
    recomputed_by_seq: dict[int, str] = {}  # {seq: recomputed record_hash} for checkpoint checks
    max_seq = -1
    for expected_seq, row in enumerate(rows):
        # (1) genesis / (2) seq continuity — strict, no gaps/dups/reorder
        if row.seq != expected_seq:
            return VerifyResult(
                False,
                n,
                Violation(row.seq, "seq_continuity", f"expected seq {expected_seq}, got {row.seq}"),
                sigs,
            )
        if expected_seq == 0 and row.prev_hash is not None:
            return VerifyResult(
                False, n, Violation(row.seq, "genesis", "genesis prev_hash must be NULL"), sigs
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
                sigs,
            )
        # (4) record_hash recompute — THE retroactive-edit detector
        canonical = canonical_json(body)
        recomputed = hashlib.sha256(canonical).hexdigest()
        if recomputed != row.record_hash:
            return VerifyResult(
                False,
                n,
                Violation(row.seq, "record_hash", "recomputed record_hash != stored record_hash"),
                sigs,
            )
        # (5) prev_hash linkage — against the prior RECOMPUTED hash, not the stored one
        if row.prev_hash != prev_recomputed:
            return VerifyResult(
                False,
                n,
                Violation(
                    row.seq, "prev_hash_linkage", "prev_hash != prior row's recomputed record_hash"
                ),
                sigs,
            )
        # (6) per-record signature (AUD-08) — catches a forger without the private key
        if public_key_pem is not None and row.signature is not None:
            # A DB attacker can corrupt the signature column with non-hex/odd-length bytes;
            # bytes.fromhex raises ValueError there, so decode INSIDE the try and turn a
            # malformed signature into the defined 'signature' violation (never a crash).
            try:
                sig_bytes = bytes.fromhex(row.signature)
            except ValueError:
                return VerifyResult(
                    False,
                    n,
                    Violation(row.seq, "signature", "signature is not valid hex"),
                    sigs,
                )
            if not verify_record_signature(public_key_pem, sig_bytes, canonical):
                return VerifyResult(
                    False,
                    n,
                    Violation(
                        row.seq,
                        "signature",
                        "Ed25519 signature invalid under the provided public key",
                    ),
                    sigs,
                )
            sigs += 1
        prev_recomputed = recomputed
        recomputed_by_seq[row.seq] = recomputed
        max_seq = row.seq
        n += 1

    # (7) AUD-05 checkpoint anchors — proves no already-checkpointed history was rewritten and
    # the chain was not truncated below a checkpointed seq. Re-derives from the VERIFIED chain
    # (recomputed_by_seq), never the stored derived columns. First-violation-wins, like above.
    with session_factory() as session:
        checkpoints = session.scalars(
            select(ChainCheckpoint).order_by(ChainCheckpoint.seq.asc())
        ).all()
    cps_checked = 0
    cps_skipped = 0
    for cp in checkpoints:
        # Tail-truncation: a checkpoint for a seq past the chain's end means rows were deleted.
        if cp.seq > max_seq:
            return VerifyResult(
                False,
                n,
                Violation(cp.seq, "checkpoint_truncation", "chain shorter than a checkpointed seq"),
                sigs,
                cps_checked,
                cps_skipped,
            )
        # Rewrite-of-checkpointed-history: the recomputed head hash must still match the bound one.
        if recomputed_by_seq.get(cp.seq) != cp.record_hash:
            return VerifyResult(
                False,
                n,
                Violation(
                    cp.seq,
                    "checkpoint_mismatch",
                    "recomputed head hash != checkpoint-bound record_hash (rewritten history)",
                ),
                sigs,
                cps_checked,
                cps_skipped,
            )
        # Anchor proof: the external/durability proof must verify over the bound message. A skip
        # (verification material absent) is surfaced, NOT a false pass and NOT a crash.
        msg = checkpoint_message(cp.seq, cp.record_hash)
        try:
            proof_ok = verify_checkpoint_proof(
                cp.anchor_kind,
                cp.proof,
                msg,
                public_key_pem=public_key_pem,
                tsa_root_pem=tsa_root_pem,
            )
        except CheckpointVerifyUnavailable:
            cps_skipped += 1
            continue
        if not proof_ok:
            return VerifyResult(
                False,
                n,
                Violation(cp.seq, "checkpoint_proof", "checkpoint anchor proof did not verify"),
                sigs,
                cps_checked,
                cps_skipped,
            )
        cps_checked += 1
    return VerifyResult(True, n, None, sigs, cps_checked, cps_skipped)


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
        # The signature step is the ONLY defense against a full consistent rewrite. If it ran
        # zero times on a non-empty chain (no --pubkey, or every row unsigned) the strongest
        # check was entirely skipped — say so loudly so 'OK' is not mistaken for 'intact'.
        if result.records_checked > 0 and result.signatures_checked == 0:
            print(
                f"WARNING: signature check skipped (no pubkey / {result.records_checked} "
                "unsigned rows) — a full rewrite would NOT have been detected"
            )
        return 0
    v = result.violation
    print(f"FAIL at seq {v.seq}: {v.check} — {v.detail}")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
