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
from agentos_controlplane.merkle import epoch_message, merkle_root
from agentos_controlplane.store.models import AuditRecord, ChainCheckpoint, MerkleRoot

# AUD-02 (action->decision->fired-principles->outcome linkage) + AUD-03 (policy/constitution
# version provenance): every DECISION record body must carry these keys. Event records carry a
# "kind" instead and are exempt. Keys must be PRESENT (a value may legitimately be null — e.g. an
# identity short-circuit or fail-safe decision never ran the policy engine, so its version is null);
# the check enforces the schema, catching a future writer regression that drops a field.
_REQUIRED_DECISION_KEYS = frozenset(
    {"action_id", "agent_id", "action_type", "outcome", "reasons", "constitution_version", "policy_version"}
)


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
    # AUD-06. The two count DIFFERENT things, deliberately: `epochs_checked` is epochs whose root
    # was re-derived from the verified chain (the substantive check — it always runs), while
    # `skipped_epochs` is epochs whose ANCHOR was not verified, because it is absent or its
    # verification material was not supplied. An epoch can be both: re-derived locally, but with
    # nobody external vouching for when its root existed.
    epochs_checked: int = 0
    skipped_epochs: int = 0


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
    a checkpoint whose verification material was not supplied is SKIPPED (counted, not failed).
    Finally every AUD-06 Merkle epoch must still re-derive its sealed root from those same
    recomputed hashes, must agree with its own signed in-chain announcement, and the epochs must
    tile the chain without a gap — a disclosed inclusion proof is only worth what this pass says
    the root is still worth."""
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
        # (3b) decision-record completeness (AUD-02 linkage + AUD-03 version provenance).
        # Event records carry a 'kind' and are exempt; a decision record must link
        # action -> decision -> fired-principles -> outcome AND carry the version keys (a value
        # may be null — e.g. an identity short-circuit never ran the engine — but the key must
        # be present). Catches a future writer regression that drops a required field.
        if "kind" not in body:
            missing = _REQUIRED_DECISION_KEYS - body.keys()
            if missing:
                return VerifyResult(
                    False,
                    n,
                    Violation(
                        row.seq,
                        "decision_completeness",
                        f"decision record missing required key(s): {sorted(missing)}",
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

    # (8) AUD-06 Merkle epochs — every sealed root must still re-derive from the records in the
    # table. This is what makes a disclosed proof worth anything: a bundle verifies against a root
    # nobody has re-checked only proves the bundle is self-consistent.
    #
    # Leaves come from `recomputed_by_seq`, NEVER the stored record_hash column — the same
    # never-trust-a-stored-derived-field discipline as every step above. A tree built over the
    # stored column would faithfully summarize whatever a forger wrote there, so the Merkle pass
    # would agree with the forgery instead of contradicting it.
    #
    # The merkle_root TABLE is not in the chain: `seq_start`, `seq_end`, `leaf_count` and `root`
    # are writable together, so re-deriving a row against the range that same row declares proves
    # only that the row is self-consistent — a forger who truncates the log and rewrites the row to
    # match gets an OK. What they cannot rewrite is `seal()`'s own `merkle_epoch_sealed` record:
    # it is hash-chained and signed, and it states what was REALLY sealed. Reading it here is the
    # one detection this pass adds that the chain pass cannot already make on its own, and it is
    # the protection seal()'s docstring claims for announcing at all.
    with session_factory() as session:
        epochs = session.scalars(select(MerkleRoot).order_by(MerkleRoot.epoch.asc())).all()
    announced: dict[int, dict] = {}
    for body in (row.body for row in rows):
        # FIRST announcement per epoch wins: an unsigned duplicate appended later (unsigned rows
        # skip step 6) must not be able to displace the genuine one.
        if body.get("kind") == "merkle_epoch_sealed" and isinstance(body.get("epoch"), int):
            announced.setdefault(body["epoch"], body)
    eps_checked = 0
    eps_skipped = 0
    expected_start = 0
    for ep in epochs:
        # Epochs are contiguous by construction. A gap strands every seq between two epochs in NO
        # epoch, where it can never be disclosed; an overlap gives one seq two roots that can
        # disagree about it. The two are named apart because the remediations are opposite — a gap
        # means re-sealing a stranded range, an overlap means deleting a bogus row — and the check
        # name is what a CI consumer keys on.
        if ep.seq_start != expected_start:
            return VerifyResult(
                False,
                n,
                Violation(
                    ep.seq_start,
                    "merkle_range_gap" if ep.seq_start > expected_start else "merkle_epoch_overlap",
                    f"epoch {ep.epoch} starts at {ep.seq_start}, expected {expected_start}",
                ),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
        # Bound the range with ARITHMETIC before materializing it. `seq_end` is attacker-writable
        # and nothing constrains it, so a forged 10**18 never returns: the operator would see a hung
        # CI job, not "forgery caught" — the same never-crash-the-verifier discipline as the
        # malformed-hex and malformed-DER fixes above, applied to never-hang.
        if (
            ep.seq_end < ep.seq_start
            or ep.seq_end - ep.seq_start + 1 != ep.leaf_count
            or ep.seq_end > max_seq
        ):
            return VerifyResult(
                False,
                n,
                Violation(
                    ep.seq_start,
                    "merkle_range_incomplete",
                    f"epoch {ep.epoch}'s range {ep.seq_start}..{ep.seq_end} cannot hold its "
                    f"stated {ep.leaf_count} records",
                ),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
        # The signed announcement, not the table, is the authority on what was sealed.
        ann = announced.get(ep.epoch)
        if ann is None:
            return VerifyResult(
                False,
                n,
                Violation(
                    ep.seq_start,
                    "merkle_announcement_missing",
                    f"epoch {ep.epoch} has no merkle_epoch_sealed record in the chain",
                ),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
        if (ann.get("seq_start"), ann.get("seq_end"), ann.get("leaf_count"), ann.get("root")) != (
            ep.seq_start,
            ep.seq_end,
            ep.leaf_count,
            ep.root,
        ):
            return VerifyResult(
                False,
                n,
                Violation(
                    ep.seq_start,
                    "merkle_announcement_mismatch",
                    f"epoch {ep.epoch}'s row disagrees with the sealed announcement in the chain",
                ),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
        expected_start = ep.seq_end + 1
        span = range(ep.seq_start, ep.seq_end + 1)
        leaves = [recomputed_by_seq[s] for s in span if s in recomputed_by_seq]
        # A record missing from a sealed range means rows were deleted under a root that still
        # claims to cover them — truncation, at epoch granularity.
        if not leaves or len(leaves) != len(span) or len(leaves) != ep.leaf_count:
            return VerifyResult(
                False,
                n,
                Violation(
                    ep.seq_start,
                    "merkle_range_incomplete",
                    f"epoch {ep.epoch} covers {len(leaves)} of its stated {ep.leaf_count} records",
                ),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
        if merkle_root(leaves) != ep.root:
            return VerifyResult(
                False,
                n,
                Violation(
                    ep.seq_start,
                    "merkle_root_mismatch",
                    f"epoch {ep.epoch} no longer re-derives its sealed root (records changed)",
                ),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
        eps_checked += 1
        # Anchoring is a SEPARATE operator step, so an unanchored epoch is normal — surfaced as a
        # skip (its root has local integrity but no external authority), never a violation.
        if ep.anchor_kind is None:
            eps_skipped += 1
            continue
        try:
            # `proof` is nullable here (unlike ChainCheckpoint's), so a row claiming a kind with no
            # proof bytes is reachable by DB write. It cannot verify — and handing None to the
            # dispatch would crash the verifier rather than fail the check, the same trap the
            # malformed-hex signature and malformed-DER token fixes closed above.
            proof_ok = ep.proof is not None and verify_checkpoint_proof(
                ep.anchor_kind,
                ep.proof,
                epoch_message(ep.epoch, ep.seq_start, ep.seq_end, ep.root, ep.leaf_count),
                public_key_pem=public_key_pem,
                tsa_root_pem=tsa_root_pem,
            )
        except CheckpointVerifyUnavailable:
            eps_skipped += 1
            continue
        if not proof_ok:
            return VerifyResult(
                False,
                n,
                Violation(ep.seq_start, "merkle_anchor_proof", "epoch anchor proof did not verify"),
                sigs,
                cps_checked,
                cps_skipped,
                eps_checked,
                eps_skipped,
            )
    return VerifyResult(True, n, None, sigs, cps_checked, cps_skipped, eps_checked, eps_skipped)


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
    p.add_argument(
        "--tsa-root",
        help="path to the TSA root-certificate PEM (enables rfc3161 checkpoint verification)",
    )
    args = p.parse_args(argv)
    url = args.db if "://" in args.db else f"sqlite+pysqlite:///{args.db}"
    sf = create_session_factory(create_engine(url))
    pub = open(args.pubkey, encoding="utf-8").read() if args.pubkey else None
    tsa_root = open(args.tsa_root, encoding="utf-8").read() if args.tsa_root else None
    result = verify_chain(sf, public_key_pem=pub, tsa_root_pem=tsa_root)
    if result.ok:
        print(
            f"OK: {result.records_checked} records, {result.checkpoints_checked} checkpoints "
            f"verified, {result.skipped_checkpoints} skipped; "
            f"{result.epochs_checked} merkle epoch(s) re-derived"
        )
        # The signature step is the ONLY defense against a full consistent rewrite. If it ran
        # zero times on a non-empty chain (no --pubkey, or every row unsigned) the strongest
        # check was entirely skipped — say so loudly so 'OK' is not mistaken for 'intact'.
        if result.records_checked > 0 and result.signatures_checked == 0:
            print(
                f"WARNING: signature check skipped (no pubkey / {result.records_checked} "
                "unsigned rows) — a full rewrite would NOT have been detected"
            )
        # A skipped checkpoint means its external/durability anchor was NOT verified (no pubkey
        # for a local anchor, no --tsa-root for an rfc3161 one) — surface it, not a false pass.
        if result.skipped_checkpoints > 0:
            print(
                f"WARNING: {result.skipped_checkpoints} checkpoint(s) skipped "
                "(missing pubkey / --tsa-root) — their anchor proof was NOT verified"
            )
        # An epoch's root re-deriving proves the records did not change under it — it does NOT date
        # the root. Without a verified anchor, a disclosure against it rests on our word alone.
        if result.skipped_epochs > 0:
            print(
                f"WARNING: {result.skipped_epochs} merkle epoch(s) unanchored or skipped "
                "(not anchored yet / missing pubkey / --tsa-root) — their root carries no "
                "external authority"
            )
        return 0
    v = result.violation
    print(f"FAIL at seq {v.seq}: {v.check} — {v.detail}")
    return 1


if __name__ == "__main__":
    raise SystemExit(_main())
