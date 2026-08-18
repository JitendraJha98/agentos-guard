"""AUD-06 — Merkle tree over the audit chain: inclusion proofs and partial disclosure.

WHY THIS EXISTS. The AUD-01 hash chain proves the log was not rewritten, but it proves it only to
someone holding the WHOLE log. An operator asked to evidence one action to an auditor therefore had
two bad options: disclose everything, or disclose an extract nobody can verify. A Merkle tree adds
the third: disclose one record and a proof path, and the recipient verifies it against a root that
carries external (RFC-3161) authority — learning nothing about the records they were not given.

The chain is UNTOUCHED. This tree is built over `record_hash` values that already exist, so every
shipped guarantee (AUD-01 linkage, AUD-05 verification, AUD-08 signatures, the checkpoints) keeps
holding byte-for-byte. Replacing the chain would have invalidated the very evidence we are here to
make provable.

HASHING RULES (RFC 6962 §2.1), both load-bearing:
  leaf     = SHA256(0x00 ‖ record_hash)
  internal = SHA256(0x01 ‖ left ‖ right)
Domain separation stops an internal node from being presented as a leaf (second-preimage). The odd
node is PROMOTED to the next level, never duplicated: duplicate-padding lets two different leaf
lists share one root (CVE-2012-2459), and a root that does not uniquely determine its contents
proves nothing. Bottom-up promotion is equivalent to RFC 6962's split-at-the-largest-power-of-two
recursion, and is easier to generate proofs against.

WHAT THIS PROVES, AND WHAT IT DOES NOT. A verified proof shows the record was IN the sealed epoch.
It does NOT show the epoch is COMPLETE — a root cannot testify that nothing was withheld before
sealing. Completeness needs a witness quorum observing roots independently, which is out of scope
here (Phase 14). Saying so plainly matters: an operator who believes this proves completeness would
over-claim to an auditor on our word.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import func, select

from agentos_controlplane.audit import canonical_json, verify_record_signature
from agentos_controlplane.checkpoint import (
    CheckpointVerifyUnavailable,
    verify_checkpoint_proof,
)
from agentos_controlplane.store.models import AuditRecord, MerkleRoot

_LEAF = b"\x00"
_NODE = b"\x01"

# One seal reads this many audit rows at most. A first seal on a production chain would otherwise
# load the entire audit table into memory at once; capping the range makes every seal bounded and
# leaves the remainder for the next call, so sealing still drains to completion.
_MAX_EPOCH_LEAVES = 100_000
# One `list_epochs` read returns at most this many rows, sized like graph.py's `_MAX_NODES`: the
# table grows without bound over a deployment's life, and a gated route is still a route.
_MAX_EPOCHS = 1000

Proof = list[tuple[str, str]]


class MerkleError(ValueError):
    """A malformed tree request (empty leaf set, index out of range, an unsealed disclosure)."""


def leaf_hash(record_hash: str) -> str:
    """SHA256(0x00 ‖ record_hash). `record_hash` is the hex digest already on the audit row."""
    return hashlib.sha256(_LEAF + bytes.fromhex(record_hash)).hexdigest()


def node_hash(left: str, right: str) -> str:
    """SHA256(0x01 ‖ left ‖ right)."""
    return hashlib.sha256(_NODE + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def _levels(leaves: list[str]) -> list[list[str]]:
    """Every level bottom-up, level 0 being the leaf hashes. Shared by root and proof so the two
    can never disagree about the tree's shape."""
    if not leaves:
        raise MerkleError("a Merkle tree needs at least one leaf")
    level = [leaf_hash(h) for h in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])  # promote, never duplicate
        level = nxt
        levels.append(level)
    return levels


def merkle_root(leaves: list[str]) -> str:
    """The root over `leaves` (audit `record_hash` values, in seq order)."""
    return _levels(leaves)[-1][0]


def inclusion_proof(leaves: list[str], index: int) -> Proof:
    """The sibling path proving `leaves[index]` is in the tree: [(side, hash), ...] bottom-up,
    where `side` is where the SIBLING sits relative to the running hash.

    A promoted node contributes NO entry at its level — it has no sibling there — which is why the
    path can be shorter than the tree is tall, and why the verifier has to climb rather than assume
    one entry per level.
    """
    if not 0 <= index < len(leaves):
        raise MerkleError(f"index {index} out of range for {len(leaves)} leaves")
    proof: Proof = []
    for level in _levels(leaves)[:-1]:
        if index % 2:
            proof.append(("left", level[index - 1]))
        elif index + 1 < len(level):
            proof.append(("right", level[index + 1]))
        # else: promoted node — it has no sibling at this level, so it contributes nothing
        index //= 2
    return proof


def verify_inclusion(
    record_hash: str, index: int, proof: Proof, root: str, leaf_count: int
) -> bool:
    """Recompute the root from `record_hash` and its proof. The body does no DB access and no I/O —
    only hashlib — so it can run against a disclosed bundle and nothing else. (Importing this MODULE
    pulls the control plane's ORM, because the sealer lives here too; that is a packaging concern,
    not a verification one, and the sentence used to overclaim it.)

    `leaf_count` is what makes the POSITION provable, not just the membership (this is why RFC 6962
    verifies an audit path against the tree size too). The tree size is what says whether a level
    had a sibling at all, so the verifier derives every side from it rather than from the proof's
    length: without it, a path is ambiguous about where it sits — in an 8-leaf tree index 1's path
    replays cleanly at index 2. `seq_start + index` is exactly how a reader locates the record, so
    that is not cosmetic.

    That binding is only as good as `leaf_count` itself: a caller who takes it from the same bundle
    it is checking has bound nothing, because one attacker chose both. `leaf_count` MUST come from
    an authenticated source — which is what `verify_bundle` exists to establish before calling here.

    Returns False on malformed input rather than raising: this runs on data from outside, and a
    traceback is easy to mistake for "the check did not run" when it means "the check failed".
    """
    try:
        if not 0 <= index < leaf_count:
            return False
        current = leaf_hash(record_hash)
        siblings = iter(proof)
        size = leaf_count
        while size > 1:
            # An odd level's last node is promoted, so it consumes no proof entry (see _levels).
            if not (size % 2 and index == size - 1):
                step = next(siblings, None)
                if step is None:
                    return False
                side, sibling = step
                if side != ("left" if index % 2 else "right"):
                    return False
                current = (
                    node_hash(sibling, current) if index % 2 else node_hash(current, sibling)
                )
            index //= 2
            size = (size + 1) // 2
        # Leftover entries mean the path is longer than the tree is tall — a fabricated shape.
        return next(siblings, None) is None and current == root
    except (ValueError, TypeError):
        return False


def epoch_message(epoch: int, seq_start: int, seq_end: int, root: str, leaf_count: int) -> bytes:
    """The exact bytes anchored for a sealed epoch.

    Reuses the audit `canonical_json` so a verifier reproduces them byte-identically, and reuses
    Phase 4's CHECKPOINT_DOMAIN so `verify_checkpoint_proof` works UNCHANGED — no second crypto
    path to get subtly wrong. Sharing that domain makes the message SHAPE the only thing keeping an
    epoch proof from being replayed as a head proof, and the two can never collide: a checkpoint's
    canonical JSON has keys {seq, record_hash}, an epoch's has {epoch, leaf_count, root, seq_end,
    seq_start}.

    `leaf_count` is committed to alongside the range so the anchored bytes pin the epoch's SIZE as
    well as its bounds — a re-seal that dropped records from the same range cannot reuse them.
    """
    return canonical_json(
        {
            "epoch": epoch,
            "leaf_count": leaf_count,
            "root": root,
            "seq_end": seq_end,
            "seq_start": seq_start,
        }
    )


@dataclass(frozen=True)
class BundleResult:
    """What a disclosure bundle actually proved.

    The two flags are separate on purpose, the same distinction `VerifyResult.skipped_epochs`
    draws: `ok` says the disclosed BODY is the record the root commits to, at the seq the bundle
    claims. `anchor_verified` says an authority outside the discloser vouched for that root. Only
    the second makes `root`/`leaf_count` more than numbers in a file the discloser wrote — so a
    caller that collapses these into one boolean is certifying the discloser's own word.
    """

    ok: bool
    anchor_verified: bool = False
    reason: str | None = None


def verify_bundle(
    bundle: dict,
    *,
    public_key_pem: str | bytes | None = None,
    tsa_root_pem: str | bytes | None = None,
) -> BundleResult:
    """Verify a disclosure bundle end to end. THIS is what an auditor runs; `verify_inclusion`
    alone is not enough and must not be handed to one.

    `verify_inclusion` proves a `record_hash` is in a tree. A bundle is a claim about a BODY at a
    SEQ, and nothing in the tree binds either. Every gap that leaves is closed here:

      * body -> record_hash. The proof commits to the hash; swap the body and the proof still
        verifies. An auditor shown `outcome: "allow"` beside "inclusion verified" would certify a
        record that said `deny`.
      * body["seq"] -> the disclosed seq, and seq -> index. `seq_start + index` is how a reader
        locates the record, so an unbound index places a genuine record where it never was.
      * leaf_count -> the epoch's own range. `verify_inclusion` derives the tree's shape from
        `leaf_count`, so a bundle that also supplies it binds nothing: a real record at index 4 of
        5 replays as index 1 of 2. Pinning it to `seq_end - seq_start + 1` means moving the record
        requires moving its seq, which is inside the hashed body.
      * the signature the bundle carries but nothing checked (when a public key is supplied).
      * the anchor. Re-derives `epoch_message` from the bundle's OWN epoch fields and runs the
        shipped AUD-05 dispatch, so `anchored: true` stops being an assertion we cannot check.

    Malformed input is a False result with a reason, never a traceback — same posture as
    `verify_inclusion`, for the same reason.
    """
    try:
        rec, ep = bundle["record"], bundle["epoch"]
        body, index = rec["body"], bundle["index"]
        if hashlib.sha256(canonical_json(body)).hexdigest() != rec["record_hash"]:
            return BundleResult(False, False, "the disclosed body does not hash to record_hash")
        if body["seq"] != rec["seq"]:
            return BundleResult(False, False, "the body's seq disagrees with the disclosed record")
        if ep["leaf_count"] != ep["seq_end"] - ep["seq_start"] + 1:
            return BundleResult(False, False, "the epoch's leaf_count disagrees with its range")
        if index != rec["seq"] - ep["seq_start"]:
            return BundleResult(False, False, "the index disagrees with the record's seq")
        if not verify_inclusion(
            rec["record_hash"], index, bundle["proof"], ep["root"], ep["leaf_count"]
        ):
            return BundleResult(False, False, "the inclusion proof does not verify")
        if public_key_pem is not None and rec.get("signature") is not None:
            if not verify_record_signature(
                public_key_pem, bytes.fromhex(rec["signature"]), canonical_json(body)
            ):
                return BundleResult(False, False, "the record's signature does not verify")
        anchor_proof = ep.get("anchor_proof")
        if ep.get("anchor_kind") is None or anchor_proof is None:
            return BundleResult(True, False, "the epoch root carries no anchor")
        try:
            anchored = verify_checkpoint_proof(
                ep["anchor_kind"],
                bytes.fromhex(anchor_proof),
                epoch_message(
                    ep["epoch"], ep["seq_start"], ep["seq_end"], ep["root"], ep["leaf_count"]
                ),
                public_key_pem=public_key_pem,
                tsa_root_pem=tsa_root_pem,
            )
        except CheckpointVerifyUnavailable as exc:
            return BundleResult(True, False, f"the anchor was not checked: {exc}")
        if not anchored:
            return BundleResult(False, False, "the epoch's anchor proof does not verify")
    except (AttributeError, KeyError, TypeError, ValueError):
        return BundleResult(False, False, "the bundle is malformed")
    return BundleResult(True, True)


class MerkleSealer:
    """Seals audit epochs, anchors their roots, and produces disclosure bundles (AUD-06).

    Operator-/schedule-driven, exactly like checkpointing — nothing here runs on the per-action
    path.
    """

    def __init__(self, session_factory, audit) -> None:
        self._sf = session_factory
        self._audit = audit

    async def seal(self) -> MerkleRoot | None:
        """Seal everything appended since the last epoch. Returns the new epoch, or None when there
        is nothing new to seal.

        The upper bound is READ ONCE and pinned before the leaves are collected. Without that pin,
        a concurrent append could land mid-build and produce a root over a range the row then
        claims is something else — a root that does not match its own stated range is worse than no
        root, because it fails verification and looks like tampering.

        Every seal appends its OWN announcement, which therefore falls into the NEXT epoch: sealing
        converges on one-record epochs rather than on None, so None means an unstarted chain. That
        is the price of keeping the root itself inside the tamper-evident chain, and it is worth
        paying — a root that lived only in this table could be edited without contradicting the
        chain or any signature. `verify_chain` step 8 cashes that in by comparing the two.
        """
        with self._sf() as s:
            last = s.scalars(select(MerkleRoot).order_by(MerkleRoot.epoch.desc()).limit(1)).first()
            start = 0 if last is None else last.seq_end + 1
            epoch = 0 if last is None else last.epoch + 1
            head = s.scalar(select(func.max(AuditRecord.seq)))
            if head is None or head < start:
                return None
            # Cap the range so one seal cannot pull an unbounded audit table into memory; the rest
            # is sealed by the next call, so coverage is delayed, never lost.
            head = min(head, start + _MAX_EPOCH_LEAVES - 1)
            # Columns, not entities: the tree needs `record_hash`, and hydrating whole rows would
            # drag every JSON body through memory to read one string from each.
            rows = s.execute(
                select(AuditRecord.seq, AuditRecord.record_hash)
                .where(AuditRecord.seq >= start, AuditRecord.seq <= head)
                .order_by(AuditRecord.seq.asc())
            ).all()
            # Contiguity is the coverage guarantee: a gap means some record sits in no epoch at all
            # and can never be proven. Refuse rather than seal a range that silently skips records.
            if [r.seq for r in rows] != list(range(start, head + 1)):
                raise MerkleError(f"audit seq range {start}..{head} is not contiguous")
            row = MerkleRoot(
                epoch=epoch,
                seq_start=start,
                seq_end=head,
                root=merkle_root([r.record_hash for r in rows]),
                leaf_count=len(rows),
            )
            s.add(row)
            s.commit()
            # Read out inside the session: the announcement below must carry what was COMMITTED,
            # and a detached row is a footgun to reach into after the fact.
            sealed = {
                "epoch": row.epoch,
                "seq_start": row.seq_start,
                "seq_end": row.seq_end,
                "root": row.root,
                "leaf_count": row.leaf_count,
            }
        # Audited AFTER the commit, so the event's own record lands beyond `head` and belongs to the
        # NEXT epoch — an epoch that contained the record announcing itself could never be sealed.
        # That ordering leaves a window: a failed append (the AUD-04 secret gate, a disk error)
        # would strand a committed epoch with no announcement, permanently outside the chain's
        # protection and indistinguishable from a forger's hand-inserted row. Undo the epoch
        # instead — an unsealed range is sealed again on the next call, an unannounced one is not.
        try:
            await self._audit.append_event("merkle_epoch_sealed", sealed)
        except Exception:
            with self._sf() as s:
                row = s.get(MerkleRoot, sealed["epoch"])
                if row is not None:
                    s.delete(row)
                    s.commit()
            raise
        # Re-read so the caller gets the server-defaulted `created_at` too, never a half-populated
        # row that reads as "this epoch has no sealing time".
        with self._sf() as s:
            return s.get(MerkleRoot, sealed["epoch"])

    def anchor_epoch(self, epoch: int, anchor, *, replace: bool = False) -> None:
        """Bind a sealed root to an external proof (AUD-05's anchors, unchanged).

        Refuses to overwrite an existing anchor unless `replace` is passed. Re-anchoring an
        RFC-3161 epoch with the local anchor would silently trade external authority for a
        durability-only self-signature (checkpoint.py is explicit that the local kind is NOT
        authority) while `anchored` kept reporting true — a downgrade nobody would see.
        """
        with self._sf() as s:
            row = s.get(MerkleRoot, epoch)
            if row is None:
                raise MerkleError(f"epoch {epoch} is not sealed")
            if row.proof is not None and not replace:
                raise MerkleError(
                    f"epoch {epoch} is already anchored ({row.anchor_kind}); "
                    "pass replace=True to deliberately re-anchor it"
                )
            row.anchor_kind = anchor.kind
            row.proof = anchor.anchor(
                epoch_message(row.epoch, row.seq_start, row.seq_end, row.root, row.leaf_count)
            )
            row.tsa_url = getattr(anchor, "tsa_url", None)
            s.commit()

    def disclose(self, seq: int) -> dict:
        """A partial-disclosure bundle for ONE record: the record, its proof, and the anchored root.

        This is the payload an operator hands an auditor. It contains exactly one record body —
        already redacted by the AUD-04 gate when it was written — and sibling HASHES, which reveal
        nothing about the records they summarize.

        The epoch's ANCHOR travels with it. Shipping `anchored: true` without the proof made the
        claim unverifiable — the recipient could not tell an RFC-3161 timestamp from a string
        someone typed into the column — and the whole point is a root that carries authority we do
        not supply. The route is already token-gated, so exporting the proof reveals nothing new.

        Every bundle is verified BEFORE it is returned. Deleting one record from under a sealed
        epoch, or editing one body, both produce a success-shaped bundle that the recipient cannot
        verify — and to an auditor an unverifiable proof reads as tampering, not as our bug.
        """
        with self._sf() as s:
            rec = s.scalars(select(AuditRecord).where(AuditRecord.seq == seq)).first()
            if rec is None:
                raise MerkleError(f"no audit record at seq {seq}")
            # Ordered: overlapping rows are reachable by DB write, and which epoch answers must not
            # depend on the engine's row order.
            ep = s.scalars(
                select(MerkleRoot)
                .where(MerkleRoot.seq_start <= seq, MerkleRoot.seq_end >= seq)
                .order_by(MerkleRoot.epoch.asc())
            ).first()
            if ep is None:
                raise MerkleError(f"seq {seq} is not in a sealed epoch yet")
            # Columns, not entities — one read of one string per leaf, never the bodies.
            leaves = list(
                s.scalars(
                    select(AuditRecord.record_hash)
                    .where(AuditRecord.seq >= ep.seq_start, AuditRecord.seq <= ep.seq_end)
                    .order_by(AuditRecord.seq.asc())
                ).all()
            )
            if len(leaves) != ep.leaf_count:
                raise MerkleError(
                    f"epoch {ep.epoch} covers {len(leaves)} of its stated {ep.leaf_count} "
                    "records — records were deleted from under a sealed root"
                )
            index = seq - ep.seq_start
            bundle = {
                "record": {
                    "seq": rec.seq,
                    "record_hash": rec.record_hash,
                    "prev_hash": rec.prev_hash,
                    "body": rec.body,
                    "signature": rec.signature,
                    "signing_key_id": rec.signing_key_id,
                },
                "index": index,
                "proof": inclusion_proof(leaves, index),
                "epoch": {
                    "epoch": ep.epoch,
                    "seq_start": ep.seq_start,
                    "seq_end": ep.seq_end,
                    "root": ep.root,
                    "leaf_count": ep.leaf_count,
                    "anchor_kind": ep.anchor_kind,
                    "anchor_proof": ep.proof.hex() if ep.proof is not None else None,
                    "tsa_url": ep.tsa_url,
                    "anchored": ep.proof is not None,
                },
            }
        result = verify_bundle(bundle)
        if not result.ok:
            raise MerkleError(f"refusing to disclose seq {seq}: {result.reason}")
        return bundle

    def list_epochs(self) -> list[dict]:
        """Every sealed epoch and whether its root carries an external anchor yet (bounded)."""
        with self._sf() as s:
            return [
                {
                    "epoch": r.epoch,
                    "seq_start": r.seq_start,
                    "seq_end": r.seq_end,
                    "root": r.root,
                    "leaf_count": r.leaf_count,
                    "anchor_kind": r.anchor_kind,
                    "anchored": r.proof is not None,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in s.scalars(
                    select(MerkleRoot).order_by(MerkleRoot.epoch).limit(_MAX_EPOCHS)
                ).all()
            ]
