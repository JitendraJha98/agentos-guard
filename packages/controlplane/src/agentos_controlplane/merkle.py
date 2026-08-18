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

from sqlalchemy import func, select

from agentos_controlplane.audit import canonical_json
from agentos_controlplane.store.models import AuditRecord, MerkleRoot

_LEAF = b"\x00"
_NODE = b"\x01"

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
    """Recompute the root from `record_hash` and its proof. PURE — no DB, no I/O, no imports beyond
    hashlib — so a third party can run it against a disclosed bundle and nothing else.

    `leaf_count` is what makes the POSITION provable, not just the membership (this is why RFC 6962
    verifies an audit path against the tree size too). The tree size is what says whether a level
    had a sibling at all, so the verifier derives every side itself and never trusts the bundle's:
    without it, a path is ambiguous about where it sits — in an 8-leaf tree index 1's path replays
    cleanly at index 2 — and a bundle could place a genuine record at a position it never occupied.
    `seq_start + index` is exactly how a reader locates the record, so that is not cosmetic.

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
        chain or any signature.
        """
        with self._sf() as s:
            last = s.scalars(select(MerkleRoot).order_by(MerkleRoot.epoch.desc()).limit(1)).first()
            start = 0 if last is None else last.seq_end + 1
            epoch = 0 if last is None else last.epoch + 1
            head = s.scalar(select(func.max(AuditRecord.seq)))
            if head is None or head < start:
                return None
            rows = s.scalars(
                select(AuditRecord)
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
        await self._audit.append_event("merkle_epoch_sealed", sealed)
        # Re-read so the caller gets the server-defaulted `created_at` too, never a half-populated
        # row that reads as "this epoch has no sealing time".
        with self._sf() as s:
            return s.get(MerkleRoot, sealed["epoch"])

    def anchor_epoch(self, epoch: int, anchor) -> None:
        """Bind a sealed root to an external proof (AUD-05's anchors, unchanged)."""
        with self._sf() as s:
            row = s.get(MerkleRoot, epoch)
            if row is None:
                raise MerkleError(f"epoch {epoch} is not sealed")
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
        """
        with self._sf() as s:
            rec = s.scalars(select(AuditRecord).where(AuditRecord.seq == seq)).first()
            if rec is None:
                raise MerkleError(f"no audit record at seq {seq}")
            ep = s.scalars(
                select(MerkleRoot).where(MerkleRoot.seq_start <= seq, MerkleRoot.seq_end >= seq)
            ).first()
            if ep is None:
                raise MerkleError(f"seq {seq} is not in a sealed epoch yet")
            leaves = [
                r.record_hash
                for r in s.scalars(
                    select(AuditRecord)
                    .where(AuditRecord.seq >= ep.seq_start, AuditRecord.seq <= ep.seq_end)
                    .order_by(AuditRecord.seq.asc())
                ).all()
            ]
            index = seq - ep.seq_start
            return {
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
                    "anchored": ep.proof is not None,
                },
            }

    def list_epochs(self) -> list[dict]:
        """Every sealed epoch and whether its root carries an external anchor yet."""
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
                for r in s.scalars(select(MerkleRoot).order_by(MerkleRoot.epoch)).all()
            ]
