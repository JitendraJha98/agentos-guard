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
