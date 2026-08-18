"""AUD-06 — the pure Merkle core: hashing rules, root, proofs, and the attacks they stop."""
import asyncio
import hashlib

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.merkle import (
    MerkleError,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import MerkleRoot

H = lambda b: hashlib.sha256(b).hexdigest()  # noqa: E731


def test_leaf_and_node_hashing_are_domain_separated() -> None:
    """The 0x00/0x01 prefixes are the second-preimage defense, so assert the EXACT preimages.

    If leaf and internal hashing shared a domain, an attacker holding an internal node's hash could
    present it as a leaf — turning a proof about a subtree into a proof that a record was written.
    """
    assert leaf_hash("ab") == H(b"\x00" + bytes.fromhex("ab"))
    assert node_hash("ab", "cd") == H(b"\x01" + bytes.fromhex("ab") + bytes.fromhex("cd"))
    assert leaf_hash("ab") != node_hash("ab", "ab")


def test_single_leaf_root_is_the_leaf_hash() -> None:
    assert merkle_root(["aa"]) == leaf_hash("aa")


def test_root_matches_a_hand_computed_four_leaf_tree() -> None:
    leaves = ["00", "11", "22", "33"]
    expected = node_hash(
        node_hash(leaf_hash("00"), leaf_hash("11")),
        node_hash(leaf_hash("22"), leaf_hash("33")),
    )
    assert merkle_root(leaves) == expected


def test_odd_leaf_is_promoted_not_duplicated() -> None:
    """REGRESSION GUARD (CVE-2012-2459 class): padding by duplicating the last leaf makes two
    distinct leaf lists collide on one root, so the root stops uniquely determining its contents."""
    three = merkle_root(["00", "11", "22"])
    padded = merkle_root(["00", "11", "22", "22"])
    assert three != padded
    assert three == node_hash(node_hash(leaf_hash("00"), leaf_hash("11")), leaf_hash("22"))


def test_an_empty_tree_is_refused() -> None:
    """A root over nothing is a footgun: it would verify no record yet look like coverage."""
    with pytest.raises(MerkleError):
        merkle_root([])


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 7, 8, 9, 17, 33])
def test_every_leaf_in_every_shape_proves_its_own_inclusion(n: int) -> None:
    """Proofs must hold at EVERY index for EVERY tree shape — off-by-one and odd-level promotion
    bugs hide in exactly the sizes a happy-path test skips."""
    leaves = [f"{i:064x}" for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        assert verify_inclusion(leaves[i], i, inclusion_proof(leaves, i), root, n)


def test_a_proof_does_not_verify_a_record_that_was_never_written() -> None:
    """The property the whole feature exists for. If a forged leaf verified, disclosure would be
    worthless: anyone could claim any action was audited."""
    leaves = [f"{i:064x}" for i in range(8)]
    root, proof = merkle_root(leaves), inclusion_proof(leaves, 3)
    forged = "de" * 32
    assert not verify_inclusion(forged, 3, proof, root, 8)


def test_sibling_order_is_load_bearing() -> None:
    """Flipping a sibling's side must break the proof — otherwise the tree is order-insensitive and
    a different log produces the same root."""
    leaves = [f"{i:064x}" for i in range(8)]
    root, proof = merkle_root(leaves), inclusion_proof(leaves, 3)
    flipped = [("right" if side == "left" else "left", h) for side, h in proof]
    assert not verify_inclusion(leaves[3], 3, flipped, root, 8)


def test_a_tampered_root_or_index_fails() -> None:
    leaves = [f"{i:064x}" for i in range(8)]
    root, proof = merkle_root(leaves), inclusion_proof(leaves, 3)
    assert not verify_inclusion(leaves[3], 3, proof, "ff" * 32, 8)
    assert not verify_inclusion(leaves[3], 4, proof, root, 8)


@pytest.mark.parametrize("n", [3, 5, 7, 8, 9])
def test_a_proof_from_one_index_never_verifies_at_another(n: int) -> None:
    """REGRESSION GUARD: the claimed index must be BOUND to the path, which is why `leaf_count` is
    a parameter. A verifier that merely replayed the path would accept any index consistent with
    the same number of steps — in an 8-leaf tree index 1's path replays cleanly at index 2 — so a
    bundle could place a genuine record at a position it never occupied, and `seq_start + index` is
    how a reader locates it. Non-power-of-two sizes are included because promotion is where the
    shape stops being derivable from the index alone."""
    leaves = [f"{i:064x}" for i in range(n)]
    root = merkle_root(leaves)
    for i in range(n):
        proof = inclusion_proof(leaves, i)
        for j in range(n):
            if j != i:
                assert not verify_inclusion(leaves[i], j, proof, root, n)


def test_a_path_longer_than_the_tree_is_refused() -> None:
    """Trailing entries mean a fabricated shape; ignoring them would let a forger append noise that
    a lenient verifier silently drops."""
    leaves = [f"{i:064x}" for i in range(4)]
    root = merkle_root(leaves)
    padded = inclusion_proof(leaves, 1) + [("right", "aa" * 32)]
    assert not verify_inclusion(leaves[1], 1, padded, root, 4)


def test_verify_inclusion_never_raises_on_hostile_input() -> None:
    """A verifier runs on bundles from outside; malformed input must be FALSE, not a traceback that
    a caller might mistake for 'the check did not run'."""
    leaves = ["00", "11"]
    root = merkle_root(leaves)
    assert not verify_inclusion("zz", 0, inclusion_proof(leaves, 0), root, 2)   # not hex
    assert not verify_inclusion("00", 0, [("sideways", "aa")], root, 2)         # bad side
    assert not verify_inclusion("00", -1, [], root, 2)                          # bad index
    assert not verify_inclusion("00", 5, [], root, 2)                           # index >= size
    assert not verify_inclusion("00", 1, [("left", "nothex")], root, 2)
    assert not verify_inclusion("00", 0, [None], root, 2)                       # not a pair


def test_inclusion_proof_rejects_an_out_of_range_index() -> None:
    with pytest.raises(MerkleError):
        inclusion_proof(["00", "11"], 5)


@pytest.fixture()
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def test_merkle_root_row_round_trips(store) -> None:
    with store() as s:
        s.add(MerkleRoot(epoch=0, seq_start=0, seq_end=9, root="ab" * 32, leaf_count=10))
        s.commit()
    with store() as s:
        row = s.scalars(select(MerkleRoot)).one()
    assert (row.epoch, row.seq_start, row.seq_end, row.leaf_count) == (0, 0, 9, 10)
    assert row.anchor_kind is None and row.proof is None


def test_the_seal_event_kind_is_accepted_and_unknown_kinds_are_not(store) -> None:
    """The kind is allowlisted, so a typo'd or invented seal event can never enter the chain."""
    audit = AuditWriter(store)
    asyncio.run(audit.append_event("merkle_epoch_sealed", {"epoch": 0, "root": "ab" * 32}))
    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("merkle_epoch_definitely_not_a_kind", {}))
