"""AUD-06 — the pure Merkle core: hashing rules, root, proofs, and the attacks they stop."""
import asyncio
import hashlib
import json

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.checkpoint import (
    LocalEd25519Anchor,
    checkpoint_message,
    verify_checkpoint_proof,
)
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.merkle import (
    MerkleError,
    MerkleSealer,
    epoch_message,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_inclusion,
)
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, MerkleRoot

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


def _actions(audit: AuditWriter, n: int) -> None:
    for i in range(n):
        asyncio.run(
            audit.append_event(
                "framework_discovered",
                {"framework": f"f{i}", "distribution": "d", "version": "1"},
            )
        )


def test_sealing_covers_every_record_and_proves_each_one(store) -> None:
    audit = AuditWriter(store)
    _actions(audit, 6)
    sealer = MerkleSealer(store, audit)
    ep = asyncio.run(sealer.seal())
    assert (ep.seq_start, ep.seq_end, ep.leaf_count) == (0, 5, 6)
    for seq in range(6):
        b = sealer.disclose(seq)
        assert verify_inclusion(
            b["record"]["record_hash"],
            b["index"],
            b["proof"],
            b["epoch"]["root"],
            b["epoch"]["leaf_count"],
        )


def test_epochs_are_contiguous_across_seals_so_no_record_escapes_coverage(store) -> None:
    """A record in NO epoch can never be proven. Contiguity is the coverage guarantee, so assert
    the second epoch starts exactly where the first ended — including the seal event itself, which
    is appended by the first seal and must be covered by the second."""
    audit = AuditWriter(store)
    _actions(audit, 3)
    sealer = MerkleSealer(store, audit)
    first = asyncio.run(sealer.seal())
    _actions(audit, 2)
    second = asyncio.run(sealer.seal())
    assert second.seq_start == first.seq_end + 1
    assert second.epoch == first.epoch + 1
    # every seq from 0 to the second epoch's end is inside exactly one epoch
    for seq in range(0, second.seq_end + 1):
        assert sealer.disclose(seq)["epoch"]["epoch"] in (first.epoch, second.epoch)


def test_sealing_with_nothing_new_returns_none_rather_than_an_empty_epoch(store) -> None:
    """A root over an empty range would verify nothing while looking like coverage.

    The reachable "nothing new" state is an unstarted chain: every seal appends its OWN
    announcement, so a seal always leaves exactly one record for the next epoch — sealing converges
    on one-record epochs, never on None. That is the price of keeping the root inside the chain.
    """
    audit = AuditWriter(store)
    sealer = MerkleSealer(store, audit)
    assert asyncio.run(sealer.seal()) is None
    _actions(audit, 2)
    first = asyncio.run(sealer.seal())
    assert (first.seq_start, first.seq_end, first.leaf_count) == (0, 1, 2)
    second = asyncio.run(sealer.seal())
    assert (second.seq_start, second.seq_end, second.leaf_count) == (2, 2, 1)


def test_the_seal_event_lands_in_the_NEXT_epoch_not_its_own(store) -> None:
    """An epoch containing the record that announces it could never be sealed — the record does not
    exist until after the root is computed. Assert the announcement is outside its own range."""
    audit = AuditWriter(store)
    _actions(audit, 3)
    sealer = MerkleSealer(store, audit)
    ep = asyncio.run(sealer.seal())
    with store() as s:
        head = s.scalar(select(func.max(AuditRecord.seq)))
    assert head > ep.seq_end


def test_an_anchored_epoch_verifies_under_the_shipped_checkpoint_dispatch(store) -> None:
    """Reusing verify_checkpoint_proof is the point: one proven crypto path, not two."""
    audit = AuditWriter(store)
    _actions(audit, 4)
    sealer = MerkleSealer(store, audit)
    ep = asyncio.run(sealer.seal())
    engine = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)

    sealer.anchor_epoch(ep.epoch, LocalEd25519Anchor(engine))

    with store() as s:
        row = s.get(MerkleRoot, ep.epoch)
    msg = epoch_message(row.epoch, row.seq_start, row.seq_end, row.root, row.leaf_count)
    assert verify_checkpoint_proof(
        row.anchor_kind, row.proof, msg, public_key_pem=engine.public_key_pem
    )


def test_the_anchored_bytes_commit_to_the_epochs_size_and_cannot_pass_as_a_checkpoint(
    store,
) -> None:
    """The message reuses CHECKPOINT_DOMAIN, so its shape is the ONLY thing keeping an epoch proof
    from being replayed as a head proof — and leaf_count is in it so a re-sealed range that dropped
    records cannot reuse the same anchored bytes."""
    assert epoch_message(0, 0, 5, "ab" * 32, 6) != epoch_message(0, 0, 5, "ab" * 32, 5)
    assert epoch_message(0, 0, 5, "ab" * 32, 6) != checkpoint_message(5, "ab" * 32)


def test_disclosing_an_unsealed_or_missing_record_is_refused(store) -> None:
    audit = AuditWriter(store)
    _actions(audit, 2)
    sealer = MerkleSealer(store, audit)
    with pytest.raises(MerkleError):
        sealer.disclose(0)  # nothing sealed yet
    asyncio.run(sealer.seal())
    with pytest.raises(MerkleError):
        sealer.disclose(9999)  # no such record


def test_a_bundle_carries_exactly_one_record_body(store) -> None:
    """Partial disclosure is the requirement. If a bundle leaked sibling BODIES the feature would
    be pointless — the operator might as well send the whole log."""
    audit = AuditWriter(store)
    _actions(audit, 8)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())

    bundle = sealer.disclose(3)

    blob = json.dumps(bundle)
    assert blob.count('"body"') == 1
    for other in ("f0", "f1", "f2", "f4", "f5", "f6", "f7"):
        assert f'"{other}"' not in blob
    assert '"f3"' in blob


def test_anchoring_an_unsealed_epoch_is_refused(store) -> None:
    audit = AuditWriter(store)
    sealer = MerkleSealer(store, audit)
    with pytest.raises(MerkleError):
        sealer.anchor_epoch(0, LocalEd25519Anchor(None))
