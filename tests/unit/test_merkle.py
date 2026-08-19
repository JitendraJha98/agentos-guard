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
from agentos_controlplane import merkle as merkle_mod
from agentos_controlplane.merkle import (
    MerkleError,
    MerkleSealer,
    epoch_message,
    inclusion_proof,
    inclusion_proofs,
    leaf_hash,
    merkle_root,
    node_hash,
    verify_bundle,
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


def test_an_index_past_the_last_leaf_is_refused_by_the_bound_not_by_luck() -> None:
    """REGRESSION GUARD for the `index < leaf_count` bound itself. Index n in an n-leaf tree
    consumes exactly the same sibling path as index n-2 and climbs to the same root, so without the
    bound a genuine record verifies at a position OUTSIDE the tree — and `seq_start + index` is how
    a reader turns that position into a seq. The other hostile-input cases pass an empty proof, so
    they die on iterator exhaustion and leave the bound untested."""
    leaves = [f"{i:064x}" for i in range(2)]
    root = merkle_root(leaves)

    assert not verify_inclusion(leaves[0], 2, inclusion_proof(leaves, 0), root, 2)


def test_inclusion_proof_rejects_an_out_of_range_index() -> None:
    with pytest.raises(MerkleError):
        inclusion_proof(["00", "11"], 5)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 9, 17])
def test_batching_proofs_changes_the_cost_and_not_the_path(n: int) -> None:
    """CMP-06 asks for a proof per disclosed record, so the batch form exists to build the tree once
    instead of once per index. It must be the SAME path: a batch proof that differed from the single
    one would verify against the same root right up until it did not, and only in bulk exports."""
    leaves = [f"{i:02x}" * 32 for i in range(n)]
    root = merkle_root(leaves)

    batched = inclusion_proofs(leaves, range(n))

    assert batched == {i: inclusion_proof(leaves, i) for i in range(n)}
    for i in range(n):
        assert verify_inclusion(leaves[i], i, batched[i], root, n)


def test_batching_rejects_an_out_of_range_index_rather_than_skipping_it() -> None:
    """A silently missing proof would become a record exported with `inclusion: null` — reported as
    "not sealed yet" when the truth is that we asked the tree for the wrong leaf."""
    with pytest.raises(MerkleError):
        inclusion_proofs(["00", "11"], [0, 5])


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


def test_re_anchoring_an_epoch_is_refused_unless_it_is_deliberate(store) -> None:
    """Re-anchoring silently would let an RFC-3161 epoch be replaced by the durability-only local
    anchor — external authority traded for a self-signature, with `anchored` still reporting true.
    A downgrade nobody can see is worse than a refusal somebody has to read."""
    audit = AuditWriter(store)
    _actions(audit, 3)
    sealer = MerkleSealer(store, audit)
    ep = asyncio.run(sealer.seal())
    engine = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    sealer.anchor_epoch(ep.epoch, LocalEd25519Anchor(engine))

    with pytest.raises(MerkleError):
        sealer.anchor_epoch(ep.epoch, LocalEd25519Anchor(engine))

    sealer.anchor_epoch(ep.epoch, LocalEd25519Anchor(engine), replace=True)  # deliberate: allowed


def test_sealing_refuses_a_range_that_skips_a_record(store) -> None:
    """REGRESSION GUARD for the contiguity check. A record inside no epoch can never be disclosed,
    so a root over a range with a hole is a claim of coverage that is not coverage — refusing is
    the only honest answer, and the check is otherwise defended by a comment alone."""
    audit = AuditWriter(store)
    _actions(audit, 4)
    with store() as s:
        s.delete(s.scalars(select(AuditRecord).where(AuditRecord.seq == 2)).one())
        s.commit()

    with pytest.raises(MerkleError):
        asyncio.run(MerkleSealer(store, audit).seal())


def _drive(coro):
    """Run a coroutine to completion from INSIDE a running asyncio.run(), which forbids nesting.

    Only sound because the audit writer's single await is an uncontended asyncio.Lock, which never
    actually suspends — asserted below rather than assumed.
    """
    try:
        coro.send(None)
    except StopIteration as stop:
        return stop.value
    raise AssertionError("the append suspended — this test's assumption no longer holds")


def test_a_record_appended_mid_seal_is_excluded_by_the_pinned_head(store) -> None:
    """REGRESSION GUARD for the pinned upper bound — the slice's ONLY concurrency protection, and
    otherwise defended by a comment alone. If the leaf query were not bounded by the head read
    before it, a record landing mid-build would be hashed into a root whose row claims a different
    range: a root that does not match its own stated range fails verification and reads as
    tampering."""
    audit = AuditWriter(store)
    _actions(audit, 4)
    raced = []

    def racing_factory():
        s = store()
        real_scalar = s.scalar

        def scalar(stmt, *a, **kw):
            out = real_scalar(stmt, *a, **kw)
            if not raced:  # the head read, before the leaves are collected
                raced.append(True)
                _drive(
                    audit.append_event(
                        "framework_discovered",
                        {"framework": "late", "distribution": "d", "version": "1"},
                    )
                )
            return out

        s.scalar = scalar
        return s

    ep = asyncio.run(MerkleSealer(racing_factory, audit).seal())

    assert raced, "the racing append never fired — the test proves nothing"
    assert (ep.seq_start, ep.seq_end, ep.leaf_count) == (0, 3, 4)


def test_one_seal_reads_a_bounded_range_and_the_next_picks_up_the_rest(store, monkeypatch) -> None:
    """A first seal on a production chain would otherwise pull the whole audit table into memory.
    Capping delays coverage to the next call; it never loses it."""
    audit = AuditWriter(store)
    _actions(audit, 5)
    sealer = MerkleSealer(store, audit)
    monkeypatch.setattr(merkle_mod, "_MAX_EPOCH_LEAVES", 2)

    first = asyncio.run(sealer.seal())
    second = asyncio.run(sealer.seal())

    assert (first.seq_start, first.seq_end, first.leaf_count) == (0, 1, 2)
    assert (second.seq_start, second.seq_end, second.leaf_count) == (2, 3, 2)


def test_a_failed_announcement_leaves_no_committed_epoch_behind(store) -> None:
    """The announcement is what puts the root inside the tamper-evident chain. An epoch committed
    without one is permanently outside that protection and indistinguishable from a row a forger
    inserted by hand — so undo the epoch rather than keep a root nobody vouched for."""

    class Failing:
        async def append_event(self, *args, **kwargs):
            raise RuntimeError("the AUD-04 secret gate refused the announcement")

    audit = AuditWriter(store)
    _actions(audit, 3)

    with pytest.raises(RuntimeError):
        asyncio.run(MerkleSealer(store, Failing()).seal())

    with store() as s:
        assert s.scalars(select(MerkleRoot)).all() == []


def test_disclosure_names_the_epoch_that_actually_covers_the_seq(store) -> None:
    """Which root a record is proven against decides what the proof means, so it must not depend on
    the engine's row order across the two epochs that exist by the second seal."""
    audit = AuditWriter(store)
    _actions(audit, 3)
    sealer = MerkleSealer(store, audit)
    first = asyncio.run(sealer.seal())
    second = asyncio.run(sealer.seal())  # covers the first seal's own announcement

    for seq in range(first.seq_start, first.seq_end + 1):
        assert sealer.disclose(seq)["epoch"]["epoch"] == first.epoch
    assert sealer.disclose(second.seq_start)["epoch"]["epoch"] == second.epoch


def test_disclose_refuses_when_records_were_deleted_from_under_the_epoch(store) -> None:
    """Building a proof over the survivors while the row still claims the original size produces a
    success-shaped bundle the recipient cannot verify — and an unverifiable proof reads to an
    auditor as tampering, not as our bug. Fail here, where the operator can see it."""
    audit = AuditWriter(store)
    _actions(audit, 8)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    with store() as s:
        s.delete(s.scalars(select(AuditRecord).where(AuditRecord.seq == 6)).one())
        s.commit()

    # the message names the real cause; "the proof did not verify" would send the operator hunting
    # for a tree bug instead of for the deletion
    with pytest.raises(MerkleError, match="deleted from under a sealed root"):
        sealer.disclose(2)


def test_disclose_refuses_a_body_that_no_longer_hashes_to_its_own_record_hash(store) -> None:
    """The tree is built over the stored `record_hash` column, so a body edited underneath it still
    yields a proof that verifies — beside a fabricated body. Handing an auditor "inclusion
    verified" next to content the root never committed to is the worst failure this feature has."""
    audit = AuditWriter(store)
    _actions(audit, 6)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    with store() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 2)).one()
        row.body = dict(row.body, framework="fabricated")  # record_hash column untouched
        s.commit()

    with pytest.raises(MerkleError):
        sealer.disclose(2)


def test_verify_bundle_refuses_a_swapped_body_that_the_raw_proof_still_accepts(store) -> None:
    """THE bundle-level attack. `verify_inclusion` binds a record_hash, not a body: swap the body,
    keep the hash, and the shipped tree check still says True. An auditor handed a bundle reading
    `allow` where the record said `deny` would run the verifier, see True, and certify it."""
    audit = AuditWriter(store)
    _actions(audit, 6)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    bundle = sealer.disclose(2)
    bundle["record"]["body"] = dict(bundle["record"]["body"], framework="fabricated")

    # the raw tree check is happy — which is exactly why an auditor must not be handed it alone
    assert verify_inclusion(
        bundle["record"]["record_hash"],
        bundle["index"],
        bundle["proof"],
        bundle["epoch"]["root"],
        bundle["epoch"]["leaf_count"],
    )
    assert not verify_bundle(bundle).ok


def test_verify_bundle_refuses_a_record_replayed_at_a_position_it_never_occupied(store) -> None:
    """`leaf_count` decides the tree's shape, so a bundle that supplies it binds nothing: a genuine
    record at index 4 of 5 replays untouched as index 1 of 2 under the same root. Pinning
    leaf_count to the epoch's range and the index to the body's seq is what makes `seq_start +
    index` mean something, because moving the record now means moving a seq inside the hashed body.
    """
    audit = AuditWriter(store)
    _actions(audit, 5)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    bundle = sealer.disclose(4)

    forgeries = 0
    for leaf_count in range(1, 30):
        for index in range(leaf_count):
            forged = json.loads(json.dumps(bundle))
            forged["index"] = index
            forged["epoch"]["leaf_count"] = leaf_count
            if verify_inclusion(
                forged["record"]["record_hash"],
                index,
                forged["proof"],
                forged["epoch"]["root"],
                leaf_count,
            ) and (index, leaf_count) != (bundle["index"], bundle["epoch"]["leaf_count"]):
                forgeries += 1
                assert not verify_bundle(forged).ok
    assert forgeries, "no replay was constructible — the guard is untested"


def test_verify_bundle_reports_an_unanchored_root_as_our_word_alone(store) -> None:
    """`anchored: false` must not read the same as `verified`. A root nobody outside vouched for is
    a number in a file the discloser wrote, so the two facts stay separate fields."""
    audit = AuditWriter(store)
    _actions(audit, 5)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())

    result = verify_bundle(sealer.disclose(2))

    assert result.ok and not result.anchor_verified and "no anchor" in result.reason


def test_verify_bundle_checks_the_anchor_the_bundle_now_carries(store) -> None:
    """The slice's goal is a root carrying authority the operator does not supply. Shipping
    `anchored: true` without the proof made that unverifiable — an auditor could not tell an
    RFC-3161 timestamp from a string typed into the column."""
    audit = AuditWriter(store)
    _actions(audit, 5)
    sealer = MerkleSealer(store, audit)
    ep = asyncio.run(sealer.seal())
    engine = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    sealer.anchor_epoch(ep.epoch, LocalEd25519Anchor(engine))
    bundle = sealer.disclose(2)

    assert bundle["epoch"]["anchor_proof"] is not None
    good = verify_bundle(bundle, public_key_pem=engine.public_key_pem)
    assert good.ok and good.anchor_verified

    # material not supplied -> a counted skip, never a silent pass
    assert not verify_bundle(bundle).anchor_verified
    # a root re-anchored over different bytes cannot pass as the original
    bundle["epoch"]["root"] = "ff" * 32
    assert not verify_bundle(bundle, public_key_pem=engine.public_key_pem).ok


def test_verify_bundle_never_raises_on_hostile_input(store) -> None:
    """An auditor runs this on a file someone mailed them; a traceback is easy to mistake for 'the
    check did not run' when it means 'the check failed'."""
    audit = AuditWriter(store)
    _actions(audit, 4)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    good = sealer.disclose(1)

    for hostile in (
        {},
        {"record": None, "epoch": {}, "index": 0, "proof": []},
        {**good, "epoch": {**good["epoch"], "leaf_count": "four"}},
        {**good, "index": None},
        {**good, "record": {**good["record"], "record_hash": "not-hex"}},
        {**good, "epoch": {**good["epoch"], "anchor_kind": "invented", "anchor_proof": "zz"}},
    ):
        assert not verify_bundle(hostile).ok


# ------------------------------------------- re-review: each verify_bundle guard, killed on its own


@pytest.fixture()
def anchored(store):
    """An ANCHORED bundle plus the key that anchored it — the strongest posture, so a guard that
    fails here has nowhere left to hide."""
    audit = AuditWriter(store)
    _actions(audit, 8)
    sealer = MerkleSealer(store, audit)
    ep = asyncio.run(sealer.seal())
    engine = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    sealer.anchor_epoch(ep.epoch, LocalEd25519Anchor(engine))
    return sealer.disclose(3), engine.public_key_pem


def test_a_corrupted_proof_path_alone_fails(anchored) -> None:
    """REGRESSION: dropping the inclusion check entirely SURVIVED the suite.

    The only test covering it tampered `root`, which breaks the inclusion check AND the anchor check
    — so each guard was covered by the other and neither was tested alone. With the inclusion check
    gone, an unanchored bundle returned ok=True for any record against any proof, which is the whole
    function's reason to exist. Tamper ONLY the proof: the root still anchors, so nothing but the
    inclusion check can catch this.
    """
    bundle, pub = anchored
    bundle["proof"] = [(side, "aa" * 32) for side, _ in bundle["proof"]]

    result = verify_bundle(bundle, public_key_pem=pub)

    assert not result.ok and "inclusion proof" in result.reason


def test_a_corrupted_anchor_alone_fails(anchored) -> None:
    """REGRESSION: accepting a failing anchor proof SURVIVED the suite, for the same mutual-cover
    reason. Tamper ONLY the anchor bytes: the tree still verifies, so nothing but the anchor check
    can catch it — and an unverified anchor reported as verified is the discloser certifying their
    own root."""
    bundle, pub = anchored
    raw = bytearray(bytes.fromhex(bundle["epoch"]["anchor_proof"]))
    raw[0] ^= 0xFF
    bundle["epoch"]["anchor_proof"] = bytes(raw).hex()

    result = verify_bundle(bundle, public_key_pem=pub)

    assert not result.ok and not result.anchor_verified


def test_a_consistently_lied_about_record_seq_is_named_as_a_seq_disagreement(anchored) -> None:
    """REGRESSION: dropping `body["seq"] == rec["seq"]` SURVIVED the suite.

    The lie has to be CONSISTENT to reach this guard — move `record["seq"]` and `index` together, or
    the index binding catches it first and the mutant hides behind that. Note what is asserted: the
    REASON, not just the verdict. With the guard dropped the bundle is still refused (the tree walk
    fails on the moved index), so a verdict-only assertion cannot tell the two apart. The reason is
    also the part that matters operationally — it is what tells an auditor which invariant broke, and
    "the inclusion proof does not verify" would send them looking at the tree instead of the seq.
    """
    bundle, pub = anchored
    bundle["record"]["seq"] += 1
    bundle["index"] += 1

    result = verify_bundle(bundle, public_key_pem=pub)

    assert not result.ok
    assert "seq" in result.reason and "body" in result.reason


def test_a_lied_about_index_alone_fails(anchored) -> None:
    """REGRESSION: dropping `index == seq - seq_start` SURVIVED. `seq_start + index` is exactly how
    a reader locates the record in the epoch, so an unbound index moves it."""
    bundle, pub = anchored
    bundle["index"] = bundle["index"] + 1

    result = verify_bundle(bundle, public_key_pem=pub)

    assert not result.ok and "index" in result.reason


def test_a_lied_about_leaf_count_alone_fails(anchored) -> None:
    """REGRESSION: dropping `leaf_count == seq_end - seq_start + 1` SURVIVED. verify_inclusion
    derives the tree's SHAPE from leaf_count, so a bundle free to choose it binds nothing — a real
    record at index 4 of 5 replays as index 1 of 2."""
    bundle, pub = anchored
    bundle["epoch"]["leaf_count"] = bundle["epoch"]["leaf_count"] + 1

    result = verify_bundle(bundle, public_key_pem=pub)

    assert not result.ok and "leaf_count" in result.reason


def test_a_negative_seq_start_is_refused(anchored) -> None:
    """A range starting before the chain does is not a range. Cheap to reject, and it was reachable:
    the arithmetic identity alone accepts seq_start=-4 with a matching seq_end."""
    bundle, pub = anchored
    ep = bundle["epoch"]
    ep["seq_start"], ep["seq_end"] = -4, -4 + ep["leaf_count"] - 1

    assert not verify_bundle(bundle, public_key_pem=pub).ok


def test_disclosure_picks_the_epoch_whose_range_STARTS_at_or_below_the_seq(store) -> None:
    """REGRESSION: dropping `seq_start <= seq` from the epoch lookup SURVIVED.

    With two epochs, the later one's `seq_end` also covers an early seq, so a lookup filtered only
    by `seq_end >= seq` can return the WRONG epoch — and then every index and proof is computed
    against a tree that does not contain the record. Two epochs are what make the bound observable;
    one epoch cannot distinguish the two predicates.
    """
    audit = AuditWriter(store)
    _actions(audit, 4)
    sealer = MerkleSealer(store, audit)
    first = asyncio.run(sealer.seal())
    _actions(audit, 4)
    second = asyncio.run(sealer.seal())
    assert second.seq_start > first.seq_start, "the probe needs two distinct epochs"

    bundle = sealer.disclose(1)

    assert bundle["epoch"]["epoch"] == first.epoch
    assert verify_bundle(bundle).ok


def test_a_seq_below_every_sealed_range_is_refused_not_given_a_negative_index(store) -> None:
    """REGRESSION: dropping `seq_start <= seq` from the epoch lookup SURVIVED the suite.

    It survives an ordinary two-epoch probe because epochs are contiguous from 0, so the first epoch
    with `seq_end >= seq` is the covering one anyway. The bound only becomes observable when NO epoch
    starts at or below the seq — a range sealed from 4 while 0..3 are still unsealed. Without it the
    lookup returns that later epoch and computes `index = seq - seq_start`, i.e. -2.

    Note what is asserted: the MESSAGE. Both paths refuse — without the bound, `inclusion_proof`
    rejects the negative index a moment later — so a `pytest.raises(MerkleError)` alone cannot tell
    them apart. Only one of them tells the operator the truth. "seq 2 is not in a sealed epoch yet"
    is actionable (seal it); "index -2 out of range for 4 leaves" describes an internal symptom of a
    lookup that should never have matched, and sends whoever reads it into the tree code.
    """
    audit = AuditWriter(store)
    _actions(audit, 8)
    with store() as s:  # an epoch covering 4..7 only; 0..3 are sealed by nothing
        hashes = list(
            s.scalars(
                select(AuditRecord.record_hash)
                .where(AuditRecord.seq >= 4, AuditRecord.seq <= 7)
                .order_by(AuditRecord.seq.asc())
            ).all()
        )
        s.add(
            MerkleRoot(epoch=0, seq_start=4, seq_end=7, root=merkle_root(hashes), leaf_count=4)
        )
        s.commit()
    sealer = MerkleSealer(store, audit)

    assert sealer.disclose(5)["epoch"]["epoch"] == 0  # the probe is live: 5 IS covered
    with pytest.raises(MerkleError, match="not in a sealed epoch"):
        sealer.disclose(2)


def test_the_epoch_list_keeps_the_NEWEST_and_says_it_truncated(store) -> None:
    """REGRESSION: the cap dropped the newest epochs and reported nothing.

    Ascending order plus a LIMIT sheds exactly the rows an operator is asking about — "is sealing
    still running, and is the latest epoch anchored?" — and a silently capped list reads as the whole
    picture. Same no-silent-caps rule the DISC-04/05/06 stores follow with their visible overflow
    markers.
    """
    with store() as s:
        s.add_all(
            MerkleRoot(epoch=i, seq_start=i, seq_end=i, root="ab" * 32, leaf_count=1)
            for i in range(merkle_mod._MAX_EPOCHS + 5)
        )
        s.commit()

    page = MerkleSealer(store, AuditWriter(store)).list_epochs()

    assert page["truncated"] is True
    assert page["total"] == merkle_mod._MAX_EPOCHS + 5
    assert len(page["epochs"]) == merkle_mod._MAX_EPOCHS
    assert page["epochs"][0]["epoch"] == merkle_mod._MAX_EPOCHS + 4, "newest must survive the cap"
