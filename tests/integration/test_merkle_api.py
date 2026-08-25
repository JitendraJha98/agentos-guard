"""AUD-06 — the gated disclosure API and the verifier's Merkle pass, end to end.

The claim under test is the one the whole slice exists for: an operator hands out ONE record plus a
proof path, and the recipient verifies it against the epoch root holding nothing else — no
database, no other record, no trust in us. The routes ride the SAME shared-token gate as the
DISC-01..06 inventory surface (which actions an agent took is not public), and an app built without
a sealer answers 404 rather than opening an ungated one, so every existing create_app caller is
unchanged.

The verifier half is the other direction: a sealed root that no longer re-derives from the records
still in the table is a build failure, which is what makes the disclosure worth anything.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter, canonical_json
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.checkpoint import LocalEd25519Anchor
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.merkle import MerkleSealer, merkle_root, verify_bundle, verify_inclusion
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, MerkleRoot

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
RECORDS = 5  # seq 0..4 are sealed into epoch 0; the seal's own announcement lands at seq 5


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def audit(store) -> AuditWriter:
    """ONE writer over the store — a second instance caches a stale chain head."""
    return AuditWriter(store)


@pytest.fixture
def sealer(store, audit) -> MerkleSealer:
    for i in range(RECORDS):
        asyncio.run(
            audit.append_event(
                "framework_discovered",
                {"framework": f"f{i}", "distribution": "d", "version": "1"},
            )
        )
    s = MerkleSealer(store, audit)
    asyncio.run(s.seal())
    return s


def _app(store, audit, sealer):
    inv = InventoryStore(store)
    inv.declare("a", tools=["http_get"])
    return create_app(
        ApprovalStore(store, audit),
        inventory_store=inv,
        api_token=TOKEN,
        sealer=sealer,
    )


@pytest.fixture
def client(store, audit, sealer) -> TestClient:
    c = TestClient(_app(store, audit, sealer))
    c.headers.update(AUTH)
    return c


@pytest.fixture
def client_no_token(store, audit, sealer) -> TestClient:
    return TestClient(_app(store, audit, sealer))  # no default auth header


@pytest.fixture
def client_no_sealer(store, audit) -> TestClient:
    c = TestClient(_app(store, audit, None))
    c.headers.update(AUTH)
    return c


def test_a_disclosed_bundle_verifies_against_the_root_with_no_database(client) -> None:
    """The end-to-end claim of AUD-06: a third party holding ONLY the bundle can verify it.

    Through `verify_bundle`, not `verify_inclusion`. The tree check alone binds a record_hash, so a
    test that feeds it `bundle["record"]["record_hash"]` asserts only that the bundle agrees with
    itself — something a forger satisfies for free. What an auditor needs proved is that the BODY
    they were handed is the record the root commits to, at the seq the bundle claims.
    """
    bundle = client.get("/audit/disclose/2").json()

    assert verify_bundle(bundle).ok


def test_a_swapped_body_is_refused_even_though_the_proof_still_verifies(client) -> None:
    """An auditor shown `outcome: "allow"` where the record said `deny`, beside a proof that says
    True, would certify the forgery. The proof never covered the body."""
    bundle = client.get("/audit/disclose/2").json()
    bundle["record"]["body"] = dict(bundle["record"]["body"], framework="fabricated")

    assert verify_inclusion(  # the raw tree check is still satisfied ...
        bundle["record"]["record_hash"],
        bundle["index"],
        bundle["proof"],
        bundle["epoch"]["root"],
        bundle["epoch"]["leaf_count"],
    )
    assert not verify_bundle(bundle).ok  # ... and the bundle check is not


def test_a_bundle_discloses_one_record_and_summarizes_the_rest_as_hashes(client) -> None:
    """Partial disclosure is the requirement — a bundle that leaked its siblings' bodies would be
    no better than mailing the whole log."""
    blob = client.get("/audit/disclose/2").text

    assert '"f2"' in blob
    for other in ("f0", "f1", "f3", "f4"):
        assert f'"{other}"' not in blob


def test_the_epoch_list_reports_what_was_sealed(client) -> None:
    page = client.get("/audit/epochs").json()
    rows = page["epochs"]

    assert [(r["seq_start"], r["seq_end"], r["leaf_count"]) for r in rows] == [(0, 4, RECORDS)]
    assert rows[0]["anchored"] is False and rows[0]["anchor_kind"] is None
    assert page["total"] == 1 and page["truncated"] is False


def test_disclosing_a_record_no_epoch_covers_yet_is_a_404(client) -> None:
    """The seal's OWN announcement is not covered until the next seal. 404 is the honest answer;
    inventing a proof against an unsealed range would not be."""
    assert client.get(f"/audit/disclose/{RECORDS}").status_code == 404
    assert client.get("/audit/disclose/9999").status_code == 404


def test_the_routes_are_gated(client_no_token) -> None:
    assert client_no_token.get("/audit/epochs").status_code == 401
    assert client_no_token.get("/audit/disclose/0").status_code == 401


def test_an_app_built_without_a_sealer_404s_and_keeps_the_other_routes(client_no_sealer) -> None:
    assert client_no_sealer.get("/audit/epochs").status_code == 404
    assert client_no_sealer.get("/audit/disclose/0").status_code == 404
    assert client_no_sealer.get("/inventory").status_code == 200


def test_a_clean_store_reports_the_epoch_as_checked(store, sealer) -> None:
    """Non-vacuity: prove the pass actually RAN rather than skipping every epoch."""
    result = verify_chain(store)

    assert result.ok and result.epochs_checked >= 1


def test_a_record_edited_after_sealing_fails_verification(store, sealer) -> None:
    """The tampering the epoch exists to catch, at epoch granularity."""
    with store() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 1)).one()
        row.body = dict(row.body, framework="tampered")
        s.commit()

    result = verify_chain(store)

    assert not result.ok


def test_a_full_consistent_rewrite_the_chain_alone_accepts_is_caught_by_the_epoch(
    store, sealer
) -> None:
    """The detection the Merkle pass ADDS, and the reason it re-derives its leaves.

    A forger with DB write access who edits a body AND recomputes every hash and prev_hash after it
    leaves a chain that is internally consistent — on unsigned rows the chain has nothing left to
    catch them with. The root was sealed BEFORE the rewrite, so it no longer re-derives.
    """
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.asc())).all()
        prev = None
        for row in rows:
            body = dict(row.body)
            if row.seq == 1:
                body["framework"] = "tampered"
            if prev is not None:
                body["prev_hash"] = prev
                row.prev_hash = prev
            row.body = body
            prev = hashlib.sha256(canonical_json(body)).hexdigest()
            row.record_hash = prev
        s.commit()

    result = verify_chain(store)

    # merkle_root_mismatch, NOT record_hash / prev_hash_linkage: naming the check is what proves
    # the chain pass was fully satisfied and the epoch is what caught the rewrite.
    assert not result.ok
    assert result.violation.check == "merkle_root_mismatch"


def test_a_record_deleted_from_under_a_sealed_epoch_is_caught(store, sealer) -> None:
    """Truncation, the checkpoint pass's own failure mode at epoch granularity: the surviving chain
    is contiguous and self-consistent, so only the epoch's stated range reveals the missing rows."""
    with store() as s:
        for seq in (RECORDS, RECORDS - 1):  # the announcement, then the epoch's last record
            s.delete(s.scalars(select(AuditRecord).where(AuditRecord.seq == seq)).one())
        s.commit()

    result = verify_chain(store)

    assert not result.ok
    assert result.violation.check == "merkle_range_incomplete"


def test_an_epoch_that_skips_a_seq_is_caught(store, sealer) -> None:
    """A record inside NO epoch can never be disclosed. A forged second epoch that starts past the
    first one's end would quietly strand everything between them.

    Named `merkle_range_gap`, not `merkle_epoch_overlap`: a gap is remediated by re-sealing the
    stranded range, an overlap by deleting a bogus row, and the check name is what a CI consumer
    keys its response on.
    """
    with store() as s:
        s.add(MerkleRoot(epoch=1, seq_start=99, seq_end=100, root="ab" * 32, leaf_count=2))
        s.commit()

    result = verify_chain(store)

    assert not result.ok
    assert result.violation.check == "merkle_range_gap"


def test_an_epoch_that_reclaims_a_covered_seq_is_still_an_overlap(store, sealer) -> None:
    """The opposite fault keeps the opposite name: one seq under two roots that can disagree."""
    with store() as s:
        s.add(MerkleRoot(epoch=1, seq_start=2, seq_end=4, root="ab" * 32, leaf_count=3))
        s.commit()

    result = verify_chain(store)

    assert not result.ok
    assert result.violation.check == "merkle_epoch_overlap"


def test_a_truncated_log_re_sealed_to_match_is_caught_by_the_signed_announcement(
    store, audit, sealer
) -> None:
    """The forgery the epoch row alone cannot refuse, on the STRONGEST posture (signed chain).

    `seq_start`, `seq_end`, `leaf_count` and `root` are writable together, so re-deriving a row
    against the range that same row declares proves only that the row is self-consistent: destroy
    the tail, shrink the row, recompute the root, and the verifier prints OK over deleted governed
    actions. The one thing the forger cannot rewrite is `seal()`'s own announcement — hash-chained
    and signed, and still stating the range that was really sealed.
    """
    with store() as s:
        for row in s.scalars(select(AuditRecord).where(AuditRecord.seq >= 3)).all():
            s.delete(row)
        ep = s.get(MerkleRoot, 0)
        ep.seq_end, ep.leaf_count = 2, 3
        ep.root = merkle_root(
            list(s.scalars(select(AuditRecord.record_hash).order_by(AuditRecord.seq.asc())).all())
        )
        s.commit()

    result = verify_chain(store)

    assert not result.ok
    assert result.violation.check == "merkle_announcement_missing"


def test_an_epoch_row_that_contradicts_its_announcement_is_caught(store, sealer) -> None:
    """The same forgery with the announcement left in place: the row and the chain now disagree
    about what was sealed, and the chain is the half that is signed."""
    with store() as s:
        s.get(MerkleRoot, 0).root = "ab" * 32
        s.commit()

    result = verify_chain(store)

    assert not result.ok
    assert result.violation.check == "merkle_announcement_mismatch"


def test_a_forged_seq_end_fails_fast_instead_of_hanging_the_verifier(store, sealer) -> None:
    """`merkle_root` has no append-only trigger and is exactly the table a forger writes to. A
    range materialized before it is bounded turns a caught forgery into a hung CI job — the
    operator reads that as a broken build, not as evidence."""
    with store() as s:
        s.get(MerkleRoot, 0).seq_end = 10**18
        s.commit()

    started = time.perf_counter()
    result = verify_chain(store)

    assert time.perf_counter() - started < 5.0
    assert not result.ok and result.violation.check == "merkle_range_incomplete"


def test_an_anchored_epoch_verifies_and_a_corrupted_anchor_does_not(store, sealer) -> None:
    """The epoch inherits AUD-05's external authority through the SAME dispatch — including its
    failure mode, so a re-anchored rewrite cannot pass as the original."""
    engine = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    sealer.anchor_epoch(0, LocalEd25519Anchor(engine))

    clean = verify_chain(store, public_key_pem=engine.public_key_pem)

    assert clean.ok and clean.epochs_checked == 1 and clean.skipped_epochs == 0
    with store() as s:
        row = s.get(MerkleRoot, 0)
        row.proof = b"\x00" * len(row.proof)
        s.commit()
    result = verify_chain(store, public_key_pem=engine.public_key_pem)
    assert not result.ok and result.violation.check == "merkle_anchor_proof"


def test_an_anchor_kind_with_no_proof_bytes_fails_rather_than_crashing(store, sealer) -> None:
    """`proof` is nullable (sealing and anchoring are separate steps), so a row claiming an anchor
    it does not carry is reachable by DB write. A CI verifier that raised there would look like a
    broken build rather than a caught forgery."""
    engine = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    sealer.anchor_epoch(0, LocalEd25519Anchor(engine))
    with store() as s:
        s.get(MerkleRoot, 0).proof = None
        s.commit()

    result = verify_chain(store, public_key_pem=engine.public_key_pem)

    assert not result.ok and result.violation.check == "merkle_anchor_proof"


def test_an_unverifiable_anchor_is_skipped_not_silently_passed(store, sealer) -> None:
    """A skipped anchor means the external authority was NOT checked. Counting it is the difference
    between 'verified' and 'we did not look' — the posture the checkpoint pass already takes."""
    sealer.anchor_epoch(
        0, LocalEd25519Anchor(IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5))
    )

    result = verify_chain(store)  # no public key supplied

    assert result.ok and result.epochs_checked == 1 and result.skipped_epochs == 1


# ---------------------------------------------------------- re-review: the announcement's OTHER half


def _signed_sealed(n: int = 5):
    """A REAL signed chain with epoch 0 sealed. Returns (session_factory, sealer, IdentityEngine).

    The pre-existing truncation test above runs on the `audit` fixture, which has no signer — so it
    demonstrated the unsigned case while its docstring claimed "the STRONGEST posture (signed
    chain)". These tests use a chain that is actually signed, because the attack they cover only
    exists there: it is the appended UNSIGNED row that does the damage.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    sf = create_session_factory(engine)
    signer = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    audit = AuditWriter(sf, signer=signer)
    for i in range(n):
        asyncio.run(
            audit.append_event("framework_discovered", {"framework": f"f{i}", "distribution": "d", "version": "1"})
        )
    sealer = MerkleSealer(sf, audit)
    asyncio.run(sealer.seal())
    return sf, sealer, signer


def _append_unsigned(sf, body: dict) -> None:
    """Append a row the way a DB-write attacker does: correctly hash-chained, NOT signed.

    Chaining costs nothing — canonical_json and sha256 are public. Signing is the part that needs a
    key the forger does not have, which is exactly why the announcement check has to require it.
    """
    with sf() as s:
        head = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).first()
        full = dict(body, seq=head.seq + 1, prev_hash=head.record_hash)
        s.add(
            AuditRecord(
                seq=full["seq"],
                prev_hash=full["prev_hash"],
                record_hash=hashlib.sha256(canonical_json(full)).hexdigest(),
                body=full,
            )
        )
        s.commit()


def test_an_unsigned_announcement_cannot_become_the_authority_it_replaces() -> None:
    """REGRESSION: the announcement check required hash-chaining but never required the SIGNATURE.

    Truncate the log past the genuine announcement, shrink the epoch row to match, then append your
    own unsigned `merkle_epoch_sealed` describing the forged range. Appending is free; only signing
    is not. Before this fix the forged announcement was the ONLY one for epoch 0, so the check that
    exists to measure the row against the chain measured it against the forger's own record and
    printed OK over destroyed governed actions — with no signature warning, because other rows in
    the chain were still signed.
    """
    sf, _, signer = _signed_sealed()
    pub = signer.public_key_pem

    assert verify_chain(sf, public_key_pem=pub).ok

    with sf() as s:
        for row in s.scalars(select(AuditRecord).where(AuditRecord.seq >= 3)).all():
            s.delete(row)
        ep = s.get(MerkleRoot, 0)
        ep.seq_end, ep.leaf_count = 2, 3
        ep.root = merkle_root(
            list(s.scalars(select(AuditRecord.record_hash).order_by(AuditRecord.seq.asc())).all())
        )
        s.commit()
    _append_unsigned(
        sf,
        {
            "kind": "merkle_epoch_sealed",
            "epoch": 0,
            "seq_start": 0,
            "seq_end": 2,
            "root": None,  # filled below from the forged row so the announcement agrees with it
            "leaf_count": 3,
        },
    )
    with sf() as s:  # make the forged announcement agree with the forged row exactly
        forged = s.scalars(
            select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)
        ).first()
        body = dict(forged.body, root=s.get(MerkleRoot, 0).root)
        forged.body = body
        forged.record_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        s.commit()

    result = verify_chain(sf, public_key_pem=pub)

    assert not result.ok, "an unsigned announcement must not be able to vouch for an epoch row"
    assert result.violation.check == "merkle_announcement_unsigned"


def test_deleting_the_epoch_row_deletes_the_check_and_is_caught() -> None:
    """REGRESSION: the Merkle pass iterated only the rows that EXIST.

    So a forger who rewrote history and then dropped the epoch row did not fail the check — they
    removed it, and `epochs_checked == 0` reads exactly like a deployment that never sealed. The
    evidence to notice was already loaded: the chain still announces that the epoch was sealed. The
    table is attacker-writable; the hash-chained announcement is not.
    """
    sf, _, signer = _signed_sealed()

    with sf() as s:
        s.delete(s.get(MerkleRoot, 0))
        s.commit()

    result = verify_chain(sf, public_key_pem=signer.public_key_pem)

    assert not result.ok
    assert result.violation.check == "merkle_epoch_row_missing"


def test_a_wholly_unsigned_chain_is_not_broken_by_the_signed_announcement_rule(store, sealer) -> None:
    """The gate is the chain's signature POSTURE, not whether a key was passed.

    AUD-08 makes signing optional, and a caller may supply a public key purely to verify a
    local_ed25519 ANCHOR on a chain whose rows are legitimately unsigned. That caller has no
    signature posture to bypass, so requiring a signed announcement there would fail every
    unsigned-but-honest deployment — a false alarm on the verifier is how operators learn to ignore
    it.
    """
    assert verify_chain(store).ok
    assert verify_chain(store, public_key_pem="not-used-because-no-row-is-signed").ok is True
