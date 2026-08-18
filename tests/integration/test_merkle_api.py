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
from agentos_controlplane.merkle import MerkleSealer, verify_inclusion
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
    """The end-to-end claim of AUD-06: a third party holding ONLY the bundle can verify it."""
    bundle = client.get("/audit/disclose/2").json()

    assert verify_inclusion(
        bundle["record"]["record_hash"],
        bundle["index"],
        bundle["proof"],
        bundle["epoch"]["root"],
        bundle["epoch"]["leaf_count"],
    )


def test_a_bundle_discloses_one_record_and_summarizes_the_rest_as_hashes(client) -> None:
    """Partial disclosure is the requirement — a bundle that leaked its siblings' bodies would be
    no better than mailing the whole log."""
    blob = client.get("/audit/disclose/2").text

    assert '"f2"' in blob
    for other in ("f0", "f1", "f3", "f4"):
        assert f'"{other}"' not in blob


def test_the_epoch_list_reports_what_was_sealed(client) -> None:
    rows = client.get("/audit/epochs").json()

    assert [(r["seq_start"], r["seq_end"], r["leaf_count"]) for r in rows] == [(0, 4, RECORDS)]
    assert rows[0]["anchored"] is False and rows[0]["anchor_kind"] is None


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
    first one's end would quietly strand everything between them."""
    with store() as s:
        s.add(MerkleRoot(epoch=1, seq_start=99, seq_end=100, root="ab" * 32, leaf_count=2))
        s.commit()

    result = verify_chain(store)

    assert not result.ok
    assert result.violation.check == "merkle_epoch_overlap"


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
