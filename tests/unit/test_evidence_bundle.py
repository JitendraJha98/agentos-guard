"""CMP-06 — the evidence bundle: per framework, per range, verifiable by someone holding neither
our database nor our trust.

The failures this file guards are all failures of HONESTY rather than of computation. A bundle that
verifies against nothing is an extract the recipient must take on our word. A range that leaks its
neighbours over-discloses records the auditor was not entitled to, and the operator cannot say what
they sent. Records silently dropped for being unsealed, or silently truncated for being numerous,
shrink the evidence without saying so. And an artifact that leaves the building carrying article
references without the D-8 statement of what they are not is the one mistake in this phase that
cannot be walked back after a regulator reads it.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.pool import StaticPool

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.checkpoint import LocalEd25519Anchor
from agentos_controlplane.compliance import (
    EU_AI_ACT_DISCLAIMER,
    EVIDENCE_BUNDLE_DISCLAIMER,
    FRAMEWORKS,
    OWASP_AGENTIC,
    RANGE_NOTE,
    _MAX_RECORDS,
    bundle_digest,
    export_evidence_bundle,
    parse_time_bound,
    verifiable_record,
)
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.merkle import MerkleIntegrityError, MerkleSealer, verify_bundle
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord

SEALED_RECORDS = 5  # seq 0..4 seal into epoch 0; the seal's own announcement lands unsealed at 5
Q1 = datetime(2026, 1, 15, 12, 0, 0)
Q3 = datetime(2026, 7, 15, 12, 0, 0)
MIDYEAR = datetime(2026, 4, 1)


@pytest.fixture
def signer() -> IdentityEngine:
    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)


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
def audit(store, signer) -> AuditWriter:
    """ONE signed writer over the store — a second instance caches a stale chain head, and signed
    because the bundle's per-record signature is half of what authenticates it."""
    return AuditWriter(store, signer=signer)


def _append(audit: AuditWriter, n: int) -> None:
    async def _run() -> None:
        for i in range(n):
            await audit.append_event(
                "framework_discovered",
                {"framework": f"f{i}", "distribution": "d", "version": "1"},
            )

    asyncio.run(_run())


def _stamp(store, moment: datetime, *seqs: int) -> None:
    """Rewrite `created_at` on the given records to fake two audit windows.

    `created_at` is the ONE field neither the record hash nor the AUD-08 signature covers — which is
    exactly why the bundle calls its range administrative metadata. Moving it therefore leaves the
    chain, the signatures and the sealed root intact, and lets the range test run in milliseconds
    instead of waiting out SQLite's one-second `created_at` granularity."""
    with store() as s:
        s.execute(update(AuditRecord).where(AuditRecord.seq.in_(seqs)).values(created_at=moment))
        s.commit()


@pytest.fixture
def sealed(store, audit, signer):
    """Five records sealed into an ANCHORED epoch 0, then the seal's announcement left unsealed."""
    _append(audit, SEALED_RECORDS)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    sealer.anchor_epoch(0, LocalEd25519Anchor(signer))
    return store


@pytest.fixture
def bundle(sealed, signer) -> dict:
    return export_evidence_bundle("soc2", sealed, public_key_pem=signer.public_key_pem)


# --- the standalone claim ---------------------------------------------------


def test_every_included_record_verifies_standalone_against_an_anchored_root(bundle, signer) -> None:
    """The claim CMP-06 makes. Nothing in this test touches a database.

    Through `merkle.verify_bundle`, never `verify_inclusion`: the tree check alone binds a
    record_hash, so feeding it the bundle's own hash asserts only that the file agrees with itself —
    something a forger satisfies for free. And `.anchor_verified` is asserted SEPARATELY, because
    that flag is what makes `root` and `leaf_count` more than numbers the exporter typed.
    """
    included = [e for e in bundle["records"] if e["inclusion"] is not None]
    assert len(included) == SEALED_RECORDS, "the fixture must seal an epoch or this proves nothing"

    for entry in included:
        result = verify_bundle(
            verifiable_record(bundle, entry), public_key_pem=signer.public_key_pem
        )
        assert result.ok, (entry["record"]["seq"], result.reason)
        assert result.anchor_verified, (entry["record"]["seq"], result.reason)


def test_a_tampered_record_fails_its_own_proof(bundle, signer) -> None:
    """The property that makes the bundle evidence rather than an extract: an edited body no longer
    hashes to the leaf the anchored root commits to."""
    entry = next(e for e in bundle["records"] if e["inclusion"] is not None)
    payload = verifiable_record(bundle, entry)
    payload["record"] = dict(
        payload["record"], body=dict(payload["record"]["body"], framework="fabricated")
    )

    assert not verify_bundle(payload, public_key_pem=signer.public_key_pem).ok


def test_a_bundle_discloses_its_own_records_and_summarizes_the_rest_as_hashes(store, audit, signer):
    """Partial disclosure is the requirement. A bundle for Q3 that carried Q1's bodies inside its
    proof paths would be no better than mailing the whole log."""
    _append(audit, SEALED_RECORDS)
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    sealer.anchor_epoch(0, LocalEd25519Anchor(signer))
    _stamp(store, Q1, 0, 1, 2)
    _stamp(store, Q3, 3, 4, 5)

    blob = json.dumps(export_evidence_bundle("soc2", store, start=MIDYEAR))

    assert '"f3"' in blob and '"f4"' in blob
    for withheld in ("f0", "f1", "f2"):
        assert f'"{withheld}"' not in blob


# --- the range --------------------------------------------------------------


def test_the_bundle_contains_only_the_requested_range(sealed) -> None:
    """A range that silently leaks its neighbours is a privacy failure and a correctness one at
    once: the auditor receives records they were not entitled to, and the operator cannot say what
    they disclosed."""
    _stamp(sealed, Q1, 0, 1, 2)
    _stamp(sealed, Q3, 3, 4, 5)

    early = export_evidence_bundle("soc2", sealed, end=MIDYEAR)
    late = export_evidence_bundle("soc2", sealed, start=MIDYEAR)

    early_seqs = {e["record"]["seq"] for e in early["records"]}
    late_seqs = {e["record"]["seq"] for e in late["records"]}
    assert early_seqs == {0, 1, 2}
    assert late_seqs == {3, 4, 5}
    assert early_seqs.isdisjoint(late_seqs)


def test_the_range_is_echoed_with_what_it_is_actually_filtered_on(sealed) -> None:
    """A recipient reading a window is entitled to know the window itself is not tamper-evident."""
    b = export_evidence_bundle("soc2", sealed, start=Q1, end=Q3)

    assert b["range"]["start"] == Q1.isoformat() and b["range"]["end"] == Q3.isoformat()
    assert b["range"]["note"] == RANGE_NOTE
    assert "created_at" in RANGE_NOTE and "seq" in RANGE_NOTE


def test_an_empty_window_is_an_honest_zero_rather_than_an_error(sealed) -> None:
    """A quiet quarter is a real answer, and it still needs the mapping and the disclaimer to be
    readable as one."""
    b = export_evidence_bundle("soc2", sealed, start=datetime(2030, 1, 1))

    assert b["records"] == [] and b["epochs"] == {}
    assert b["verification"]["records_in_range"] == 0
    assert b["mapping"] and b["disclaimer"] == EVIDENCE_BUNDLE_DISCLAIMER


def test_a_malformed_bound_is_refused_rather_than_ignored() -> None:
    """Ignoring an unparseable `start` exports the ENTIRE log: the operator asked for a quarter,
    disclosed a year, and nothing in the artifact says so."""
    assert parse_time_bound(None) is None
    assert parse_time_bound("2026-04-01") == MIDYEAR

    for junk in ("last-tuesday", "2026-13-01", "", "   ", "04/01/2026"):
        with pytest.raises(ValueError):
            parse_time_bound(junk)


def test_an_aware_bound_in_another_zone_is_converted_not_truncated(sealed) -> None:
    """A caller in UTC+14 asking for 'since yesterday' must not have its offset dropped — the same
    rule the SOC 2 counts follow, applied to the records they are counted from."""
    _stamp(sealed, datetime(2026, 5, 1, 12, 0, 0), *range(SEALED_RECORDS + 1))
    far_east = timezone(timedelta(hours=14))
    just_before = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc).astimezone(far_east)

    b = export_evidence_bundle("soc2", sealed, start=just_before)

    assert len(b["records"]) == SEALED_RECORDS + 1


# --- what is never silently dropped -----------------------------------------


def test_unsealed_records_are_reported_not_dropped(bundle) -> None:
    """Omitting them would shrink the evidence without saying so. The seal's own announcement is
    always one of them, which is why this holds on every freshly sealed chain."""
    unsealed = [e for e in bundle["records"] if e["inclusion"] is None]

    assert bundle["verification"]["records_unsealed"] == len(unsealed) >= 1
    assert all(e["record"]["body"] for e in unsealed), "the record itself still travels"


def test_a_large_range_is_bounded_and_says_how_much_it_left_behind(sealed, monkeypatch) -> None:
    """An unbounded export is a memory event on our side and an unusable artifact on theirs, so the
    recipient is told they hold a subset AND how big a one.

    The cap is monkeypatched rather than seeded past: 5001 hash-chained, signed appends prove
    nothing the fourth one does not, and the branch under test is identical either way.
    """
    monkeypatch.setattr("agentos_controlplane.compliance._MAX_RECORDS", 3)

    v = export_evidence_bundle("soc2", sealed)["verification"]

    assert v["truncated"] is True
    assert v["records_exported"] == 3
    assert v["records_in_range"] == SEALED_RECORDS + 1  # the gap is visible, not just flagged


def test_the_shipped_record_cap_is_actually_a_bound() -> None:
    assert isinstance(_MAX_RECORDS, int) and 0 < _MAX_RECORDS <= 50_000


def test_an_untruncated_bundle_does_not_claim_to_be_truncated(bundle) -> None:
    """Non-vacuity for the flag above: a `truncated` that is always True says nothing."""
    v = bundle["verification"]

    assert v["truncated"] is False
    assert v["records_exported"] == v["records_in_range"] == SEALED_RECORDS + 1
    assert v["records_included"] + v["records_unsealed"] == v["records_exported"]


def test_the_bundle_separates_included_from_anchored(bundle) -> None:
    """`leaf_count` is authenticated only where the root is anchored (11a). A recipient counting
    'verified' records without that distinction is certifying our own word."""
    v = bundle["verification"]

    assert v["records_anchored"] == v["records_included"] == SEALED_RECORDS
    assert all(ep["anchored"] is True for ep in bundle["epochs"].values())


def test_an_unanchored_epoch_is_reported_as_such_rather_than_counted_as_anchored(store, audit):
    """The other half of the flag: sealing and anchoring are separate steps, and a bundle whose root
    nothing external vouches for must not read like one that has been anchored."""
    _append(audit, SEALED_RECORDS)
    asyncio.run(MerkleSealer(store, audit).seal())  # sealed, deliberately NOT anchored

    b = export_evidence_bundle("soc2", store)

    assert b["verification"]["records_included"] == SEALED_RECORDS
    assert b["verification"]["records_anchored"] == 0
    assert all(ep["anchored"] is False for ep in b["epochs"].values())


def test_a_record_deleted_from_under_a_sealed_root_is_refused_not_exported(sealed) -> None:
    """A bundle we cannot verify ourselves must never leave: to an auditor an unverifiable proof
    reads as tampering, not as our bug. Same posture as `MerkleSealer.disclose`."""
    with sealed() as s:
        s.delete(s.scalars(select(AuditRecord).where(AuditRecord.seq == 4)).one())
        s.commit()

    with pytest.raises(MerkleIntegrityError):
        export_evidence_bundle("soc2", sealed)


def test_a_body_edited_under_a_sealed_root_is_refused_not_exported(sealed) -> None:
    """The other integrity failure, and the one the leaf-count check cannot see: nothing was
    deleted, so the epoch still covers exactly `leaf_count` records. Only re-deriving each proof
    before the bundle leaves catches it — otherwise this ships looking correct and fails in the
    auditor's hands, where it reads as tampering rather than as our bug."""
    with sealed() as s:
        row = s.scalars(select(AuditRecord).where(AuditRecord.seq == 2)).one()
        row.body = dict(row.body, framework="tampered")
        s.commit()

    with pytest.raises(MerkleIntegrityError):
        export_evidence_bundle("soc2", sealed)


# --- the manifest digest ----------------------------------------------------


def test_the_manifest_digest_detects_an_edited_bundle(bundle) -> None:
    assert bundle_digest(bundle) == bundle["manifest_digest"]

    for edited in (
        dict(bundle, records=bundle["records"][:-1]),  # a record dropped
        dict(bundle, range=dict(bundle["range"], start="2020-01-01T00:00:00")),  # a range widened
        dict(
            bundle,
            verification=dict(bundle["verification"], truncated=True),  # a caveat flipped
        ),
    ):
        assert bundle_digest(edited) != bundle["manifest_digest"]


def test_the_manifest_digest_survives_the_json_round_trip_it_will_actually_take(bundle) -> None:
    """The recipient recomputes it over a FILE, not over our in-memory dict. A digest taken over
    anything `json.dumps`/`json.loads` changes — a tuple, an int key, a datetime — would fail for
    every honest recipient and read to them as a tampered bundle."""
    assert bundle_digest(json.loads(json.dumps(bundle))) == bundle["manifest_digest"]


def test_the_bundle_states_what_the_digest_and_the_root_do_NOT_prove(bundle) -> None:
    """Two over-readings the artifact has to pre-empt, because both are ways a recipient over-claims
    on our word: that the digest authenticates the exporter, and that a root proves completeness."""
    steps = " ".join(bundle["verification"]["how_to_verify"]).lower()

    assert "does not authenticate the exporter" in steps
    assert "verify_bundle, not verify_inclusion" in steps
    assert "anchor_verified" in steps
    assert "cannot show the epoch is complete" in steps


# --- per framework ----------------------------------------------------------


def test_each_framework_exports_only_its_own_mapping(sealed) -> None:
    for framework in FRAMEWORKS:
        b = export_evidence_bundle(framework, sealed)
        assert b["framework"] == framework and b["mapping"], framework

    assert set(export_evidence_bundle("owasp_agentic_2026", sealed)["mapping"]) == set(
        OWASP_AGENTIC
    )
    soc2 = json.dumps(export_evidence_bundle("soc2", sealed)["mapping"])
    assert "ASI01" not in soc2 and "Art." not in soc2


def test_an_unknown_framework_is_refused_rather_than_answered_emptily(sealed) -> None:
    """An empty bundle for a typo'd framework reads as 'no evidence exists' — the wrong conclusion
    drawn from a wrong name."""
    with pytest.raises(ValueError, match="unknown framework"):
        export_evidence_bundle("not-a-framework", sealed)


def test_the_soc2_evidence_is_derived_over_the_same_window_as_the_records(store, audit) -> None:
    """11e left `derive_soc2_evidence` with no production caller; this is it. The counts must be
    scoped to the SAME window as the records, or the bundle reports a quarter's records beside the
    whole log's counts and an auditor reads the pair as consistent."""

    async def _kill_switch() -> None:
        await audit.append_event(
            "kill_switch_set", {"target": "t", "scope": "agent", "set_by": "op"}
        )

    asyncio.run(_kill_switch())
    _stamp(store, Q1, 0)
    asyncio.run(_kill_switch())
    _stamp(store, Q3, 1)

    early = export_evidence_bundle("soc2", store, end=MIDYEAR)["derived_evidence"]
    late = export_evidence_bundle("soc2", store, start=MIDYEAR)["derived_evidence"]

    assert early["CC7"]["counts"]["kill_switch_set"] == 1
    assert late["CC7"]["counts"]["kill_switch_set"] == 1
    assert early["CC7"]["range"]["end"] == MIDYEAR.isoformat()


def test_the_eu_bundle_carries_the_operator_declared_risk_classifications(store, audit) -> None:
    """CMP-04's determination is the operator's, and the export echoes it rather than inferring it —
    including the statement that it is read NOW, not as of the range."""
    registry = Registry(store, audit=audit)
    registry.register("a1")
    asyncio.run(registry.declare_risk_classification("a1", "high_risk", declared_by="op"))

    derived = export_evidence_bundle("eu_ai_act", store)["derived_evidence"]

    assert derived["risk_classifications"]["a1"] == "high_risk"
    assert "operator-declared, never inferred" in derived["risk_classification_source"]
    assert "not the tiers in force during the exported range" in derived["as_of"]


def test_a_taxonomy_with_no_aggregate_says_so_instead_of_returning_an_empty_object(sealed) -> None:
    """`{}` reads as 'no evidence exists'. That is a different statement, and a false one."""
    for framework in ("owasp_agentic_2026", "nist_ai_rmf"):
        note = export_evidence_bundle(framework, sealed)["derived_evidence"]["note"]
        assert framework in note and "no evidence exists" not in note.lower()


# --- D-8: the artifact that leaves the building -----------------------------

# `records` is the ONE exempt section, and only because those bodies are verbatim, hash-committed
# audit data: we cannot edit them without destroying the evidence they are, and an "Art." inside an
# agent's own payload is that agent's string rather than a citation of ours. Everything we WRITE is
# in scope — keys and list values alike — because a section lifted out with `jq` carries only what
# is inside it.
_VERBATIM = "records"


def test_no_authored_section_carries_articles_without_the_disclaimer(sealed) -> None:
    """The blunt 11e guard, applied to the artifact that actually leaves our hands.

    11e spent two review rounds establishing that any "Art." in a section — in a key or in a list
    value — requires the disclaimer inside that same section, because a consumer lifts sections, not
    bundles. An evidence bundle is built to be forwarded, so the rule matters more here than there.
    """
    for framework in FRAMEWORKS:
        bundle = export_evidence_bundle(framework, sealed)
        for key, section in bundle.items():
            if key == _VERBATIM:
                continue
            blob = json.dumps(section, ensure_ascii=False)
            if "Art." not in blob:
                continue
            assert EU_AI_ACT_DISCLAIMER in blob, (
                f"{framework}: bundle[{key!r}] can be lifted out carrying EU AI Act article "
                "references and no statement of what they are not"
            )


def test_the_eu_bundle_is_the_only_one_that_mentions_articles_at_all(sealed) -> None:
    """Non-vacuity for the guard above, in both directions: the EU bundle must carry articles (or
    the guard passes over nothing) and the other three must not (or they inherit an obligation to
    disclaim something they never claimed)."""
    eu = export_evidence_bundle("eu_ai_act", sealed)
    eu.pop(_VERBATIM)
    assert "Art." in json.dumps(eu)

    for framework in ("owasp_agentic_2026", "nist_ai_rmf", "soc2"):
        other = export_evidence_bundle(framework, sealed)
        other.pop(_VERBATIM)
        assert "Art." not in json.dumps(other), framework


def test_the_bundle_carries_the_non_conformity_disclaimer(bundle) -> None:
    """It travels OUTSIDE our hands. The disclaimer rides inside it, not in our docs."""
    assert bundle["disclaimer"] == EVIDENCE_BUNDLE_DISCLAIMER
    assert "not a conformity assessment" in json.dumps(bundle).lower()


def test_no_framework_bundle_makes_a_conformity_claim(sealed, assert_no_conformity_claim) -> None:
    for framework in FRAMEWORKS:
        assert_no_conformity_claim(json.dumps(export_evidence_bundle(framework, sealed)))
