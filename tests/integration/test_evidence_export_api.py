"""CMP-06 — the one click: a gated export route and a CLI, end to end.

The claim under test is that the artifact survives the trip. A bundle that verifies in-process but
not after FastAPI has serialized it, or after the CLI has written and re-read it, is not the thing
CMP-06 promises — the recipient always holds JSON someone sent them, never our objects. So the
verification here runs on the parsed HTTP response and on the file on disk, through
`merkle.verify_bundle`, with no database in reach.

The route is gated for the same reason the AUD-06 disclosure route is: an evidence bundle is a
curated disclosure of who did what, and deciding who receives it is the operator's call rather than
a URL's.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.checkpoint import LocalEd25519Anchor
from agentos_controlplane.compliance import FRAMEWORKS, _main, bundle_digest, verifiable_record
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.merkle import MerkleSealer, verify_bundle
from agentos_controlplane.store.engine import create_all, create_session_factory

TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
RECORDS = 5  # seq 0..4 seal into epoch 0; the seal's announcement lands unsealed at seq 5


@pytest.fixture
def signer() -> IdentityEngine:
    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)


def _seed(store, signer) -> None:
    audit = AuditWriter(store, signer=signer)

    async def _run() -> None:
        for i in range(RECORDS):
            await audit.append_event(
                "framework_discovered",
                {"framework": f"f{i}", "distribution": "d", "version": "1"},
            )

    asyncio.run(_run())
    sealer = MerkleSealer(store, audit)
    asyncio.run(sealer.seal())
    sealer.anchor_epoch(0, LocalEd25519Anchor(signer))


@pytest.fixture
def store(signer):
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    sf = create_session_factory(engine)
    _seed(sf, signer)
    return sf


@pytest.fixture
def seeded_db(tmp_path, signer):
    """A FILE-backed store, because the CLI reaches it by path rather than by object."""
    path = tmp_path / "evidence.db"
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    create_all(engine)
    _seed(create_session_factory(engine), signer)
    return path


def _app(store, wired: bool = True):
    inventory = InventoryStore(store)
    inventory.declare("a", tools=["http_get"])
    return create_app(
        ApprovalStore(store, AuditWriter(store)),
        inventory_store=inventory,
        api_token=TOKEN,
        session_factory=store if wired else None,
    )


@pytest.fixture
def client(store) -> TestClient:
    c = TestClient(_app(store))
    c.headers.update(AUTH)
    return c


@pytest.fixture
def client_no_token(store) -> TestClient:
    return TestClient(_app(store))  # no default auth header


@pytest.fixture
def client_unwired(store) -> TestClient:
    c = TestClient(_app(store, wired=False))
    c.headers.update(AUTH)
    return c


# --- the artifact survives the wire -----------------------------------------


def test_the_export_route_returns_a_bundle_that_verifies_with_no_database(client, signer) -> None:
    """Everything after `.json()` here is data a recipient could have been emailed."""
    bundle = client.get("/compliance/export/soc2").json()

    included = [e for e in bundle["records"] if e["inclusion"] is not None]
    assert len(included) == RECORDS
    for entry in included:
        result = verify_bundle(
            verifiable_record(bundle, entry), public_key_pem=signer.public_key_pem
        )
        assert result.ok and result.anchor_verified, result.reason


def test_the_digest_still_matches_after_fastapi_has_serialized_the_bundle(client) -> None:
    """The digest is computed over our dict and checked over their JSON. Anything the serializer
    reshapes on the way out breaks it for every honest recipient."""
    bundle = client.get("/compliance/export/soc2").json()

    assert bundle_digest(bundle) == bundle["manifest_digest"]


def test_the_route_exports_every_framework(client) -> None:
    for framework in FRAMEWORKS:
        response = client.get(f"/compliance/export/{framework}")
        assert response.status_code == 200, framework
        assert response.json()["framework"] == framework


# --- refusals ---------------------------------------------------------------


def test_the_export_route_is_gated(client_no_token) -> None:
    """An evidence bundle is a curated disclosure of who did what — never a public URL."""
    assert client_no_token.get("/compliance/export/soc2").status_code == 401


def test_an_unknown_framework_is_422_not_an_empty_bundle(client) -> None:
    """An empty bundle for a typo'd framework reads as 'no evidence exists' — the wrong conclusion
    drawn from a wrong URL."""
    response = client.get("/compliance/export/nope")

    assert response.status_code == 422
    assert "nope" in response.json()["detail"]


def test_a_malformed_date_is_refused_rather_than_ignored(client) -> None:
    """Ignoring an unparseable start date silently exports the ENTIRE log. The operator asked for a
    quarter, over-disclosed a year, and has no way to notice."""
    assert client.get("/compliance/export/soc2?start=last-tuesday").status_code == 422
    assert client.get("/compliance/export/soc2?end=2026-13-01").status_code == 422
    assert client.get("/compliance/export/soc2?start=").status_code == 422


def test_a_well_formed_range_still_gets_through(client) -> None:
    """Non-vacuity for the refusals above: a 422 on every range would also 'never over-disclose'."""
    response = client.get("/compliance/export/soc2?start=2020-01-01&end=2030-01-01")

    assert response.status_code == 200
    assert response.json()["range"]["start"] == "2020-01-01T00:00:00"
    assert len(response.json()["records"]) == RECORDS + 1


def test_a_range_that_excludes_everything_is_an_empty_but_honest_bundle(client) -> None:
    body = client.get("/compliance/export/soc2?start=2030-01-01").json()

    assert body["records"] == []
    assert body["verification"]["records_in_range"] == 0
    assert body["disclaimer"]


def test_an_app_with_no_store_wired_404s_and_keeps_the_other_routes(client_unwired) -> None:
    """404, not an empty 200: a bundle from a control plane that cannot read its own audit log is
    not a smaller bundle, it is a different and false statement."""
    assert client_unwired.get("/compliance/export/soc2").status_code == 404
    assert client_unwired.get("/inventory").status_code == 200


# --- the CLI ----------------------------------------------------------------


def test_the_cli_writes_a_bundle_that_verifies(tmp_path, seeded_db, signer) -> None:
    out = tmp_path / "bundle.json"

    assert _main(["--db", str(seeded_db), "--framework", "soc2", "--out", str(out)]) == 0

    bundle = json.loads(out.read_text(encoding="utf-8"))
    assert bundle["framework"] == "soc2"
    assert bundle_digest(bundle) == bundle["manifest_digest"]
    entry = next(e for e in bundle["records"] if e["inclusion"] is not None)
    assert verify_bundle(
        verifiable_record(bundle, entry), public_key_pem=signer.public_key_pem
    ).anchor_verified


def test_the_cli_honours_the_range_it_was_given(tmp_path, seeded_db) -> None:
    out = tmp_path / "empty.json"

    assert (
        _main(
            ["--db", str(seeded_db), "--framework", "soc2", "--start", "2030-01-01", "--out", str(out)]
        )
        == 0
    )

    assert json.loads(out.read_text(encoding="utf-8"))["records"] == []


def test_the_cli_refuses_a_malformed_date_rather_than_exporting_everything(seeded_db) -> None:
    """The same over-disclosure as the route's, reached from a terminal instead of a URL."""
    with pytest.raises(SystemExit):
        _main(["--db", str(seeded_db), "--framework", "soc2", "--start", "last-tuesday"])


def test_the_cli_refuses_a_framework_export_with_no_store_to_read(capsys) -> None:
    """A bundle without the records it is evidence FROM is not evidence."""
    with pytest.raises(SystemExit):
        _main(["--framework", "soc2"])


def test_the_cli_refuses_a_range_it_would_have_to_ignore(seeded_db) -> None:
    """`--start` with no `--framework` used to be silently dropped by the CMP-03 path — the same
    ignored-bound failure the parser exists to prevent, one argument earlier."""
    with pytest.raises(SystemExit):
        _main(["--db", str(seeded_db), "--start", "2026-01-01"])


def test_the_cmp03_bundle_still_prints_unchanged(seeded_db, capsys) -> None:
    """The CMP-06 flags are additive: the existing entry point keeps its behaviour."""
    assert _main(["--db", str(seeded_db)]) == 0

    parsed = json.loads(capsys.readouterr().out)
    assert set(parsed["frameworks"]) == {"owasp_agentic_2026", "nist_ai_rmf"}
    assert parsed["evidence"]["chain_verifies"] is True
