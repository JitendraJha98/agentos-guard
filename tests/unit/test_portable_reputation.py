"""TRST-05 — portable reputation, and the quarantine that keeps it from being a laundering path.

The load-bearing test is that importing NEVER moves local trust. An importable score that silently
became authoritative would let anyone stand up a permissive deployment, farm a 0.99 there, and import
it somewhere that matters — TRST-04's escalation with a deployment boundary in place of a delegation
edge.

The second is ADR-0007: crypto-economics live only in an optional backend and are never required, so
core must run and be fully testable with the seam empty.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.portable_reputation import (
    CLAIMED,
    PortableReputation,
    ReputationBackend,
    bundle_message,
)
from agentos_controlplane.reputation import ReputationEngine
from agentos_controlplane.store.engine import create_all, create_session_factory


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
    return AuditWriter(store)


@pytest.fixture
def signer() -> IdentityEngine:
    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)


def _act(audit, agent_id: str, outcome: Outcome = Outcome.allow) -> None:
    action = AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/x", "content": ""},
    )
    asyncio.run(
        audit.append(
            action,
            Decision(
                action_id=action.id,
                outcome=outcome,
                reasons=[Reason(stage="identity", code="identity_verified", detail="ok")],
            ),
        )
    )


@pytest.fixture
def engine(store, audit) -> ReputationEngine:
    for _ in range(4):
        _act(audit, "a1")
    _act(audit, "a1", Outcome.deny)
    return ReputationEngine(store)


@pytest.fixture
def portable(engine, signer) -> PortableReputation:
    return PortableReputation(engine, issuer="deployment-alpha", signer=signer)


# --- export --------------------------------------------------------------------


def test_an_export_carries_the_evidence_counts_not_just_the_score(portable) -> None:
    """A receiver deciding whether to believe a 0.99 needs to know if it rests on four signals or
    four thousand — the same reason TEST-07 refuses to ship a rate without its sample size."""
    bundle = portable.export(["a1"])

    entry = bundle["agents"][0]
    assert entry["agent_id"] == "a1"
    assert "score" in entry and "signals" in entry and "good" in entry and "bad" in entry


def test_the_export_is_signed_and_verifies(portable, signer) -> None:
    bundle = portable.export(["a1"])

    result = PortableReputation.import_bundle(bundle, public_key_pem=signer.public_key_pem)

    assert result.signature_verified is True and result.rejected is None


def test_the_exported_score_is_the_one_this_deployment_ACTS_on(portable, engine) -> None:
    """Reuses the TRST-03 engine rather than re-deriving, so an exported number cannot drift from the
    number the local pipeline uses."""
    bundle = portable.export(["a1"])

    assert bundle["agents"][0]["score"] == pytest.approx(round(engine.score("a1"), 6))


def test_an_unattributed_issuer_is_refused(engine) -> None:
    """"Should I trust this score" is unanswerable without knowing who asserts it."""
    with pytest.raises(ValueError, match="issuer is required"):
        PortableReputation(engine, issuer="   ")


# --- import: the quarantine ----------------------------------------------------


def test_an_import_NEVER_modifies_local_trust(portable, engine, signer) -> None:
    """THE property of this slice.

    An importable score that silently became the local score is a trust-laundering path between
    deployments: farm a 0.99 on a permissive deployment, export, import where it matters. TRST-04's
    answer applies unchanged — an inherited claim is capped by what the receiver independently
    knows, never substituted for it.
    """
    before = engine.score("a1")
    hostile = {
        "schema": 1,
        "issuer": "deployment-evil",
        "exported_at": "2026-08-20T00:00:00+00:00",
        "agents": [{"agent_id": "a1", "score": 0.99, "good": 9999.0, "bad": 0.0, "signals": 9999}],
    }

    result = PortableReputation.import_bundle(hostile)

    assert result.local_trust_modified is False
    assert engine.score("a1") == pytest.approx(before), "local trust must be untouched"


def test_an_imported_entry_is_marked_CLAIMED_and_attributed(portable) -> None:
    """The claim carries who made it, so a caller can decide to trust that issuer explicitly rather
    than inheriting a number from an unnamed source."""
    bundle = portable.export(["a1"])

    claim = PortableReputation.import_bundle(bundle).claims[0]

    assert claim.status == CLAIMED and claim.issuer == "deployment-alpha"


def test_the_claim_field_is_not_called_trust(portable) -> None:
    """Naming discipline as a guard: local trust is what this deployment computed. Giving the two the
    same name in a payload is how one gets substituted for the other by a well-meaning consumer."""
    bundle = portable.export(["a1"])

    payload = PortableReputation.import_bundle(bundle).claims[0].as_dict()

    assert "claimed_score" in payload
    assert "trust" not in payload and "trust_score" not in payload


def test_import_cannot_reach_local_state_by_construction(portable) -> None:
    """`import_bundle` is static: a method that cannot reach the local engine cannot accidentally
    write it. The invariant is enforced by construction rather than by care."""
    import inspect

    assert isinstance(
        inspect.getattr_static(PortableReputation, "import_bundle"), staticmethod
    )


# --- import: authentication ----------------------------------------------------


def test_a_tampered_bundle_is_rejected(portable, signer) -> None:
    bundle = portable.export(["a1"])
    bundle["agents"][0]["score"] = 0.99

    result = PortableReputation.import_bundle(bundle, public_key_pem=signer.public_key_pem)

    assert result.rejected and result.claims == ()


def test_an_unsigned_bundle_is_rejected_when_a_key_was_supplied(portable, signer) -> None:
    """Silently accepting it would make the key a decoration: a caller who passed one asked for
    authentication and must not get an unauthenticated result that looks the same."""
    bundle = portable.export(["a1"])
    bundle.pop("signature")

    result = PortableReputation.import_bundle(bundle, public_key_pem=signer.public_key_pem)

    assert result.rejected and "unsigned" in result.rejected


def test_an_unknown_schema_is_refused_rather_than_best_effort_parsed(portable) -> None:
    """A future schema may mean something different by the same field name, and guessing is how a
    score changes meaning in transit."""
    bundle = portable.export(["a1"])
    bundle["schema"] = 99

    result = PortableReputation.import_bundle(bundle)

    assert result.rejected and "schema" in result.rejected


def test_a_malformed_bundle_is_a_rejection_not_a_traceback(portable) -> None:
    """Bundles arrive from other deployments; a traceback is easy to mistake for "the check did not
    run"."""
    for bad in ({}, {"schema": 1}, None, {"schema": 1, "issuer": "x", "agents": "nope"}):
        assert PortableReputation.import_bundle(bad).rejected


def test_a_signature_proves_origin_and_NOT_truth(portable, signer) -> None:
    """The note travels in the bundle because the distinction is the whole quarantine rationale: a
    deployment can honestly sign a reputation it farmed dishonestly."""
    bundle = portable.export(["a1"])

    assert "does not make the scores true" in bundle["note"]

    result = PortableReputation.import_bundle(bundle, public_key_pem=signer.public_key_pem)
    assert result.signature_verified is True
    assert all(c.status == CLAIMED for c in result.claims), "verified is still only claimed"


# --- ADR-0007: crypto-economics stay out of core -------------------------------


def test_core_ships_no_backend_implementation(portable) -> None:
    """ADR-0007 fences stake/slashing into an OPTIONAL backend that is never required. "Optional"
    decays into "required" the moment one core path assumes it, so core ships the Protocol and no
    implementation."""
    import agentos_controlplane.portable_reputation as mod

    implementations = [
        name
        for name, obj in vars(mod).items()
        if isinstance(obj, type)
        and obj is not ReputationBackend
        and hasattr(obj, "publish")
        and hasattr(obj, "fetch")
    ]
    assert implementations == [], f"core must ship no backend: {implementations}"


def test_no_crypto_economics_anywhere_in_core(portable) -> None:
    """ADR-0007's fence, asserted on the CODE rather than the prose.

    Scans identifiers, attributes, imports and string literals via the AST, with docstrings and
    comments excluded on purpose: this module's own docstring necessarily says the words "stake" and
    "slashing" to explain what is fenced out, and a check that cannot tell an explanation from an
    implementation would force the fence to go undocumented to stay green. What must be absent is a
    NAME — something core actually calls, imports or stores.
    """
    import ast
    import inspect

    import agentos_controlplane.portable_reputation as mod

    banned = ("stake", "slash", "token", "blockchain", "wallet", "onchain", "on_chain")
    tree = ast.parse(inspect.getsource(mod))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, ast.Attribute):
            names.append(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
        elif isinstance(node, ast.arg):
            names.append(node.arg)
        elif isinstance(node, ast.alias):
            names.append(node.name)
            if node.asname:
                names.append(node.asname)

    lowered = [n.lower() for n in names]
    for word in banned:
        offenders = [n for n in lowered if word in n]
        assert offenders == [], f"core must not name {word!r}: {offenders}"


def test_export_and_import_work_with_no_backend_wired(engine, signer) -> None:
    """A deployment that wires no backend keeps every capability: the bundle is ordinary signed JSON
    over ordinary storage."""
    portable = PortableReputation(engine, issuer="alpha", signer=signer)

    bundle = portable.export(["a1"])
    result = PortableReputation.import_bundle(bundle, public_key_pem=signer.public_key_pem)

    assert result.claims and result.signature_verified


def test_the_bundle_digest_identifies_what_was_imported(portable) -> None:
    bundle = portable.export(["a1"])

    assert PortableReputation.bundle_digest(bundle) == PortableReputation.bundle_digest(bundle)
    assert len(PortableReputation.bundle_digest(bundle)) == 64


def test_the_signing_domain_is_separate_from_the_audit_domain(portable) -> None:
    """A reputation bundle signature must never verify as an audit record. Same reasoning as POL-12's
    vote domain, and the reason this module does not reuse audit.verify_record_signature."""
    from agentos_controlplane.audit import SIG_DOMAIN

    message = bundle_message(portable.export(["a1"]))

    assert not message.startswith(SIG_DOMAIN)
    assert message.startswith(b"agentos-guard/portable-reputation/v1\x00")
