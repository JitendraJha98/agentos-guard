"""Phase 16 — RED-01 keyed audit digests and RED-02 PII recall.

An unkeyed SHA-256 of a low-entropy value is not redaction: an SSN has 10^9 candidates, so the
"redacted" value in the audit log was one brute-force loop away. With a deployment key the digest
is an HMAC, useless without the key; without one, the legacy form is unchanged.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

import pytest
from sqlalchemy import create_engine, select

from agentos_contract import ActionType, AgentAction, Decision, Outcome
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter, digest_key_id, resolve_digest_key
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.identity_engine import IdentityEngine
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import ApprovalRequest, AuditRecord
from agentos_pipeline.risk.pii import PiiScorer

KEY = b"k" * 32
SSN = "123-45-6789"


def _sf():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _action(content: str) -> AgentAction:
    return AgentAction(
        agent_id="a", type=ActionType.tool_call, target="t",
        payload={"url": "https://x.example/p?q=1", "content": content},
    )


def _append(writer, content):
    action = _action(content)
    asyncio.run(writer.append(action, Decision(action_id=action.id, outcome=Outcome.allow)))
    with writer.session_factory() as s:
        return s.scalars(select(AuditRecord)).all()[-1].body["redacted_payload"]["content"]


def test_a_keyed_digest_is_an_hmac_and_names_its_key() -> None:
    stored = _append(AuditWriter(_sf(), digest_key=KEY), SSN)
    assert set(stored) == {"len", "hmac_sha256", "key_id"}
    assert stored["key_id"] == digest_key_id(KEY) and KEY.hex() not in stored["key_id"]
    # The brute-force the unkeyed form allowed: the plain SHA-256 of the SSN is NOT stored.
    assert stored["hmac_sha256"] != hashlib.sha256(SSN.encode()).hexdigest()
    assert SSN not in str(stored)


def test_keyed_digests_are_stable_per_key_and_differ_across_keys() -> None:
    a = _append(AuditWriter(_sf(), digest_key=KEY), SSN)
    b = _append(AuditWriter(_sf(), digest_key=KEY), SSN)
    c = _append(AuditWriter(_sf(), digest_key=b"z" * 32), SSN)
    assert a["hmac_sha256"] == b["hmac_sha256"]  # correlatable within a deployment (forensics)
    assert a["hmac_sha256"] != c["hmac_sha256"] and a["key_id"] != c["key_id"]


def test_without_a_key_the_legacy_form_is_unchanged(monkeypatch) -> None:
    monkeypatch.delenv("AGENTOS_AUDIT_DIGEST_KEY", raising=False)
    stored = _append(AuditWriter(_sf()), SSN)
    assert stored == {"len": len(SSN), "sha256": hashlib.sha256(SSN.encode()).hexdigest()}


def test_the_key_comes_from_the_environment(monkeypatch) -> None:
    monkeypatch.setenv("AGENTOS_AUDIT_DIGEST_KEY", "e" * 40)
    assert "hmac_sha256" in _append(AuditWriter(_sf()), SSN)


@pytest.mark.parametrize("weak", ["short", b"x" * 31])
def test_a_guessable_key_is_refused_at_startup(weak) -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        resolve_digest_key(weak)


def test_keyed_records_still_sign_verify_and_pass_the_secret_gate() -> None:
    """The HMAC hex and key_id must not trip AUD-04's scanner (a 64-hex run is not a secret), and
    the chain must verify exactly as before."""
    sf = _sf()
    signer = IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)
    writer = AuditWriter(sf, signer=signer, digest_key=KEY)
    for content in (SSN, "x" * 5000, "", "AKIA-looking but digested: AKIAIOSFODNN7EXAMPLE"):
        _append(writer, content)
    result = verify_chain(sf, public_key_pem=signer.public_key_pem)
    assert result.ok and result.signatures_checked == 4


def test_approval_context_uses_the_same_key() -> None:
    sf = _sf()
    writer = AuditWriter(sf, digest_key=KEY)
    action = _action(SSN)
    ApprovalStore(sf, writer).create(
        action, Decision(action_id=action.id, outcome=Outcome.require_approval), deadline_s=60
    )
    with sf() as s:
        context = s.scalars(select(ApprovalRequest)).one().context
    assert set(context["content"]) == {"len", "hmac_sha256", "key_id"}


# ---- RED-02: PII recall ----


@pytest.mark.parametrize(
    "text,expected",
    [
        ("call +1 415-555-2671 now", ["phone"]),
        ("UK +44 20 7946 0958", ["phone"]),
        ("NANP 415.555.2671", ["phone"]),
        ("IBAN GB82 WEST 1234 5698 7654 32", ["iban"]),
        ("DE89370400440532013000", ["iban"]),
        ("NO9386011117947", ["iban"]),  # the shortest national IBAN (15)
        # Things that must NOT be PII:
        ("checksum-wrong GB82 WEST 1234 5698 7654 33", []),
        ("version 1.2.3 built 2024-01-15", []),
        ("host 192.168.100.1", []),
        ("semver +1.2.3", []),
        ("mixed separators 415-555.2671", []),
        ("request id AB12CDEF3456GHIJ", []),
    ],
)
def test_pii_recall_and_precision(text, expected) -> None:
    assert PiiScorer.find_pii(text) == expected


@pytest.mark.parametrize(
    "adversarial",
    [
        "GB82 " + "AAAA " * 6500,
        "+1 " + "1 " * 16000,
        "415." * 8000,
        "A1" * 16000,
    ],
)
def test_new_patterns_stay_linear_on_hostile_input(adversarial) -> None:
    """ReDoS guard: 32 KB of near-miss input must scan in milliseconds (these run on every action)."""
    start = time.perf_counter()
    PiiScorer.find_pii(adversarial[:32 * 1024])
    assert time.perf_counter() - start < 0.25
