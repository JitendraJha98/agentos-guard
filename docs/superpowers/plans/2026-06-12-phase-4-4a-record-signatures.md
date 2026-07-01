# Phase 4 · Slice 4a — Per-Record EdDSA Signatures + Canonicalization Pin — Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end with a second
> `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"` (Fable is currently inaccessible;
> trailer matches the model that runs). Tests: `./.venv/Scripts/python.exe -m pytest`. TDD per task.
> Gates `floor_invariant` (430) + `regression_lock` (10) green at every commit.

**Goal:** Each `AuditRecord` carries a **detached Ed25519 signature** (AUD-08), reusing the
control-plane keypair already in `IdentityEngine`, so any single record verifies on its own —
proof the control plane authored that decision, independent of the chain links. Plus pin
`canonical_json` to an exact, verifier-reproducible definition.

**Verified crypto decisions (research, 2026-06-12):**
- **Sign the canonical BODY bytes, NOT the `record_hash` digest.** Ed25519 is PureEdDSA (RFC 8032);
  signing a SHA-256 prehash forfeits its built-in collision resistance and RFC 8032 §8.7 says the
  prehash variants "SHOULD NOT be used." The body already contains `seq`+`prev_hash`, so signing it
  binds authorship to the full chain-linked content. Cost is identical (Ed25519 hashes internally).
- **Domain separation:** sign `b"agentos-guard/audit-record/v1\x00" + canonical_json(body)`. The
  SAME control-plane Ed25519 key signs agent JWTs; a fixed context prefix makes an audit signature
  unusable as a JWT (and vice-versa). The private key never leaves `IdentityEngine`.
- **Canonicalization pin:** the SAME `canonical_json(body)` output is what is both hashed
  (`record_hash`) and signed; an external verifier MUST import the exact function. Drop the
  "RFC-8785-ish" claim, pin the definition precisely. No behavior change (the verifier reuses the
  function), so existing hashes are unaffected.

## File structure
- Modify `packages/controlplane/src/agentos_controlplane/identity_engine.py` — keep the
  `Ed25519PrivateKey` object; add `sign_record(data: bytes) -> bytes` + `public_key_id` property.
- Modify `packages/controlplane/src/agentos_controlplane/store/models.py` — `AuditRecord` gains
  nullable `signature` + `signing_key_id` columns (OUT of `body`).
- Create `packages/controlplane/src/agentos_controlplane/store/migrations/versions/0003_audit_signatures.py`
  (mirror `0002_approvals.py`).
- Modify `packages/controlplane/src/agentos_controlplane/audit.py` — `SIG_DOMAIN`, `RecordSigner`
  Protocol, optional `signer`, sign on `append`/`append_event`, `verify_record_signature` helper,
  pin `canonical_json` docstring.
- Modify `tests/conftest.py` — wire `signer=registry.identity` into `_wire`'s `AuditWriter` (the
  main e2e path now produces signed records).
- Tests: `tests/unit/test_record_signatures.py`.

---

### Task 1: `IdentityEngine.sign_record` + `public_key_id`
**Files:** `identity_engine.py`; test `tests/unit/test_record_signatures.py`.

- [ ] **Failing test:**
```python
import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from agentos_controlplane.identity_engine import IdentityEngine

def _engine():
    return IdentityEngine(is_registered=lambda s: True, load_trust=lambda s: 0.5)

def test_sign_record_roundtrips_with_public_key():
    eng = _engine()
    data = b"agentos-guard/audit-record/v1\x00{\"seq\":0}"
    sig = eng.sign_record(data)
    assert isinstance(sig, bytes) and len(sig) == 64
    pub = load_pem_public_key(eng.public_key_pem.encode())
    pub.verify(sig, data)  # raises InvalidSignature on failure

def test_signature_is_message_bound():
    eng = _engine()
    sig = eng.sign_record(b"message-A")
    pub = load_pem_public_key(eng.public_key_pem.encode())
    import pytest
    with pytest.raises(InvalidSignature):
        pub.verify(sig, b"message-B")

def test_public_key_id_stable_16_hex():
    eng = _engine()
    kid = eng.public_key_id
    assert kid == eng.public_key_id and len(kid) == 16 and all(c in "0123456789abcdef" for c in kid)
```
- [ ] **Implement** in `identity_engine.py`: `import hashlib`; in `__init__` keep `self._priv = priv`
  (alongside the existing PEMs). Add:
```python
    @property
    def public_key_id(self) -> str:
        """Short stable fingerprint of the public key (AUD-08 signing_key_id) — lets a
        verifier pick the right historical key and makes a re-key auditable."""
        return hashlib.sha256(self._pub_pem).hexdigest()[:16]

    def sign_record(self, data: bytes) -> bytes:
        """Detached Ed25519 signature over `data` (AUD-08). The caller prepends the
        audit-record domain prefix; the same key signs agent JWTs, so domain separation
        prevents cross-protocol replay. The private key never leaves this engine."""
        return self._priv.sign(data)
```
- [ ] Green. Commit `feat(controlplane): IdentityEngine.sign_record + public_key_id for per-record audit signatures (AUD-08)`.

### Task 2: `AuditRecord` signature columns + migration
**Files:** `store/models.py`; `store/migrations/versions/0003_audit_signatures.py`.

- [ ] **Failing test** (append to the test file): construct the SQLite store, assert an `AuditRecord`
  can be created with `signature` + `signing_key_id` set AND with them NULL (both nullable).
- [ ] **Implement:** in `AuditRecord` add after `record_hash`:
```python
    # AUD-08: detached per-record EdDSA signature over SIG_DOMAIN + canonical_json(body),
    # and a short fingerprint of the signing public key. Nullable: a writer without a signer
    # produces unsigned records (backward compat); the production path always signs.
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)        # 64-byte sig, hex
    signing_key_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
```
  Create `0003_audit_signatures.py` mirroring `0002_approvals.py` (down_revision = 0002's revision):
  `op.add_column("audit_record", sa.Column("signature", sa.Text(), nullable=True))` +
  `signing_key_id` `sa.String(64)`; downgrade drops both.
- [ ] Green. Commit `feat(controlplane): audit_record signature + signing_key_id columns (AUD-08)`.

### Task 3: `AuditWriter` signs records
**Files:** `audit.py`; tests.

- [ ] **Failing tests:**
```python
from agentos_controlplane.audit import AuditWriter, canonical_json, SIG_DOMAIN, verify_record_signature
# build a signed writer: AuditWriter(session_factory, signer=engine); append an action;
# read the row; assert signature + signing_key_id set; verify_record_signature(engine.public_key_pem,
#   bytes.fromhex(row.signature), canonical_json(row.body)) is True.
# tamper: mutate one body field -> verify_record_signature(...) is False.
# domain separation: load_pem_public_key(pub).verify(sig, canonical_json(body)) WITHOUT SIG_DOMAIN
#   raises InvalidSignature (the prefix is load-bearing).
# append_event signed too (same assertions over an approval_resolved event body).
# no signer: AuditWriter(session_factory) -> row.signature is None and row.signing_key_id is None.
```
- [ ] **Implement** in `audit.py`:
```python
from typing import Protocol, runtime_checkable
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

SIG_DOMAIN = b"agentos-guard/audit-record/v1\x00"  # AUD-08 domain prefix (vs JWTs on the same key)

@runtime_checkable
class RecordSigner(Protocol):
    public_key_id: str
    def sign_record(self, data: bytes) -> bytes: ...

def verify_record_signature(public_key_pem, signature: bytes, canonical_body: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 sig over SIG_DOMAIN + canonical_body under
    `public_key_pem`. Shared by the writer's tests and the Slice-4b CI verifier."""
    pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
    try:
        load_pem_public_key(pem).verify(signature, SIG_DOMAIN + canonical_body)
        return True
    except InvalidSignature:
        return False
```
  `AuditWriter.__init__(self, session_factory, *, signer: RecordSigner | None = None)` → store
  `self._signer`. Add a helper:
```python
    def _sign(self, canonical: bytes) -> tuple[str | None, str | None]:
        if self._signer is None:
            return None, None
        return self._signer.sign_record(SIG_DOMAIN + canonical).hex(), self._signer.public_key_id
```
  In `append`: compute the canonical bytes ONCE and reuse for hash + signature:
```python
            canonical = canonical_json(body)
            record_hash = hashlib.sha256(canonical).hexdigest()
            signature, signing_key_id = self._sign(canonical)
            return self._insert(seq, prev_hash, record_hash, body, signature, signing_key_id)
```
  Same in `append_event` (compute `canonical = canonical_json(full_body)` once). Extend `_insert`
  to accept + persist `signature` + `signing_key_id` (advance the cached head exactly as now).
- [ ] **Pin `canonical_json`** — replace the "RFC-8785-ish" docstring with the exact definition:
```python
def canonical_json(obj: dict) -> bytes:
    """agentos-guard canonical JSON v1 — the EXACT bytes that are both hashed (record_hash)
    and signed (AUD-08). Defined precisely (NOT RFC-8785/JCS) as:
        json.dumps(obj, sort_keys=True, separators=(",", ":"))  # default ensure_ascii=True
    An independent verifier MUST import THIS function (do not reimplement). Bodies are restricted
    to JSON-native scalars + ASCII keys; float fields (risk/trust scores) use CPython's repr —
    reproducible by another CPython, with cross-language verification a documented later concern."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
```
- [ ] Green. Commit `feat(controlplane): AuditWriter signs each record over the domain-prefixed canonical body; pin canonical_json (AUD-08)`.

### Task 4: wire the signer into the e2e path + full gate
**Files:** `tests/conftest.py`; full suite.

- [ ] In `conftest._wire`, pass `signer=registry.identity` to the `AuditWriter(...)` construction so
  the main pipeline-test audit chain is genuinely signed (the realistic path the Slice-4b verifier
  will check). `registry.identity` is the `IdentityEngine`, which now satisfies `RecordSigner`.
- [ ] FULL gate: `pytest -q` green (existing audit tests unaffected — signature is additive/nullable;
  the e2e chains now carry signatures); `-m floor_invariant` 430; `-m regression_lock` 10;
  `-m latency` healthy (one Ed25519 sign per append ≈ tens of µs — confirm the budget holds).
- [ ] Commit `test(controlplane): sign the e2e audit chain end-to-end (AUD-08)`.

## Self-review
AUD-08: sign canonical body not digest / domain-prefixed (JWT non-replay) / private key stays in
the engine / columns out of `body` / single-record verify works + tamper detected / append AND
append_event signed / canonical_json pinned + verifier-shared / signer optional (backward compat) /
e2e path signed for 4b. Gates green; latency budget held.
