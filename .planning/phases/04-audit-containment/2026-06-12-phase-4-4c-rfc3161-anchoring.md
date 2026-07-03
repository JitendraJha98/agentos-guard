# Phase 4 · Slice 4c — External Anchoring (RFC-3161 Checkpoints) — Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end with a second
> `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task. Gates `floor_invariant` (430) +
> `regression_lock` (10) green at every commit.

**Goal (AUD-05 anchoring):** Periodically anchor the audit chain HEAD to an external trust domain
the in-house operator cannot forge — **RFC-3161 trusted timestamping** (token-free; a TSA is a
notary, not a blockchain — ADR-0007-clean). A checkpoint binds `{seq, record_hash}` to a TSA-signed
time; the CI verifier (4b) then proves no already-checkpointed history was rewritten.

**Verified tech (research, 2026-06-12, high confidence):**
- Library **`rfc3161-client>=1.0.3`** (Trail of Bits / Sigstore) — Windows wheels, no compiler, does
  request-build AND full offline verify; `cryptography>=43` (we have `>=48`). `rfc3161ng` rejected
  (unmaintained, sha1 default).
- **Caveat:** `TimestampRequestBuilder().data(b)` hashes `b` internally (no precomputed-digest
  setter). So we anchor `checkpoint_message(seq, record_hash)` bytes and the messageImprint becomes
  `sha256(checkpoint_message)`. Verify mirrors it: `verifier.verify(ts_response, sha256(msg).digest())`.
- **Offline verification is real** — the lib does no network I/O; verify chains the token's embedded
  leaf cert to a supplied ROOT and checks the imprint locally. So the mechanism + verifier tests are
  fully offline via a stub anchor; only obtaining a live TSA token needs network.
- TSA POST via the already-present **`httpx`** (no new `requests` dep). Free TSAs: DigiCert
  `http://timestamp.digicert.com`, freetsa.org.

**Honest threat model (document in checkpoint.py + the overview):** RFC-3161 checkpoints + the
verifier catch an insider with DB write access who **rewrites already-checkpointed history** (the
rewritten head won't match the TSA-signed token, which they can't forge). They do NOT prove
completeness/forward-forgery (→ Phase-11 Merkle/witness, AUD-06), defeat split-view (→ witness
quorum), or survive live key/process compromise. `LocalEd25519Anchor` is durability-only (same key
as the chain — proves the MECHANISM and powers deterministic tests; NOT external authority).

## File structure
- Create `packages/controlplane/src/agentos_controlplane/checkpoint.py` — `CHECKPOINT_DOMAIN`,
  `checkpoint_message`, `CheckpointAnchor` Protocol, `LocalEd25519Anchor`, `Rfc3161Anchor`,
  `verify_checkpoint_proof`, `CheckpointService`.
- Modify `store/models.py` — `ChainCheckpoint` table; migration `0004_chain_checkpoint.py`.
- Modify `audit_verify.py` — checkpoint validation + truncation detection in `verify_chain`; CLI
  `--tsa-root`.
- Modify root `pyproject.toml` — `rfc3161-client>=1.0.3`; `uv sync`.
- Tests: `tests/unit/test_checkpoint.py`, `tests/unit/test_audit_verify_checkpoints.py`,
  `tests/integration/test_rfc3161_live.py`.

---

### Task 1: checkpoint primitives + LocalEd25519Anchor + model + migration
**Files:** create `checkpoint.py`; modify `store/models.py`; create migration `0004`; test
`tests/unit/test_checkpoint.py`.

- [ ] **`checkpoint.py`** (core, offline):
```python
"""AUD-05 external anchoring — periodic RFC-3161 timestamping of the audit chain head.

A checkpoint binds {seq, record_hash} (the chain head at a point in time) to an external,
unforgeable proof. The CI verifier (audit_verify) then proves that already-checkpointed history
was not retroactively rewritten: a rewrite changes the recomputed head hash, which no longer
matches the checkpoint's bound record_hash — and an insider with DB write access cannot forge a
new RFC-3161 token (no access to the TSA's key).

Threat model (honest): catches AFTER-THE-FACT rewrites of checkpointed history. Does NOT prove
completeness/forward-forgery (Phase-11 Merkle/witness, AUD-06), defeat split-view (witness quorum),
or survive live key/process compromise. LocalEd25519Anchor is DURABILITY-ONLY (same control-plane
key as the chain) — it powers the deterministic offline tests and proves the mechanism, but is NOT
external authority; Rfc3161Anchor is.
"""
from __future__ import annotations
import hashlib
from typing import Protocol, runtime_checkable
from agentos_controlplane.audit import canonical_json

CHECKPOINT_DOMAIN = b"agentos-guard/audit-checkpoint/v1\x00"

def checkpoint_message(seq: int, record_hash: str) -> bytes:
    """The exact bytes anchored for the head at `seq`. Reuses the pinned canonical_json so a
    verifier reproduces them byte-identically."""
    return canonical_json({"seq": seq, "record_hash": record_hash})

@runtime_checkable
class CheckpointAnchor(Protocol):
    kind: str
    def anchor(self, message: bytes) -> bytes: ...   # returns opaque proof bytes for this kind

class LocalEd25519Anchor:
    """Durability-only anchor (NOT external authority): signs the checkpoint message with the
    control-plane key. Proves the verifier's checkpoint mechanism + powers offline tests."""
    kind = "local_ed25519_v1"
    def __init__(self, signer) -> None:  # signer = IdentityEngine (sign_record + public_key_id)
        self._signer = signer
    def anchor(self, message: bytes) -> bytes:
        return self._signer.sign_record(CHECKPOINT_DOMAIN + message)

def verify_checkpoint_proof(kind, proof: bytes, message: bytes, *, public_key_pem=None, tsa_root_pem=None) -> bool:
    """Dispatch proof verification by anchor kind. Returns False on invalid; raises
    CheckpointVerifyUnavailable if the material needed for `kind` was not supplied (so the
    verifier can surface a skip rather than a false pass or a crash)."""
    if kind == "local_ed25519_v1":
        if public_key_pem is None:
            raise CheckpointVerifyUnavailable("local_ed25519_v1 checkpoint needs the control-plane public key")
        from agentos_controlplane.audit import verify_record_signature  # reuse Ed25519 verify
        # the local anchor signs CHECKPOINT_DOMAIN + message, NOT the audit SIG_DOMAIN; verify the
        # raw Ed25519 over that exact preimage:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.exceptions import InvalidSignature
        pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        try:
            load_pem_public_key(pem).verify(proof, CHECKPOINT_DOMAIN + message)
            return True
        except InvalidSignature:
            return False
    if kind == "rfc3161_v1":
        if tsa_root_pem is None:
            raise CheckpointVerifyUnavailable("rfc3161_v1 checkpoint needs the TSA root certificate")
        return _verify_rfc3161(proof, message, tsa_root_pem)  # Task 4
    raise CheckpointVerifyUnavailable(f"unknown checkpoint kind {kind!r}")

class CheckpointVerifyUnavailable(RuntimeError):
    """The verification material for a checkpoint kind was not supplied (skip, not a violation)."""
```
  (Drop the unused `verify_record_signature`/`hashlib` imports if a reviewer flags them; the local
  verify uses raw Ed25519 over `CHECKPOINT_DOMAIN + message`. `_verify_rfc3161` is added in Task 4
  — until then `kind == "rfc3161_v1"` may reference a not-yet-defined function; define a stub that
  raises `CheckpointVerifyUnavailable("rfc3161 support not yet wired")` in Task 1 and replace it in
  Task 4, OR implement Task 4's `_verify_rfc3161` here. Keep Task 1 importable.)
- [ ] **`ChainCheckpoint` model** (`store/models.py`):
```python
class ChainCheckpoint(Base):
    """AUD-05 — an external anchor binding the chain head {seq, record_hash} to an unforgeable proof."""
    __tablename__ = "chain_checkpoint"
    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)          # the head seq anchored
    record_hash: Mapped[str] = mapped_column(Text, nullable=False)        # the head record_hash anchored
    anchor_kind: Mapped[str] = mapped_column(String(32), nullable=False)  # local_ed25519_v1 | rfc3161_v1
    proof: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)     # opaque per kind (sig | DER TimeStampResp)
    tsa_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
```
  (Add `LargeBinary` to the sqlalchemy import.) Migration `0004_chain_checkpoint.py` mirrors `0003`
  (down_revision = `0003`'s revision) creating the table; downgrade drops it.
- [ ] **Tests:** `LocalEd25519Anchor(engine).anchor(msg)` round-trips through `verify_checkpoint_proof("local_ed25519_v1", proof, msg, public_key_pem=engine.public_key_pem)` → True; tamper `message` → False; wrong domain (verify the raw sig over `message` WITHOUT the prefix) → False; missing pubkey → `CheckpointVerifyUnavailable`; `ChainCheckpoint` row round-trips on SQLite.
- [ ] Green. Commit `feat(controlplane): checkpoint primitives + LocalEd25519Anchor + chain_checkpoint table (AUD-05)`.

### Task 2: `CheckpointService.checkpoint()`
**Files:** `checkpoint.py`; tests.

- [ ] **Implement** `CheckpointService(session_factory, anchor)`:
```python
    def checkpoint(self) -> "ChainCheckpoint":
        """Read the current chain head, anchor it, and store the checkpoint row. Operator-/schedule-
        driven (Phase-5 reconcilers automate cadence). Raises if the chain is empty."""
        with self._sf() as s:
            head = s.scalars(select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)).first()
        if head is None:
            raise ValueError("cannot checkpoint an empty audit chain")
        msg = checkpoint_message(head.seq, head.record_hash)
        proof = self._anchor.anchor(msg)
        row = ChainCheckpoint(seq=head.seq, record_hash=head.record_hash,
                              anchor_kind=self._anchor.kind, proof=proof,
                              tsa_url=getattr(self._anchor, "tsa_url", None))
        with self._sf() as s:
            s.add(row); s.commit(); s.refresh(row)
        return row
```
- [ ] **Tests:** build a signed chain (3 records), `CheckpointService(sf, LocalEd25519Anchor(engine)).checkpoint()`
  → row has the head's seq + record_hash, kind local_ed25519_v1, proof verifies; empty chain → ValueError.
- [ ] Green. Commit `feat(controlplane): CheckpointService.checkpoint() anchors the chain head (AUD-05)`.

### Task 3: verifier validates checkpoints + truncation
**Files:** `audit_verify.py`; test `tests/unit/test_audit_verify_checkpoints.py`.

- [ ] **Extend `verify_chain(session_factory, public_key_pem=None, tsa_root_pem=None)`:** after the
  per-row loop (and capturing `max_seq` + a `{seq: recomputed_hash}` map, or re-deriving), load all
  `ChainCheckpoint` rows and for each:
  - if `checkpoint.seq > max_seq` → `Violation(checkpoint.seq, "checkpoint_truncation", "chain shorter than a checkpointed seq")` (tail-truncation defense).
  - recompute the head hash at `checkpoint.seq` from the verified chain; if `!= checkpoint.record_hash` → `Violation(... "checkpoint_mismatch" ...)` (rewrite-of-checkpointed-history defense).
  - `verify_checkpoint_proof(checkpoint.anchor_kind, checkpoint.proof, checkpoint_message(checkpoint.seq, checkpoint.record_hash), public_key_pem=..., tsa_root_pem=...)`:
    - returns False → `Violation(... "checkpoint_proof" ...)`;
    - raises `CheckpointVerifyUnavailable` → record a skip (do NOT fail, do NOT crash — like the unsigned-row skip), surfaced in the result (e.g. `VerifyResult.skipped_checkpoints` count or a note).
  Keep first-violation-wins. Reuse `canonical_json` + `checkpoint_message` (import from checkpoint.py).
- [ ] **Tests** (offline, LocalEd25519Anchor): clean chain + checkpoint → ok; rewrite a body + recompute
  ALL hashes consistently (internally valid chain) but leave the OLD checkpoint → `checkpoint_mismatch`;
  truncate the chain below a checkpointed seq → `checkpoint_truncation`; corrupt the checkpoint `proof`
  bytes → `checkpoint_proof`; checkpoint present but no pubkey supplied → result reports a skipped
  checkpoint, ok stays True (not a false fail). This is the proof that the checkpoint catches the
  "full consistent rewrite" that 4b alone could not.
- [ ] Green. Commit `feat(controlplane): verifier validates checkpoint anchors + detects truncation (AUD-05)`.

### Task 4: Rfc3161Anchor (real external authority) + dep + network-gated test
**Files:** `checkpoint.py` (`Rfc3161Anchor`, `_verify_rfc3161`); root `pyproject.toml`;
`tests/integration/test_rfc3161_live.py`.

- [ ] Add `rfc3161-client>=1.0.3` to root `[project].dependencies`; `uv sync`; verify import.
- [ ] **`Rfc3161Anchor`** (lazy imports; uses httpx for the POST):
```python
class Rfc3161Anchor:
    """External-authority anchor: RFC-3161 trusted timestamp of the checkpoint message."""
    kind = "rfc3161_v1"
    def __init__(self, *, tsa_url: str = "http://timestamp.digicert.com", timeout: float = 15.0) -> None:
        self.tsa_url, self._timeout = tsa_url, timeout
    def anchor(self, message: bytes) -> bytes:
        import httpx
        from rfc3161_client import TimestampRequestBuilder, decode_timestamp_response
        from cryptography.hazmat.primitives import hashes
        req = TimestampRequestBuilder().data(message).hash_algorithm(hashes.SHA256()).build()
        resp = httpx.post(self.tsa_url, content=req.as_bytes(),
                          headers={"Content-Type": "application/timestamp-query"}, timeout=self._timeout)
        resp.raise_for_status()
        decode_timestamp_response(resp.content)   # parse-validate shape; raises on a bad TSA reply
        return resp.content                        # store the DER TimeStampResp

def _verify_rfc3161(proof: bytes, message: bytes, tsa_root_pem) -> bool:
    import hashlib
    from cryptography import x509
    from rfc3161_client import decode_timestamp_response, VerifierBuilder, VerificationError
    pem = tsa_root_pem.encode() if isinstance(tsa_root_pem, str) else tsa_root_pem
    root = x509.load_pem_x509_certificate(pem)
    verifier = VerifierBuilder().add_root_certificate(root).build()
    try:
        verifier.verify(decode_timestamp_response(proof), hashlib.sha256(message).digest())
        return True
    except VerificationError:
        return False
```
- [ ] **Network-gated test** (`tests/integration/test_rfc3161_live.py`,
  `pytestmark = skipif(not os.environ.get("AGENTOS_RFC3161_LIVE"))` so it stays opt-in/offline by
  default): timestamp a sample message against the default TSA, then verify the returned token
  OFFLINE — fetch/pin the TSA root (try `certifi` roots via `VerifierBuilder` looping certifi, or a
  committed DigiCert root PEM) and assert `verify_checkpoint_proof("rfc3161_v1", token, message,
  tsa_root_pem=root)` is True, and a tampered message → False. Record+verify in ONE run (no
  long-term fixture — avoids the TSA-cert-expiry caveat). Skip cleanly on any network/cert error.
- [ ] Green (the live test SKIPS by default — verify it skips). Commit
  `feat(controlplane): Rfc3161Anchor + offline token verification + network-gated live test (AUD-05)`.

### Task 5: CLI + full gate
- [ ] `audit_verify` CLI gains `--tsa-root <pem>` (passed to `verify_chain`). The CLI already prints
  OK/FAIL; ensure a skipped checkpoint is reported (e.g. "OK: N records, M checkpoints verified, K skipped").
- [ ] FULL gate: `pytest -q` green (rfc3161 live test skips; offline checkpoint tests pass);
  `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy (checkpointing is
  operator-/schedule-driven, NOT on the per-action hot path — confirm nothing wired it into evaluate).
- [ ] Commit `feat(controlplane): audit_verify --tsa-root; checkpoint verification reporting (AUD-05)`.

## Self-review
AUD-05 anchoring: RFC-3161 external authority (insider can't forge) + LocalEd25519Anchor (mechanism/
offline tests, honestly durability-only) behind one Protocol / checkpoint binds {seq, record_hash}
via the pinned canonical_json / verifier catches checkpoint_mismatch (rewrite of checkpointed
history — the case 4b alone misses) + checkpoint_truncation + checkpoint_proof, skips cleanly when
verification material is absent / offline token verification real, live test network-gated &
default-skip / threat model documented honestly / checkpointing off the hot path. Gates green.
