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

from typing import Protocol, runtime_checkable

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.audit import canonical_json
from agentos_controlplane.store.models import AuditRecord, ChainCheckpoint

CHECKPOINT_DOMAIN = b"agentos-guard/audit-checkpoint/v1\x00"

# Which anchor kinds carry an authority the operator does NOT control.
#
# `anchor_kind` is a bare enum, and an artifact that leaves the building is read by someone who has
# never seen this module: to them `local_ed25519_v1` and `rfc3161_v1` are two opaque strings that
# both make `anchored` true. Only one of them means a third party vouched for the root. Naming the
# difference in words — and counting on the SET rather than on the string — is what stops a
# durability signature from being read as independent attestation.
EXTERNAL_AUTHORITY_KINDS = frozenset({"rfc3161_v1"})

_ANCHOR_AUTHORITY = {
    "local_ed25519_v1": (
        "the control plane's OWN key, over its own root — durability and proof of mechanism, NOT "
        "independent attestation: this is the same key that signs the audit records, so whoever "
        "could fabricate the records could fabricate this anchor"
    ),
    "rfc3161_v1": (
        "an RFC-3161 timestamp authority outside the operator, whose signing key the operator does "
        "not hold — worth what verifying the token against that authority's root certificate proves"
    ),
}


def anchor_authority(kind: str | None) -> str | None:
    """WHO vouches for a root anchored with `kind`, in a sentence rather than as an enum.

    An unrecognised kind is named as unrecognised rather than dropped to None: `anchor_kind` is
    attacker-writable, and a kind nothing can verify must not read the same as no anchor at all.
    """
    if kind is None:
        return None
    return _ANCHOR_AUTHORITY.get(
        kind,
        f"unrecognised anchor kind {kind!r} — nothing here can verify it, so nothing vouches for "
        "this root",
    )


class CheckpointVerifyUnavailable(RuntimeError):
    """The verification material for a checkpoint kind was not supplied (skip, not a violation)."""


def checkpoint_message(seq: int, record_hash: str) -> bytes:
    """The exact bytes anchored for the head at `seq`. Reuses the pinned canonical_json so a
    verifier reproduces them byte-identically."""
    return canonical_json({"seq": seq, "record_hash": record_hash})


@runtime_checkable
class CheckpointAnchor(Protocol):
    kind: str

    def anchor(self, message: bytes) -> bytes: ...  # returns opaque proof bytes for this kind


class LocalEd25519Anchor:
    """Durability-only anchor (NOT external authority): signs the checkpoint message with the
    control-plane key. Proves the verifier's checkpoint mechanism + powers offline tests."""

    kind = "local_ed25519_v1"

    def __init__(self, signer) -> None:  # signer = IdentityEngine (sign_record + public_key_id)
        self._signer = signer

    def anchor(self, message: bytes) -> bytes:
        return self._signer.sign_record(CHECKPOINT_DOMAIN + message)


def verify_checkpoint_proof(
    kind, proof: bytes, message: bytes, *, public_key_pem=None, tsa_root_pem=None
) -> bool:
    """Dispatch proof verification by anchor kind. Returns False on invalid; raises
    CheckpointVerifyUnavailable if the material needed for `kind` was not supplied (so the
    verifier can surface a skip rather than a false pass or a crash)."""
    if kind == "local_ed25519_v1":
        if public_key_pem is None:
            raise CheckpointVerifyUnavailable(
                "local_ed25519_v1 checkpoint needs the control-plane public key"
            )
        # the local anchor signs CHECKPOINT_DOMAIN + message, NOT the audit SIG_DOMAIN; verify the
        # raw Ed25519 over that exact preimage:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.serialization import load_pem_public_key

        pem = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        try:
            load_pem_public_key(pem).verify(proof, CHECKPOINT_DOMAIN + message)
            return True
        except InvalidSignature:
            return False
    if kind == "rfc3161_v1":
        if tsa_root_pem is None:
            raise CheckpointVerifyUnavailable(
                "rfc3161_v1 checkpoint needs the TSA root certificate"
            )
        return _verify_rfc3161(proof, message, tsa_root_pem)
    raise CheckpointVerifyUnavailable(f"unknown checkpoint kind {kind!r}")


class Rfc3161Anchor:
    """External-authority anchor: RFC-3161 trusted timestamp of the checkpoint message.

    The TSA is a notary, not a blockchain — it signs {our message digest, its trusted time} with
    a key the in-house operator does NOT hold, so a rewrite of checkpointed history cannot be
    re-anchored. The POST uses the already-present httpx; the token (DER TimeStampResp) is stored
    and later verified OFFLINE (the library does no network I/O on the verify path)."""

    kind = "rfc3161_v1"

    def __init__(
        self, *, tsa_url: str = "http://timestamp.digicert.com", timeout: float = 15.0
    ) -> None:
        self.tsa_url, self._timeout = tsa_url, timeout

    def anchor(self, message: bytes) -> bytes:
        import httpx
        from rfc3161_client import (
            HashAlgorithm,
            TimestampRequestBuilder,
            decode_timestamp_response,
        )

        # DEVIATION (rfc3161-client 1.0.6): hash_algorithm() takes the library's own
        # HashAlgorithm.SHA256 enum, NOT cryptography's hashes.SHA256() instance (which raises
        # TypeError on this version). .data() still hashes its input internally, so the
        # messageImprint is sha256(message) and verification mirrors it with sha256(message).
        req = (
            TimestampRequestBuilder().data(message).hash_algorithm(HashAlgorithm.SHA256).build()
        )
        resp = httpx.post(
            self.tsa_url,
            content=req.as_bytes(),
            headers={"Content-Type": "application/timestamp-query"},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        decode_timestamp_response(resp.content)  # parse-validate shape; raises on a bad TSA reply
        return resp.content  # store the DER TimeStampResp


def _verify_rfc3161(proof: bytes, message: bytes, tsa_root_pem) -> bool:
    import hashlib

    from cryptography import x509
    from rfc3161_client import VerifierBuilder, VerificationError, decode_timestamp_response

    pem = tsa_root_pem.encode() if isinstance(tsa_root_pem, str) else tsa_root_pem
    root = x509.load_pem_x509_certificate(pem)
    verifier = VerifierBuilder().add_root_certificate(root).build()
    # A DB attacker (or genuine corruption) can replace the stored DER token with garbage/truncated
    # bytes; decode_timestamp_response raises ValueError ('ASN.1 parse error') there — NOT a
    # VerificationError — so decode INSIDE the try and turn a malformed token into the defined
    # 'checkpoint_proof' violation (never a crash), mirroring the 4b malformed-hex signature fix.
    try:
        # .anchor() hashes `message` internally (messageImprint == sha256(message)); mirror it.
        verifier.verify(decode_timestamp_response(proof), hashlib.sha256(message).digest())
        return True
    except (VerificationError, ValueError):
        return False


class CheckpointService:
    """Reads the current chain head, anchors it, and stores the checkpoint row.

    Operator-/schedule-driven (NOT wired into the per-action hot path; Phase-5 reconcilers
    automate the cadence)."""

    def __init__(self, session_factory: sessionmaker[Session], anchor: CheckpointAnchor) -> None:
        self._sf = session_factory
        self._anchor = anchor

    def checkpoint(self) -> ChainCheckpoint:
        """Anchor the current chain head and persist the checkpoint. Raises if the chain is empty."""
        with self._sf() as s:
            head = s.scalars(
                select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)
            ).first()
        if head is None:
            raise ValueError("cannot checkpoint an empty audit chain")
        msg = checkpoint_message(head.seq, head.record_hash)
        proof = self._anchor.anchor(msg)
        row = ChainCheckpoint(
            seq=head.seq,
            record_hash=head.record_hash,
            anchor_kind=self._anchor.kind,
            proof=proof,
            tsa_url=getattr(self._anchor, "tsa_url", None),
        )
        with self._sf() as s:
            s.add(row)
            s.commit()
            s.refresh(row)
        return row
