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


def _verify_rfc3161(proof: bytes, message: bytes, tsa_root_pem) -> bool:
    # Replaced in Task 4 with the real offline RFC-3161 token verification.
    raise CheckpointVerifyUnavailable("rfc3161 support not yet wired")


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
