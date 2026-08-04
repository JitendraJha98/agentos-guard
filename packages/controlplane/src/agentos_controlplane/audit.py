"""Hash-chained audit writer with fail-closed redaction — AUD-01 / D-14 / D-15.

Source: 01-RESEARCH.md § Audit (the `append`/`canonical_json` code, the
serial-chain lock, Pitfall 8 monotonic-seq note) + Pitfall 3 (fail-closed
redaction); ADR-0004.

Chain shape (NOT cheaply retrofittable — get it right now):
- `seq` is strictly monotonic and is COVERED by `record_hash` (ordering derives
  from `seq`, never from wall-clock `created_at`; Pitfall 8).
- `prev_hash` links each record to the prior record's `record_hash`; NULL only
  for the genesis record.
- `record_hash = sha256(canonical_json(body)).hexdigest()` — canonical JSON
  (sorted keys, no whitespace) makes the hash reproducible.
- Redaction fails CLOSED (D-15): if a payload field cannot be classified, the
  writer RAISES and NO record is written. Never best-effort.

No-Docker deviation (D-14): the active Phase-1 backend is the SQLite Store.
Chain correctness is fully provable on SQLite for the single-process skeleton;
Postgres concurrency / advisory-lock serialization / the append-only trigger
are deferred to Phase 4 per the Deviation Log. In-process serialization here is
an `asyncio.Lock` (single writer) — the seam a Postgres advisory lock replaces.
"""

import asyncio
import hashlib
import json
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_contract import AgentAction, Decision
from agentos_controlplane.secret_scan import SecretLeakError, scan
from agentos_controlplane.store.models import AuditRecord

# AUD-08 domain prefix. The control-plane Ed25519 key ALSO signs agent JWTs;
# this fixed context byte-string makes an audit-record signature unusable as a
# JWT (and vice-versa). Prepended to canonical_json(body) before signing.
SIG_DOMAIN = b"agentos-guard/audit-record/v1\x00"


@runtime_checkable
class RecordSigner(Protocol):
    """The slice of IdentityEngine the writer needs to sign records (AUD-08).

    Structural: any object exposing a stable `public_key_id` and a `sign_record`
    over raw bytes satisfies it — the writer never touches the private key.
    """

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

# Payload keys the redactor knows how to classify. A key NOT classified here is
# unclassifiable -> fail closed (D-15). This is intentionally minimal; the
# Presidio-grade redactor is Phase 4.
#
# Phase 1 governed only tool_call ({url, content}). Phase 2 (INT-02..05) adds the
# four remaining action types, each with a small fixed payload shape:
#   model_invocation : {"model", "messages"}
#   memory_access    : {"operation", "key", "value"}
#   mcp_call         : {"server", "tool", "args"}
#   delegation       : {"to_agent", "task"}
# Free-text / secret-bearing fields are reduced to a length+SHA-256 digest (never
# persisted raw); short identifier fields are safe to keep verbatim for forensics.
_DIGEST_KEYS = frozenset({"content", "messages", "value", "args", "task"})
_VERBATIM_KEYS = frozenset(
    {"model", "operation", "key", "server", "tool", "to_agent", "from_agent"}
)
# `url` is special-cased (host-only redaction). The full set of classifiable keys:
_KNOWN_PAYLOAD_KEYS = frozenset({"url"}) | _DIGEST_KEYS | _VERBATIM_KEYS


class RedactionError(Exception):
    """Raised when a payload field cannot be classified — fail closed (D-15).

    The caller MUST NOT write a record when this is raised.
    """


# Lifecycle event kinds (Slice 6): every approval / exception / review /
# enforcement lifecycle event is an AuditRecord through the SAME hash chain.
# Allowlisted so a typo'd or invented kind can never enter the chain.
EVENT_KINDS = frozenset(
    {
        "approval_resolved",
        "approval_timed_out",
        "exception_granted",
        "review_opened",
        "enforcement_substitution",
        "side_effect",
        # RUN-01/02 (Slice 4e): operator kill-switch toggles. The event body carries
        # short identifiers only (target/scope/set_by) — the free-text reason lives in
        # the kill_switch TABLE, so the 4d secret-gate here can never block a kill.
        "kill_switch_set",
        "kill_switch_cleared",
        # RUN-03 (Slice 9a): a quarantined sandbox run. Short identifiers only — the
        # redacted detail lives in the sandbox_run TABLE, so the 4d secret-gate here
        # can never block containment.
        "sandbox_executed",
        # RUN-04 (Slice 9b): an administrative privilege-ring assignment (agent tier or target
        # requirement). Short identifiers only; the per-action deny is audited as a DECISION record.
        "privilege_ring_set",
        # RUN-05 (Slice 9c): the administrative budget assignment, and a per-execution budget
        # breach. Short identifiers + numbers only — no target, no payload — so the 4d secret-gate
        # here can never block a breach from being recorded.
        "resource_limit_set",
        "resource_limit_exceeded",
    }
)

# Chain fields the writer computes itself — an event body may never shadow them.
_RESERVED_EVENT_KEYS = frozenset({"seq", "prev_hash", "kind"})


def canonical_json(obj: dict) -> bytes:
    """agentos-guard canonical JSON v1 — the EXACT bytes that are both hashed (record_hash)
    and signed (AUD-08). Defined precisely (NOT RFC-8785/JCS) as:
        json.dumps(obj, sort_keys=True, separators=(",", ":"))  # default ensure_ascii=True
    An independent verifier MUST import THIS function (do not reimplement). Bodies are restricted
    to JSON-native scalars + ASCII keys; float fields (risk/trust scores) use CPython's repr —
    reproducible by another CPython, with cross-language verification a documented later concern."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _redact_url(url: str) -> str:
    """Reduce a URL to scheme+host(+port) only — drops path/query (where secrets hide).

    Keeps the host for forensic value; never persists the query string or path.
    Rebuilds the host from `parts.hostname` (lowercased, NO userinfo) rather than
    `parts.netloc`, which retains the `user:password@` segment and would leak
    embedded credentials into the hash-covered body (D-15 fail-closed redaction).
    """
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise RedactionError(f"unclassifiable url field: {parts.scheme or '<no-scheme>'}")
    host = parts.hostname  # lowercased, NO userinfo, NO password
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}"


def _redact_content(content: object) -> dict:
    """Never persist raw content — store length + SHA-256 digest only.

    Digest keys accept ANY JSON-serializable value (PIPE-05 seed): a non-str
    value is digested over its canonical JSON bytes. A value canonical_json
    cannot serialize raises RedactionError — fail closed, never best-effort.
    """
    if isinstance(content, str):
        raw = content.encode("utf-8")
    else:
        try:
            raw = canonical_json(content)
        except TypeError:
            raise RedactionError(
                f"undigestable payload value of type {type(content).__name__}"
            ) from None
    return {"len": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _redact_or_raise(payload: dict) -> dict:
    """Classify + redact every payload field; raise on any unknown field (D-15)."""
    redacted: dict = {}
    for key, value in payload.items():
        if key not in _KNOWN_PAYLOAD_KEYS:
            raise RedactionError(f"unclassifiable payload field: {key!r}")
        if key == "url":
            if not isinstance(value, str):
                raise RedactionError("payload field 'url' is not a string")
            redacted["url"] = _redact_url(value)
        elif key in _DIGEST_KEYS:
            redacted[key] = _redact_content(value)
        else:  # _VERBATIM_KEYS — short string identifiers, safe to keep
            if not isinstance(value, str):
                raise RedactionError(f"payload field {key!r} is not a string")
            redacted[key] = value
    return redacted


class AuditWriter:
    """Append-only, hash-chained writer over a (SQLite-backed) Store.

    Phase-1 backend is SQLite (D-14). The writer only ever INSERTs — append-only
    is enforced at the application layer (no UPDATE/DELETE path); the Postgres
    DB-level trigger is the production-target second line of defense.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signer: RecordSigner | None = None,
    ) -> None:
        self.session_factory = session_factory
        # AUD-08: optional record signer (the control-plane IdentityEngine). None
        # -> unsigned records (backward compat); the production path always wires one.
        self._signer = signer
        self._lock = asyncio.Lock()  # serial chain: single in-process writer
        # PIPE-04 hot-path lever (Slice 6c): the chain head is cached INSIDE the
        # writer-lock discipline, so steady-state appends are one INSERT, not
        # SELECT+INSERT. Safe under the same single-writer assumption the lock
        # already encodes (D-14); a failed insert rolls back without touching
        # the cache, so the prior head stays correct. (prev record_hash, next seq)
        self._head: tuple[str | None, int] | None = None

    async def append(self, action: AgentAction, decision: Decision) -> UUID:
        """Append one AuditRecord; return its id (the Decision.evidence_ref)."""
        # 1. Redact FIRST and fail closed — if this raises, no record is written.
        redacted = _redact_or_raise(action.payload)

        # 2. Serialize the chain head -> body -> hash -> append-only INSERT.
        async with self._lock:
            prev_hash, seq = self._chain_head()
            body = {
                "seq": seq,
                "prev_hash": prev_hash,
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "action_type": action.type.value,
                # Lineage (INT-05): persist the delegation/conversation edges so the
                # Phase-12 evidence graph (AUD-09) can reconstruct causal chains. These
                # are ids, not payload, so they need no redaction.
                "parent_action_id": (
                    str(action.context.parent_action_id)
                    if action.context.parent_action_id
                    else None
                ),
                "conversation_id": action.context.conversation_id,
                "outcome": decision.outcome.value,
                "risk_score": decision.risk_score,
                "trust_score": decision.trust_score,
                # mode="json" keeps every reason field JSON-native for canonical_json
                # (belt-and-braces atop the contract's JSON-native evidence validator).
                "reasons": [r.model_dump(mode="json") for r in decision.reasons],
                "redacted_payload": redacted,
                # Phase-3 Slice-1 Decision fields — all bounded/typed at the contract,
                # so the hash covers the COMPLETE decision (no un-audited field).
                "side_effects": [s.value for s in decision.side_effects],
                "inferred_intent": decision.inferred_intent,
                "remediation": decision.remediation,
                "constitution_version": decision.constitution_version,
                "policy_version": decision.policy_version,
                "expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
            }
            # Compute the canonical bytes ONCE — the SAME bytes feed the hash AND
            # the signature (AUD-08), so a verifier reproduces both from `body`.
            canonical = canonical_json(body)
            # AUD-04 last gate: content-based secret scan over the fully-assembled,
            # already-redacted body bytes (defense-in-depth beneath the classifier).
            # A hit fails CLOSED before any write — the head is not advanced.
            leaks = scan(canonical.decode("utf-8"))
            if leaks:
                raise SecretLeakError(f"secret-like content in audit body: {sorted(set(leaks))}")
            record_hash = hashlib.sha256(canonical).hexdigest()
            signature, signing_key_id = self._sign(canonical)
            return self._insert(seq, prev_hash, record_hash, body, signature, signing_key_id)

    async def append_event(self, kind: str, body: dict) -> UUID:
        """Append one lifecycle EVENT record through the SAME hash chain.

        Shares the lock / seq / prev_hash discipline with action records, so
        events and decisions interleave on one tamper-evident chain. `body` is
        ids / enums / short strings only — constructed by the control plane,
        never attacker payload (the redactor is for action payloads). The hash
        covers {seq, prev_hash, kind, ...body}, so the kind itself is
        tamper-evident. Unknown kinds raise and write NOTHING.
        """
        if kind not in EVENT_KINDS:
            raise ValueError(f"unknown audit event kind: {kind!r}")
        # A body key shadowing the chain fields would overwrite exactly what the
        # hash must cover — reject fail-closed, write NOTHING.
        shadowed = _RESERVED_EVENT_KEYS & body.keys()
        if shadowed:
            raise ValueError(f"audit event body shadows reserved keys: {sorted(shadowed)}")
        async with self._lock:
            prev_hash, seq = self._chain_head()
            full_body = {"seq": seq, "prev_hash": prev_hash, "kind": kind, **body}
            canonical = canonical_json(full_body)
            # AUD-04 last gate — same fail-closed scan as `append` (gate BOTH paths).
            leaks = scan(canonical.decode("utf-8"))
            if leaks:
                raise SecretLeakError(f"secret-like content in audit body: {sorted(set(leaks))}")
            record_hash = hashlib.sha256(canonical).hexdigest()
            signature, signing_key_id = self._sign(canonical)
            return self._insert(seq, prev_hash, record_hash, full_body, signature, signing_key_id)

    def _sign(self, canonical: bytes) -> tuple[str | None, str | None]:
        """Detached EdDSA signature over SIG_DOMAIN + the canonical body bytes (AUD-08).

        Returns (hex signature, signing_key_id) or (None, None) when unsigned.
        Signing the BODY bytes (not the record_hash digest) keeps Ed25519's
        built-in collision resistance (RFC 8032 §8.7); the body already covers
        seq + prev_hash, so authorship binds to the full chain-linked content.
        """
        if self._signer is None:
            return None, None
        return self._signer.sign_record(SIG_DOMAIN + canonical).hex(), self._signer.public_key_id

    def _chain_head(self) -> tuple[str | None, int]:
        """Return (prior record_hash, next monotonic seq) — cached after the
        first lookup; only ever read/written under `self._lock`.

        ONE AuditWriter instance per store: the cache assumes this writer is
        the store's only appender. A second instance over the same store gets
        a stale head, but cannot fork the chain silently — its INSERT collides
        with the UNIQUE `seq` constraint and raises IntegrityError (fail
        closed; the colliding record is never written)."""
        if self._head is not None:
            return self._head
        with self.session_factory() as session:
            last = session.scalars(
                select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)
            ).first()
            if last is None:
                return None, 0  # genesis: prev_hash NULL, seq 0
            return last.record_hash, last.seq + 1

    def _insert(
        self,
        seq: int,
        prev_hash: str | None,
        record_hash: str,
        body: dict,
        signature: str | None,
        signing_key_id: str | None,
    ) -> UUID:
        record_id = uuid4()
        with self.session_factory() as session:
            session.add(
                AuditRecord(
                    id=record_id,
                    seq=seq,
                    prev_hash=prev_hash,
                    record_hash=record_hash,
                    body=body,
                    signature=signature,
                    signing_key_id=signing_key_id,
                )
            )
            session.commit()
        # Advance the cached head only AFTER the commit succeeded (a failed
        # insert raises above, leaving the prior head correct).
        self._head = (record_hash, seq + 1)
        return record_id
