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
import hmac
import json
import os
from typing import Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from sqlalchemy import select, text
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
# Phase 17: `text` (typed into a UI), `element` (a UI target description, which can quote what is
# on the page) and `code` are free text -> digested; `language` is a short identifier.
_DIGEST_KEYS = frozenset({"content", "messages", "value", "args", "task", "text", "element", "code"})
_VERBATIM_KEYS = frozenset(
    {"model", "operation", "key", "server", "tool", "to_agent", "from_agent", "language"}
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
        # RUN-06 (Slice 9d): automatic breaker transitions. Short identifiers + counts only.
        "circuit_tripped",
        "circuit_reset",
        # RUN-07 (Slice 9e): fleet-wide emergency stop + explicit resume. Short identifiers + the
        # incident id only — the free-text justification stays in the emergency_shutdown TABLE.
        "emergency_shutdown",
        "emergency_resume",
        # POL-09 (Slice 9f): per-voter verdicts + the round resolution. Short identifiers +
        # counts only — voter rationale (if any) stays in the consensus_vote TABLE, so the
        # 4d secret-gate here can never block a consensus round from being recorded.
        "consensus_vote",
        "consensus_resolved",
        # DISC-03 (Slice 10c): a framework observed in this deployment. Short identifiers only.
        "framework_discovered",
        # DISC-04 (Slice 10d): an unregistered actor was seen acting. The claimed id is
        # attacker-controlled, so the body carries a BOUNDED, sanitized identifier + a digest —
        # never the raw string, which could otherwise trip the AUD-04 gate and block the record.
        "shadow_agent_detected",
        # DISC-05 (Slice 10e): a REGISTERED agent used a component it never declared. Short
        # identifiers only. ADVISORY — an observation, not a decision: the control plane surfaces
        # the divergence and an operator decides, because a manifest can simply be stale.
        "rogue_agent_detected",
        # AUD-06 (Slice 11a): an epoch was sealed under a Merkle root. Short identifiers + the
        # root digest only — never record bodies.
        "merkle_epoch_sealed",
        # ECON-01 (Slice 11b): what an action cost. Short identifiers + numbers only — never the
        # prompt that produced the tokens.
        "cost_recorded",
        # CMP-04 (Slice 11e): an operator declared (or withdrew) an EU AI Act risk classification.
        # Short identifiers only. The column holds the CURRENT value; this is the only record that
        # it ever said something else, who said so, and when — which is what a regulator asks.
        "risk_classification_declared",
        # TEST-07 (Slice 12a): a red-team suite was run against an agent's decision path. Short
        # identifiers and counts only — never an attack payload.
        "validation_run",
        # POL-12 (Slice 13c): the Byzantine quorum certificate, and a voter caught equivocating.
        # Counts and identifiers only — the signed votes live in the certificate.
        "quorum_certified",
        "voter_equivocated",
        # POL-10 (Slice 13a): the Constitution's own change log. Short identifiers only — the
        # proposed text lives in the amendment row, not in the chain.
        "amendment_proposed",
        "amendment_resolved",
        # AUTH-01 (Phase 16): who may act on the control plane is itself governed state. Name,
        # role and the acting principal only — never the token.
        "principal_created",
        "principal_revoked",
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


def _redact_content(content: object, key: bytes | None = None) -> dict:
    """Never persist raw content — store length + a digest only.

    With a deployment `key` (RED-01, Phase 16) the digest is HMAC-SHA256: an UNKEYED digest of a
    low-entropy value (an SSN has 10^9 candidates) is reversed by brute force in seconds, so the
    "redacted" value was recoverable from the audit log. `key_id` names the key, never reveals it.
    Without a key the legacy `sha256` form is kept, so existing deployments read the same.

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
    if key is not None:
        return {
            "len": len(raw),
            "hmac_sha256": hmac.new(key, raw, hashlib.sha256).hexdigest(),
            "key_id": digest_key_id(key),
        }
    return {"len": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def digest_key_id(key: bytes) -> str:
    """A stable, non-reversible name for a digest key (domain-separated from any other use)."""
    return hashlib.sha256(b"agentos-guard/digest-key-id/v1\x00" + key).hexdigest()[:16]


_MIN_DIGEST_KEY = 32


def resolve_digest_key(explicit: bytes | str | None = None) -> bytes | None:
    """explicit -> AGENTOS_AUDIT_DIGEST_KEY -> None (legacy unkeyed digests). A key shorter than
    32 bytes is refused at startup: a guessable key is the brute-force problem again."""
    key = explicit if explicit is not None else os.environ.get("AGENTOS_AUDIT_DIGEST_KEY")
    if key is None or key == "":
        return None
    key = key.encode("utf-8") if isinstance(key, str) else key
    if len(key) < _MIN_DIGEST_KEY:
        raise ValueError(f"audit digest key must be at least {_MIN_DIGEST_KEY} bytes")
    return key


def _redact_or_raise(payload: dict, digest_key: bytes | None = None) -> dict:
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
            redacted[key] = _redact_content(value, key=digest_key)
        else:  # _VERBATIM_KEYS — short string identifiers, safe to keep
            if not isinstance(value, str):
                raise RedactionError(f"payload field {key!r} is not a string")
            redacted[key] = value
    return redacted


# Every control-plane instance appending to one Postgres store takes THIS advisory lock, so appends
# serialize across processes, not only across coroutines. Any fixed 64-bit key works; it only has
# to be the same everywhere ("agentos1" in ASCII).
CHAIN_LOCK_KEY = 0x6167656E746F7331


class AuditWriter:
    """Append-only, hash-chained writer over the Store.

    The writer only ever INSERTs — append-only is enforced at the application layer (no
    UPDATE/DELETE path) and by the DB trigger from migration 0001 as the second line of defense.

    Two serialization modes, chosen from the engine's dialect:

    - SQLite (single process by nature): an `asyncio.Lock` plus a cached chain head, so a
      steady-state append is one INSERT (the PIPE-04 lever from Slice 6c).
    - Postgres (Phase 15 — any number of control-plane instances on one store): each append is one
      transaction that takes `pg_advisory_xact_lock(CHAIN_LOCK_KEY)`, re-reads the head INSIDE the
      lock, then inserts. No head is cached, because another instance may have advanced it. The
      lock is released by the commit or the rollback, so a writer that dies mid-append cannot
      wedge the chain.

    In both modes the UNIQUE `seq` constraint is the backstop: a writer that somehow bypassed the
    lock collides and raises instead of forking the chain.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signer: RecordSigner | None = None,
        digest_key: bytes | str | None = None,
    ) -> None:
        self.session_factory = session_factory
        # RED-01: keyed payload digests (explicit -> AGENTOS_AUDIT_DIGEST_KEY -> legacy unkeyed).
        self.digest_key = resolve_digest_key(digest_key)
        # AUD-08: optional record signer (the control-plane IdentityEngine). None
        # -> unsigned records (backward compat); the production path always wires one.
        self._signer = signer
        self._lock = asyncio.Lock()  # in-process serialization (both modes)
        # SQLite-mode head cache: (prev record_hash, next seq). A failed insert rolls back
        # without touching it, so the prior head stays correct.
        self._head: tuple[str | None, int] | None = None
        bind = session_factory.kw.get("bind")
        self._shared = bind is not None and bind.dialect.name == "postgresql"

    async def append(self, action: AgentAction, decision: Decision) -> UUID:
        """Append one AuditRecord; return its id (the Decision.evidence_ref)."""
        # 1. Redact FIRST and fail closed — if this raises, no record is written.
        redacted = _redact_or_raise(action.payload, self.digest_key)
        fields = {
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
        # 2. Serialize the chain head -> body -> hash -> append-only INSERT.
        async with self._lock:
            return self._append_chained(fields)

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
            return self._append_chained({"kind": kind, **body})

    def _append_chained(self, fields: dict) -> UUID:
        """Link `fields` onto the chain and insert it. Caller holds `self._lock`."""
        if self._shared:
            return self._append_shared(fields)
        prev_hash, seq = self._chain_head()
        body, record_hash, signature, signing_key_id = self._seal(seq, prev_hash, fields)
        return self._insert(seq, prev_hash, record_hash, body, signature, signing_key_id)

    def _seal(
        self, seq: int, prev_hash: str | None, fields: dict
    ) -> tuple[dict, str, str | None, str | None]:
        """Build the chained body and its hash + signature, or raise before anything is written."""
        body = {"seq": seq, "prev_hash": prev_hash, **fields}
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
        return body, record_hash, signature, signing_key_id

    def _append_shared(self, fields: dict) -> UUID:
        """Postgres mode: lock, read the head, seal and insert — all in ONE transaction."""
        record_id = uuid4()
        with self.session_factory() as session:
            # READ COMMITTED is load-bearing: each statement takes a fresh snapshot, so the head
            # read AFTER the lock sees the previous holder's commit. Under REPEATABLE READ the
            # snapshot could predate the wait and the insert would collide on `seq`.
            session.connection(execution_options={"isolation_level": "READ COMMITTED"})
            session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": CHAIN_LOCK_KEY})
            last = session.execute(
                select(AuditRecord.record_hash, AuditRecord.seq)
                .order_by(AuditRecord.seq.desc())
                .limit(1)
            ).first()
            prev_hash, seq = (last.record_hash, last.seq + 1) if last else (None, 0)
            body, record_hash, signature, signing_key_id = self._seal(seq, prev_hash, fields)
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
            session.commit()  # releases the advisory lock; any raise above rolls back and releases
        return record_id

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
