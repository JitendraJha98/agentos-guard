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
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_contract import AgentAction, Decision
from agentos_controlplane.store.models import AuditRecord

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
    }
)


def canonical_json(obj: dict) -> bytes:
    """Reproducible canonical JSON: sorted keys, no whitespace (RFC-8785-ish)."""
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

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory
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
            record_hash = hashlib.sha256(canonical_json(body)).hexdigest()
            return self._insert(seq, prev_hash, record_hash, body)

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
        async with self._lock:
            prev_hash, seq = self._chain_head()
            full_body = {"seq": seq, "prev_hash": prev_hash, "kind": kind, **body}
            record_hash = hashlib.sha256(canonical_json(full_body)).hexdigest()
            return self._insert(seq, prev_hash, record_hash, full_body)

    def _chain_head(self) -> tuple[str | None, int]:
        """Return (prior record_hash, next monotonic seq) — cached after the
        first lookup; only ever read/written under `self._lock`."""
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
        self, seq: int, prev_hash: str | None, record_hash: str, body: dict
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
                )
            )
            session.commit()
        # Advance the cached head only AFTER the commit succeeded (a failed
        # insert raises above, leaving the prior head correct).
        self._head = (record_hash, seq + 1)
        return record_id
