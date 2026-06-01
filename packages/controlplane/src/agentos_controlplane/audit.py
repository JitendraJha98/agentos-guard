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

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from agentos_contract import AgentAction, Decision
from agentos_controlplane.store.models import AuditRecord

# Payload keys the Phase-1 redactor knows how to classify. A key NOT in this
# allowlist is unclassifiable -> fail closed (D-15). This is intentionally
# minimal; the Presidio-grade redactor is Phase 4.
_KNOWN_PAYLOAD_KEYS = frozenset({"url", "content"})


class RedactionError(Exception):
    """Raised when a payload field cannot be classified — fail closed (D-15).

    The caller MUST NOT write a record when this is raised.
    """


def canonical_json(obj: dict) -> bytes:
    """Reproducible canonical JSON: sorted keys, no whitespace (RFC-8785-ish)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _redact_url(url: str) -> str:
    """Reduce a URL to scheme+host only — drops path/query (where secrets hide).

    Keeps the host for forensic value; never persists the query string or path.
    """
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise RedactionError(f"unclassifiable url field: {parts.scheme or '<no-scheme>'}")
    return f"{parts.scheme}://{parts.netloc}"


def _redact_content(content: str) -> dict:
    """Never persist raw fetched content — store length + SHA-256 digest only."""
    raw = content.encode("utf-8")
    return {"len": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _redact_or_raise(payload: dict) -> dict:
    """Classify + redact every payload field; raise on any unknown field (D-15)."""
    redacted: dict = {}
    for key, value in payload.items():
        if key not in _KNOWN_PAYLOAD_KEYS:
            raise RedactionError(f"unclassifiable payload field: {key!r}")
        if key == "url":
            if not isinstance(value, str):
                raise RedactionError("url field is not a string")
            redacted["url"] = _redact_url(value)
        elif key == "content":
            if not isinstance(value, str):
                raise RedactionError("content field is not a string")
            redacted["content"] = _redact_content(value)
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
                "outcome": decision.outcome.value,
                "risk_score": decision.risk_score,
                "trust_score": decision.trust_score,
                "reasons": [r.model_dump() for r in decision.reasons],
                "redacted_payload": redacted,
                # policy_version: Phase 4 (AUD-03) — nullable / omitted now.
            }
            record_hash = hashlib.sha256(canonical_json(body)).hexdigest()
            return self._insert(seq, prev_hash, record_hash, body)

    def _chain_head(self) -> tuple[str | None, int]:
        """Return (prior record_hash, next monotonic seq)."""
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
        return record_id
