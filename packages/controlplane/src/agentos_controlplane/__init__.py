"""agentos-controlplane — registry, identity engine, and hash-chained audit.

Phase 1 (Wave 2). Persistence behind a pluggable `Store` interface; the active
Phase-1 backend is SQLite (D-14 no-Docker deviation). The SQLAlchemy/Alembic
models are authored against PostgreSQL as the production target using
dialect-agnostic generic types, so the same models run on SQLite now and map to
Postgres later (a backend swap, not a rewrite).
"""

from agentos_controlplane.audit import AuditWriter, RedactionError, canonical_json
from agentos_controlplane.identity_engine import IdentityEngine, IdentityResult
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.models import Agent, AuditRecord, Base

__all__ = [
    "AuditWriter",
    "RedactionError",
    "canonical_json",
    "IdentityEngine",
    "IdentityResult",
    "Registry",
    "Agent",
    "AuditRecord",
    "Base",
]
