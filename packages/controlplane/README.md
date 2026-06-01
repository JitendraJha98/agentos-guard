# agentos-controlplane

Control-plane persistence for agentos-guard (Phase 1, Wave 2).

- **registry.py** — agent self-registration; issues a signed identity token; loads the seed trust score (IDN-01, TRST-01 seed).
- **identity_engine.py** — EdDSA (Ed25519) JWT `issue_token` / `verify` with an explicit `algorithms=["EdDSA"]` allowlist (IDN-01/02; no algorithm-confusion — GHSA-ffqj-6fqr-9h24).
- **audit.py** — hash-chained `AuditWriter.append` over canonical JSON with monotonic `seq`, prev-hash links, and fail-closed redaction (AUD-01 / D-15).
- **store/** — SQLAlchemy 2.0 models (`Agent`, `audit_record`) + Alembic migration, authored against **PostgreSQL as the production target** but using dialect-agnostic generic types so they run on the **Phase-1 SQLite backend** (D-14 no-Docker deviation). The `Store` interface is the seam that makes the backend swap clean.

**No Docker / no Postgres in Phase 1.** Chain correctness is proven on SQLite; real-Postgres concurrency, advisory locks, and the append-only trigger are re-validated in Phase 4/5 per the Deviation Log.
