# ADR 0004 — Hash-chained tamper-evident audit log

- **Status:** Accepted
- **Date:** 2026-06-01

## Context

Audit evidence must be tamper-evident to be trusted for compliance (OWASP, NIST, EU AI Act,
SOC 2). Options range from a simple append-only log to a hash chain, a Merkle DAG, or full
zero-knowledge proofs. We want verifiability without over-engineering the MVP.

## Decision

Phase 0 uses an **append-only, hash-chained** audit table (each record stores the previous
record's hash) in Postgres, with **policy-version provenance** and a **detached per-record
EdDSA signature** (reusing the identity keys) on every record, so a single record verifies
independently of the chain. Upgrade to a **Merkle DAG** in Phase 1 (efficient inclusion proofs /
partial disclosure) and add **zero-knowledge compliance proofs** (RISC Zero / SP1) in Phase 2.

Forensic causal reconstruction (the "evidence graph") is served by **joining the audit log with
the materialized agent graph at query time** on `parent_action_id` / `conversation_id` /
`trace_id` — Postgres recursive CTEs, **no separate graph database**. A dedicated graph backend
remains an optional later optimization, not a Phase-0 dependency.

## Consequences

- (+) Detectable tampering from day one with minimal infrastructure.
- (+) A clean upgrade path (chain → DAG → ZK) without changing the record contract.
- (−) A hash chain alone doesn't give efficient partial proofs — acceptable until the Merkle
  upgrade.
- (−) Sensitive payloads must be redacted at write time (policy-driven) so retained logs are
  safe; ZK later proves compliance over never-disclosed data.
- (+) Per-record signatures prove *authorship* (this control plane issued this decision), which
  the hash chain alone does not; they cost one signature per write and reuse existing keys.
- (+) Query-time join for the evidence graph keeps Phase 0 on a single datastore (no graph DB to
  operate) while still answering causal-chain / forensic queries.
- Detail: [`../07-audit-and-compliance.md`](../07-audit-and-compliance.md).
