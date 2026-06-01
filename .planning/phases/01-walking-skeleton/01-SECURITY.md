---
phase: 1
slug: walking-skeleton
status: verified
asvs_level: 1
block_on: high
threats_total: 22
threats_closed: 22
threats_open: 0
created: 2026-06-02
---

# Phase 1 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.
> Verification mode: confirm each plan-time threat's declared mitigation exists in
> implemented code (register authored at plan time — NOT a fresh vulnerability scan).

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| serialization boundary (`AgentAction`/`Decision` ↔ JSON) | Untrusted/foreign data deserialized into the contract types; boundary must reject unknown shapes. | normalized action / decision JSON |
| finding → audit log | `RiskFinding.matched` is written into an un-redactable, hash-covered record; raw payload must never enter. | pattern IDs only |
| agent → identity engine | Untrusted caller presents a token claiming an agent_id; the engine verifies signature + registration, never trusts claims. | EdDSA JWT, claimed agent_id |
| decision → audit log | Decision payload (possibly attacker-controlled fetched content) written into an immutable hash-covered record. | redacted payload, scores, reasons |
| fetched content → detector | Attacker-controlled page content / tool args enter `score()`; must not be evadable trivially, must not ReDoS, can only contribute risk. | bounded (32 KB) text |
| action host → policy floor | Target host (from attacker-influenceable tool args) checked against allowlist — THE access-control decision. | host string |
| package supply chain | `opa-wasmtime` (young, single-maintainer) added to the trusted dependency set. | locked dependency |
| action → pipeline | Full untrusted `AgentAction` enters `evaluate`; stages run in order, policy floor is authoritative over advisory risk/trust. | AgentAction |
| LangGraph agent → SDK PEP | Agent's tool call (possibly attacker-driven) crosses into the governed boundary; PEP must intercept BEFORE execution. | ToolCallRequest |
| deny decision → tool execution | A deny must structurally prevent the tool (egress) from running — not merely log. | handler invocation (or not) |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-01-01 | Tampering | `AgentAction`/`Decision` deserialization | mitigate | `model_config = {"extra": "forbid"}` — unknown fields rejected at the boundary. `action.py:30`, `decision.py:31` | closed |
| T-01-02 | Information Disclosure | `RiskFinding.matched` → audit log | mitigate | `_no_raw_payload` field_validator rejects URL-like / >64-char strings. `risk.py:30-37` | closed |
| T-01-03 | Tampering | data bounds on scores | mitigate | `risk_score`/`trust_score` bounded `Field(ge=0.0, le=1.0)`. `decision.py:34-35` | closed |
| T-01-04 | Spoofing | `identity_engine.verify` | mitigate | EdDSA verify with explicit `algorithms=[ALGORITHM]` (no header-derived alg — GHSA-ffqj-6fqr-9h24), `issuer=ISSUER` check, `sub==claimed` check, `is_registered(sub)` check; `jwt.InvalidTokenError` → terminal ok=False. `identity_engine.py:90-104` | closed |
| T-01-05 | Information Disclosure | `audit.append` redaction | mitigate | Fail-closed redaction: unclassifiable field → `RedactionError` raised, no record written; `_redact_url` rebuilds from `parts.hostname` (no userinfo — CR-01 fix); `_redact_content` stores len+SHA-256 only. `audit.py:54-91,108-109` | closed |
| T-01-06 | Tampering / Repudiation | `audit_record` chain | mitigate | SHA-256 hash chain over canonical JSON, monotonic `seq` (hash-covered), `prev_hash` links; `seq BIGINT UNIQUE NOT NULL` + nullable `prev_hash`; app-layer append-only + Postgres UPDATE/DELETE trigger (production target). `audit.py:49-51,106-154`, `models.py:52-72`, `0001_initial.py:27-82` | closed |
| T-01-07 | Repudiation | token validity window | accept (bounded) | `exp` claim set on issue (`TOKEN_TTL = 12h`); full rotation/revocation deferred to Phase 7. See Accepted Risks Log RISK-01. `identity_engine.py:25,77` | closed (accepted) |
| T-01-08 | Tampering / Elevation | `PromptInjectionScorer.score` (indirect injection) | mitigate | Deterministic regex over normalized text catches covered classes; detector is advisory only (`assess_risk` max-pools, never authoritative) — the authoritative block is the policy floor. `prompt_injection.py:54-77`, `aggregator.py:12-18` | closed |
| T-01-09 | Tampering | obfuscated/encoded injection | mitigate | `normalize()` (NFKC fold + zero-width/bidi strip + opportunistic base64 decode) runs BEFORE matching; honest partial coverage. `normalize.py:35-48`, `prompt_injection.py:95` | closed |
| T-01-10 | Denial of Service | ReDoS via hostile page | mitigate | Bounded-quantifier regexes (`[^.\n]{0,N}`, no nested unbounded groups) compiled once as class attributes; 32 KB input cap with truncation recorded. `prompt_injection.py:37-52,79-95` | closed |
| T-01-11 | Information Disclosure | finding contents | mitigate | `RiskFinding.matched` holds pattern IDs only (validator from T-01-02); raw payload never enters the finding. `prompt_injection.py:57-77`, `risk.py:30-37` | closed |
| T-01-12 | Elevation (P0-killer) | LLM/model on hot path | mitigate | Detector is stdlib-only (`re`/`unicodedata`/`base64`), `inline=True`; no network/model import reachable from `score()`. `prompt_injection.py:20-24`, `normalize.py:12-14` | closed |
| T-01-13 | Information Disclosure | egress to non-allowlisted host | mitigate | Deny-by-default Rego (`default allow := false`); non-allowlisted/empty host → terminal `deny`. `egress.rego:15-20`, `policy.py:75-88`, `runner.py:49-57` | closed |
| T-01-14 | Tampering | WASM load per request (Pitfall 2) | mitigate | `OPAPolicy` constructed ONCE in `__init__`, never in `evaluate`; allowlist case-normalized (`h.strip().lower()` — CR-02 fix). `policy.py:62-73` | closed |
| T-01-15 | Spoofing / Elevation | identity short-circuit | mitigate | Forged/unknown identity → terminal `deny` WITHOUT running policy/risk/graduated, still audited. `runner.py:80-92`, `identity.py:48-50` | closed |
| T-01-16 | Elevation (P0-killer) | graduated stage upgrading a deny | mitigate | `graduated_response` returns `deny` first if `policy_outcome == Outcome.deny`; risk/trust may only RESTRICT (floor invariant). `graduated.py:38-46` | closed |
| T-01-17 | Repudiation | missing audit on deny | mitigate | `evaluate` awaits `audit.append` and sets `evidence_ref` on BOTH the deny short-circuit path AND the normal path before returning. `runner.py:90-91,124-125` | closed |
| T-01-18 | Denial of Service | nested event loop | mitigate | No `asyncio.run()` in the runner (grep gate = 0 across `packages/`); CPU stages stay sync, only audit write awaited. `runner.py` (whole file) | closed |
| T-01-19 | Information Disclosure | data exfiltration via http_get | mitigate | Deny short-circuits in `awrap_tool_call` by NOT calling `handler` — tool never executes, no egress; returns a `ToolMessage` instead. `middleware.py:50-60` | closed |
| T-01-20 | Tampering / Elevation | indirect prompt injection (the probe) | mitigate | Deterministic egress-allowlist Rego floor is the authoritative block; detector is advisory; D-04 regression-lock proves deleting the principle flips deny→allow. `egress.rego:15-20`, `tests/redteam/test_exfil_injection.py` | closed |
| T-01-21 | Tampering | PEP logic leaking into the PDP | mitigate | SDK depends on contract + pipeline only; no `if from_sdk:` branch; pipeline/identity stage see only `AgentAction`. `middleware.py:24-26,30-35`, `identity.py:48-50`, `normalize.py:41-50` | closed |
| T-01-22 | Denial of Service | nested event loop in middleware | mitigate | No `asyncio.run()` in the hook (grep gate = 0); async path uses `awrap_tool_call` + `await`. `middleware.py:50-60` | closed |
| T-01-SC | Tampering (supply chain) | pip/uv installs (PyJWT, cryptography, sqlalchemy, asyncpg, alembic, langchain, langgraph, opa-wasmtime, wasmtime) | mitigate (BLOCKING) | All VERIFIED PyPI + slopcheck-OK and pinned in `uv.lock`; the only ASSUMED package (`opa-wasmtime`) gated behind the blocking human-verify checkpoint (01-04 Task 1) — source-repo review + real `egress.wasm` smoke test; human approval recorded ("approved — lock opa-wasmtime"); no `wasmer` in the resolution. `01-04-SUMMARY.md:74,79`; `uv.lock` | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

### Code-Review Critical Fixes (already-fixed, regression-verified)

| Defect | Fix Location | Regression Test |
|--------|-------------|-----------------|
| CR-01 — audit `_redact_url` leaked `user:password@` userinfo into the hash-covered body | `audit.py:54-68` (rebuilds from `parts.hostname`, no userinfo) | `tests/integration/test_audit_chain.py:121` `test_redaction_strips_url_userinfo_credentials` (asserts `s3cr3t` and `user:` absent) |
| CR-02 — egress allowlist match was case-sensitive vs an always-lowercased host (silent fail-deny) | `policy.py:73` (`[h.strip().lower() for h in allowlist]`) | `tests/unit/test_policy_engine.py:63` `test_mixed_case_allowlist_entry_matches_lowercased_host` |

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| RISK-01 | T-01-07 | Token validity is bounded by an `exp` claim (`TOKEN_TTL = 12h`, `identity_engine.py:25,77`) but full key rotation / revocation is out of Phase-1 scope. Single-process Walking Skeleton with short-lived dev tokens; rotation/revocation lands in Phase 7. ASVS V3 partial. | Phase plan (01-02-PLAN `<threat_model>`, disposition `accept (bounded)`) | 2026-06-02 |

*Accepted risks do not resurface in future audit runs.*

---

## Unregistered Flags

None. The `## Threat Flags` sections of every SUMMARY (01-02, 01-06 explicitly "None"; 01-01/01-03/01-04/01-05 confirm "no new threat surface beyond the plan's `<threat_model>`") report no new attack surface. Every component introduced maps to a registered threat ID.

## Context Deviations Acknowledged (not gaps)

- **D-14 (no-Docker):** audit store runs on a pluggable SQLite `Store`; Postgres SQLAlchemy models + Alembic migration retained as the production target. App-layer append-only is enforced for SQLite; the Postgres UPDATE/DELETE trigger is authored (dialect-guarded) and is the production-target hardening. Real-Postgres concurrency / advisory-lock serialization / trigger validation is deferred to Phase 4 per the Deviation Log. NOT flagged as an open threat (approved Phase-1 state).

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-06-02 | 22 | 22 | 0 | gsd-security-auditor (Claude) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log (RISK-01 / T-01-07)
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-06-02
