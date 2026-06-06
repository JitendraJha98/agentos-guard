---
phase: 01-walking-skeleton
reviewed: 2026-06-02T00:00:00Z
depth: standard
files_reviewed: 20
files_reviewed_list:
  - packages/contract/src/agentos_contract/action.py
  - packages/contract/src/agentos_contract/decision.py
  - packages/contract/src/agentos_contract/pipeline.py
  - packages/contract/src/agentos_contract/risk.py
  - packages/controlplane/src/agentos_controlplane/audit.py
  - packages/controlplane/src/agentos_controlplane/identity_engine.py
  - packages/controlplane/src/agentos_controlplane/registry.py
  - packages/controlplane/src/agentos_controlplane/store/models.py
  - packages/controlplane/src/agentos_controlplane/store/engine.py
  - packages/pipeline/src/agentos_pipeline/runner.py
  - packages/pipeline/src/agentos_pipeline/graduated.py
  - packages/pipeline/src/agentos_pipeline/identity.py
  - packages/pipeline/src/agentos_pipeline/policy.py
  - packages/pipeline/src/agentos_pipeline/risk/prompt_injection.py
  - packages/pipeline/src/agentos_pipeline/risk/normalize.py
  - packages/pipeline/src/agentos_pipeline/risk/aggregator.py
  - packages/sdk/src/agentos_sdk/middleware.py
  - packages/sdk/src/agentos_sdk/normalize.py
  - packages/sdk/src/agentos_sdk/tools.py
  - policies/egress.rego
findings:
  critical: 2
  warning: 6
  info: 4
  total: 12
status: issues_found
---

# Phase 1: Code Review Report

**Reviewed:** 2026-06-02T00:00:00Z
**Depth:** standard
**Files Reviewed:** 20
**Status:** issues_found

## Summary

Phase 1 walking skeleton for `agentos-guard`. Reviewed the contract boundary,
control-plane (identity engine, registry, audit writer, store), the 4-stage
pipeline (identity / policy / risk / graduated), the SDK PEP middleware, and the
egress Rego policy.

The core security invariants are mostly upheld and were specifically verified:

- **Floor invariant (graduated.py):** A policy `deny` short-circuits to `deny`
  regardless of risk/trust; risk/trust can only move down the spectrum on an
  allowed action. Correct.
- **Identity short-circuit (runner.py / identity_engine.py):** `not ident.ok`
  returns a terminal `deny` before policy/risk/graduated run; `jwt.decode` passes
  `algorithms=[ALGORITHM]` explicitly (never header-derived), checks `iss`, `sub`,
  and registration. Correct — no algorithm-confusion regression.
- **Deny enforcement (middleware.py):** On `deny` the middleware returns a
  `ToolMessage` without calling `handler` — no egress. Correct.
- **Detector ReDoS-safety (prompt_injection.py / normalize.py):** Patterns are
  compiled once as class attributes, use only bounded quantifiers
  (`[^.\n]{0,N}`), no nested unbounded groups, input capped at 32 KB, no
  network/LLM. Deterministic. Correct.
- **Policy WASM load-once (policy.py):** `OPAPolicy` is constructed in
  `__init__`, not per `evaluate`. Correct.

However, two BLOCKER-class defects undermine audit integrity and the egress floor,
and several robustness/coverage gaps weaken the stated guarantees. Details below.

## Critical Issues

### CR-01: Audit redaction leaks embedded URL credentials into the hash-covered audit log

**File:** `packages/controlplane/src/agentos_controlplane/audit.py:54-62`
**Issue:** `_redact_url` reduces a URL to `f"{parts.scheme}://{parts.netloc}"`,
but `urlsplit(...).netloc` **retains userinfo** (the `user:password@` segment) and
the port. For a URL like `https://user:s3cr3t@evil.example.com:8443/path?token=abc`,
`netloc` is `user:s3cr3t@evil.example.com:8443`, so the stored "redacted" value is
`https://user:s3cr3t@evil.example.com:8443` — the embedded credential is persisted
verbatim into the body that is covered by `record_hash` and is, per the module
docstring, explicitly un-redactable after the fact. This directly violates the
stated invariant ("never persists the query string or path" / "no raw secret leaked
into the stored body"). Credentials embedded in URLs are exactly the kind of secret
the redactor is supposed to drop. Verified empirically: `urlsplit` preserves
userinfo in `netloc`.
**Fix:** Strip userinfo before persisting — use `parts.hostname` (and optionally
`parts.port`) instead of the raw `netloc`:
```python
def _redact_url(url: str) -> str:
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        raise RedactionError(f"unclassifiable url field: {parts.scheme or '<no-scheme>'}")
    host = parts.hostname  # lowercased, NO userinfo, NO password
    if parts.port is not None:
        host = f"{host}:{parts.port}"
    return f"{parts.scheme}://{host}"
```
Note `.hostname` is also lowercased, which keeps the stored host consistent with the
policy-stage host in CR-02.

### CR-02: Egress allowlist match is case-sensitive against a lowercased host — config-dependent fail-open / fail-deny

**File:** `packages/pipeline/src/agentos_pipeline/runner.py:49-57` and `policies/egress.rego:17-20`
**Issue:** `_host` returns `urlsplit(url).hostname`, which urllib **always
lowercases** (verified: `urlsplit("http://EXAMPLE.COM/").hostname == "example.com"`).
The Rego rule then performs an exact-string membership test
`input.host in data.allowlist`, and the allowlist is passed verbatim into
`WasmPolicyEngine.__init__(allowlist)` (policy.py:62-68) with no normalization. Two
consequences, both bad for an authoritative security floor:
1. **Silent fail-deny:** an allowlist entry authored as `API.Example.com` or
   `Example.com` can never match the always-lowercased host — legitimate traffic is
   denied with no diagnostic, and an operator "fixing" it by mutating the rule could
   weaken the floor.
2. **No host canonicalization on the trust boundary:** the floor's correctness
   depends entirely on the caller having pre-lowercased every allowlist entry. There
   is no enforcement of that precondition in code, so the security guarantee is
   implicit and easy to regress. Host comparison in a security allowlist must be
   canonicalized on both sides, not left to caller discipline.
**Fix:** Canonicalize the allowlist to lowercase at construction so both sides of
the comparison are normalized:
```python
def __init__(self, wasm_path: str, allowlist: list[str]) -> None:
    self._policy = OPAPolicy(wasm_path)
    self._policy.set_data({"allowlist": [h.strip().lower() for h in allowlist]})
```
(Confirm trailing-dot / IDNA handling is out of Phase-1 scope; if not, normalize
those too. The host side is already lowercased by `urlsplit.hostname`.)

## Warnings

### WR-01: Audit chain head-read and insert run in separate sessions/transactions — read-then-write is not atomic

**File:** `packages/controlplane/src/agentos_controlplane/audit.py:106-148`
**Issue:** `append` holds an `asyncio.Lock`, then `_chain_head()` opens one session
to read `(prev_hash, seq)` and `_insert()` opens a **second, separate** session to
write. The lock only serializes coroutines within one event loop and one
`AuditWriter` instance; it does not make the read+write atomic at the DB level. Two
`AuditWriter` instances, two processes, or any future async/threaded writer would
race between read and insert, producing duplicate `seq` (the `unique=True` on
`seq` would then raise mid-chain) or a forked `prev_hash`. The module documents
single-process single-writer as the Phase-1 scope, but the two-session split is a
latent correctness hazard that is "not cheaply retrofittable" per the file's own
warning.
**Fix:** Read the chain head and insert within a **single** session/transaction so
the head selection and the append commit atomically:
```python
async with self._lock:
    with self.session_factory() as session:
        last = session.scalars(
            select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(1)
        ).first()
        prev_hash, seq = (None, 0) if last is None else (last.record_hash, last.seq + 1)
        body = {...}
        record_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        record_id = uuid4()
        session.add(AuditRecord(id=record_id, seq=seq, prev_hash=prev_hash,
                                record_hash=record_hash, body=body))
        session.commit()
        return record_id
```

### WR-02: Blocking synchronous DB I/O inside the async `append` coroutine

**File:** `packages/controlplane/src/agentos_controlplane/audit.py:100-148`
**Issue:** `append` is `async`, but `_chain_head` and `_insert` perform synchronous
SQLAlchemy calls (`session.scalars(...)`, `session.commit()`) directly on the event
loop. Under SQLite this can still block the loop on disk I/O / SQLite write locks
(`SQLITE_BUSY`), stalling every other coroutine sharing the loop — including the
LangGraph agent loop the middleware runs inside (middleware.py:50-53 awaits
`pipeline.evaluate`, which awaits this `append`). For the single-process skeleton
this is tolerable, but it contradicts the "async-first" rationale and will not scale
to the Postgres swap without rework.
**Fix:** Either keep the writer fully synchronous (it does no real async work) and
have the pipeline call it without `await`, or offload the blocking DB section with
`await asyncio.to_thread(self._sync_append, action, decision)`. Be explicit about
which, since the current shape is async in signature but blocking in body.

### WR-03: Risk detector never inspects fetched content at PEP interception time — stated coverage invariant is unmet

**File:** `packages/pipeline/src/agentos_pipeline/risk/prompt_injection.py:79-95` and `packages/sdk/src/agentos_sdk/normalize.py:41-50`
**Issue:** `_inspect_text` scans `action.payload.values()`, and the module docstring
claims it inspects "the `http_get` tool call and the content it would fetch."
However, `normalize_action` builds the payload from `dict(tc["args"])` only —
for `http_get(url)` the payload is `{"url": ...}` with **no `content` key**, because
the PEP intercepts *before* the tool executes (middleware.py blocks/allows
pre-execution). So at decision time the detector only ever sees the URL string, not
the fetched page body where the indirect-injection probe lives (AI-SPEC §1b item 1:
"The detector must inspect retrieved content, not just the literal tool arguments").
The `truncated`/32 KB content-window machinery is effectively dead on this path. The
floor still denies the exfil host, so the demo's deterministic block holds, but the
detector's headline capability (catching injected exfil directives in fetched
content) is not exercised end-to-end.
**Fix:** Either (a) explicitly scope the Phase-1 detector to URL/argument inspection
in the docstring and tests, and stop claiming content coverage, or (b) add a
post-fetch evaluation hook so fetched `content` is normalized into a follow-up
`AgentAction` the detector actually scores. Pick one and make the code and the
asserted invariant agree.

### WR-04: A `RedactionError` on the deny path drops the audit record and aborts the decision

**File:** `packages/controlplane/src/agentos_controlplane/audit.py:100-103` and `packages/pipeline/src/agentos_pipeline/runner.py:89-92,124-125`
**Issue:** `append` calls `_redact_or_raise(action.payload)` first and re-raises on
any unclassifiable field. In the runner, both the identity-deny path and the success
path do `decision.evidence_ref = await self._audit.append(...)`. If redaction raises
(e.g. an attacker includes an extra payload key, or a non-string `url`), the
exception propagates out of `evaluate` and out of `awrap_tool_call` entirely — so no
`Decision` is returned and **no audit record is written for a denied action**. While
this is fail-closed for egress (the handler is never called, so the tool does not
run), it is fail-open for evidence: the very action that tripped fail-closed
redaction leaves no audit trail, and the caller (LangChain) receives an unhandled
exception rather than a governed `deny`. For a control plane whose value is
"evidence exists before enforcement," a denied/blocked action with no record is a
gap.
**Fix:** On the deny/abort path, write a redaction-failure audit record that omits
the unclassifiable payload (store a `redaction_failed` marker + the failing key name,
never the value) so the block is still evidenced, then surface a governed `deny`
rather than letting the raw exception escape the PEP.

### WR-05: `evaluate` swallows no policy-engine errors — a WASM/runtime failure escapes as an unhandled exception (fail-open risk)

**File:** `packages/pipeline/src/agentos_pipeline/runner.py:98-104` and `packages/pipeline/src/agentos_pipeline/policy.py:70-71`
**Issue:** `policy.evaluate(...)` calls `OPAPolicy.evaluate`, which can raise on a
malformed input, a wasmtime trap, or a bundle/version mismatch. `_extract_bool`
fails closed only for *unexpected shapes* of a successful return; it does not catch
*exceptions*. An exception from the policy stage propagates out of `evaluate`, so the
middleware's `await self._pipeline.evaluate(action)` raises. Depending on how
LangChain treats a raising middleware hook, the safe outcome (deny) is not
guaranteed — and the floor is the authoritative control. A security floor should
never depend on an exception being handled "somewhere upstream."
**Fix:** Wrap the policy-stage call so any exception deterministically becomes a
`deny` with a `policy_error` reason, mirroring the deny-by-default discipline already
applied to unexpected result shapes in `_extract_bool`.

### WR-06: `register` rotates no key but unconditionally overwrites `trust_score` to the default on re-register

**File:** `packages/controlplane/src/agentos_controlplane/registry.py:28-42`
**Issue:** `register(agent_id)` with the default argument sets
`agent.trust_score = trust_score` (= `DEFAULT_TRUST_SCORE` 0.5) on an **existing**
agent. So re-registering an agent silently resets a previously-adjusted trust score
back to 0.5. Trust feeds the graduated stage (TRST-01); an unintended reset to the
default could relax a deliberately-lowered trust. The "seed" framing suggests trust
is not yet adjusted elsewhere in Phase 1, so the impact is currently latent, but the
overwrite-on-default is a foot-gun the moment trust becomes mutable.
**Fix:** Only update `trust_score` when the caller passes an explicit value (sentinel
default), or document that re-register intentionally resets trust. As written, the
silent reset is surprising.

## Info

### IN-01: Unused import `func` in audit.py

**File:** `packages/controlplane/src/agentos_controlplane/audit.py:30`
**Issue:** `from sqlalchemy import func, select` — `func` is never used in this
module (only `select`). Dead import.
**Fix:** `from sqlalchemy import select`.

### IN-02: `Decision.evidence_ref` is mutated after construction on a model with `extra="forbid"`

**File:** `packages/contract/src/agentos_contract/decision.py:30-37` and `packages/pipeline/src/agentos_pipeline/runner.py:91,125`
**Issue:** `Decision` is not frozen, so `decision.evidence_ref = await ...` is legal,
but constructing the `Decision` and then mutating one field is a minor smell on an
otherwise immutable-by-intent contract object. If `Decision` is ever frozen for
audit-integrity reasons (consistent with `RiskFinding` being `frozen=True`), this
mutation breaks.
**Fix:** Pass `evidence_ref` at construction by writing the audit record first, or
use `model_copy(update={"evidence_ref": ...})`. Low priority while `Decision` stays
mutable.

### IN-03: Genesis `seq = 0` with a falsy-prone integer

**File:** `packages/controlplane/src/agentos_controlplane/audit.py:123-131`
**Issue:** Genesis returns `seq = 0`. `0` is falsy; any future code that guards on
`if seq:` rather than `if seq is not None:` would mis-handle the genesis record. Not
a current bug (no such guard exists), but a sharp edge for a load-bearing monotonic
counter.
**Fix:** None required now; if any boolean check on `seq` is added later, use
explicit `is not None`. Noted for awareness.

### IN-04: `normalize()` silently swallows all base64-decode exceptions with bare `except Exception: pass`

**File:** `packages/pipeline/src/agentos_pipeline/risk/normalize.py:42-45`
**Issue:** The decode loop catches `Exception` broadly and `pass`es. This is
intentional ("not valid base64 — ignore, never raise") and is acceptable for an
opportunistic de-obfuscation pass, but the bare `except Exception` is wider than the
expected `binascii.Error` / `UnicodeDecodeError` and would also swallow unexpected
programmer errors, masking real bugs in the decode path.
**Fix:** Narrow to the expected exception types:
`except (binascii.Error, ValueError): pass`. Keeps the never-raise guarantee while
not hiding unrelated failures.

---

_Reviewed: 2026-06-02T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
