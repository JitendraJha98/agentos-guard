# Phase 4 · Slice 4d — Secret-Detector Last Gate — Implementation Plan

> REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end with a second
> `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task. Gates `floor_invariant` (430) +
> `regression_lock` (10) green at every commit.

**Goal (AUD-04):** A fail-closed, content-based, name-agnostic secret detector run as the **LAST
gate** over the fully-assembled, already-redacted audit body — AFTER canonicalization, BEFORE
hash/sign/INSERT — in BOTH `append` and `append_event`. Defense-in-depth beneath the field
classifier: it catches a secret that slipped into a known verbatim-kept field (`model`, `to_agent`)
or a free-text field the runner/interpreter produced (`rationale`, `inferred_intent`,
`remediation`). On a hit → `SecretLeakError`, write NOTHING (same fail-closed contract as
`RedactionError`).

**Honest scope:** best-effort RECALL (regex + entropy will miss novel/low-entropy secrets) — a
backstop that shrinks the blast radius of a misclassification, NOT a guarantee. The guarantee
stays the fail-closed allowlist classifier; Presidio-grade ML PII is the later upgrade already
noted in `audit.py`. Deterministic: stdlib `re` compiled once + Shannon entropy; no LLM/network;
ReDoS-safe.

**Critical FP discipline:** the audit body legitimately contains the redactor's own `{len,
sha256:<64hex>}` digest, `prev_hash` (64-hex), `action_id` (UUID), and `"sha256:..."` versions —
**none may trip the gate.** The entropy gate excludes them by requiring an OPAQUE-SECRET shape
(mixed character classes), which lowercase-hex/uuid/version strings are not. **No existing test
may start failing** — tune the threshold against the full suite.

> First commit in this slice: `docs(phase-4): Slice 4d plan` for this file, then the tasks below.

## File structure
- Create `packages/controlplane/src/agentos_controlplane/secret_scan.py` — `SecretLeakError`,
  `scan(text) -> list[str]`.
- Modify `packages/controlplane/src/agentos_controlplane/audit.py` — run the gate in `append` +
  `append_event` after `canonical_json(...)`, before hash/sign/insert.
- Tests: `tests/unit/test_secret_scan.py`, `tests/unit/test_audit_secret_gate.py`.

---

### Task 1: `secret_scan.py`
```python
"""AUD-04 last gate — fail-closed, content-based secret detector over the about-to-be-written
audit body (see module-level rationale in the plan). Deterministic; stdlib re + entropy only."""
from __future__ import annotations
import math
import re


class SecretLeakError(Exception):
    """A secret was detected in the audit body — fail closed, write NOTHING (RedactionError peer)."""


# High-precision structured-secret patterns (gitleaks/detect-secrets family), compiled once,
# bounded (ReDoS-safe).
_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),
}

# Opaque-token candidates for the entropy gate.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
_ENTROPY_THRESHOLD = 4.0  # bits/char


def _shannon(s: str) -> float:
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values()) if n else 0.0


def _looks_opaque_secret(tok: str) -> bool:
    # Real keys mix character classes; the audit body's hex digests / UUIDs / "sha256:" prefixes
    # are single-class lowercase-hex and must NOT trip. Require (uppercase AND digit) OR a
    # base64-special char — excludes lowercase-hex/uuid/version, catches AWS-secret/base64 tokens.
    has_upper = any(c.isupper() for c in tok)
    has_digit = any(c.isdigit() for c in tok)
    has_b64 = any(c in "+/=" for c in tok)
    return (has_upper and has_digit) or has_b64


def scan(text: str) -> list[str]:
    """Return finding ids for secrets detected in `text`; empty list == clean."""
    findings = [name for name, pat in _PATTERNS.items() if pat.search(text)]
    for tok in _TOKEN.findall(text):
        if _looks_opaque_secret(tok) and _shannon(tok) >= _ENTROPY_THRESHOLD:
            findings.append("high_entropy_token")
            break
    return findings
```
**Tests** (`tests/unit/test_secret_scan.py`):
- FLAGGED: `AKIAIOSFODNN7EXAMPLE`; `ghp_` + 36 alnum; `xoxb-...`; `-----BEGIN PRIVATE KEY-----`;
  a 3-part `eyJ...` JWT; `Bearer <20+ token>`; a mixed-case+digit 40-char base64-ish token.
- NOT FLAGGED (FP guards): clean English; a 64-char lowercase sha256 hex; a UUID
  (`11111111-1111-1111-1111-111111111111`); `"sha256:" + 64hex`; an https host; an NVIDIA model id
  `meta/llama-3.1-8b-instruct`; the redactor digest JSON fragment `{"len": 5, "sha256": "<64hex>"}`.
- `scan("")` == [].
Commit `feat(controlplane): AUD-04 content-based secret scanner (regex + entropy, FP-guarded)`.

### Task 2: wire the last gate into the writer
In `audit.py`, import `from agentos_controlplane.secret_scan import SecretLeakError, scan`. In BOTH
`append` and `append_event`, right after the `canonical = canonical_json(body)` line and BEFORE the
`record_hash = hashlib.sha256(canonical)...` line (inside the lock):
```python
            leaks = scan(canonical.decode("utf-8"))
            if leaks:
                raise SecretLeakError(f"secret-like content in audit body: {sorted(set(leaks))}")
```
(It runs over the literal to-be-written bytes, so it sees `redacted_payload`, `reasons`,
`inferred_intent`, `remediation` — every field. Raising before `_insert` writes nothing and does
NOT advance the cached head.)
**Tests** (`tests/unit/test_audit_secret_gate.py`):
- A `Decision` whose `reasons[0].rationale` contains `AKIAIOSFODNN7EXAMPLE` → `append` raises
  `SecretLeakError`; row count unchanged (fail-closed, nothing written).
- A secret in `append_event` body (e.g. a resolver note with a token) → `SecretLeakError`, no row.
- A clean decision → appends normally; row present + verifies.
- A normal `tool_call` with `content` (→ body carries the redactor's sha256 digest) → appends fine
  (the digest does NOT trip the gate — the load-bearing FP test).
Commit `feat(controlplane): secret-scan last gate in append/append_event, fail-closed (AUD-04)`.

### Task 3: full gate + tuning
- FULL suite `pytest -q` green — **no existing audit/e2e test trips the scanner.** If one does, it's
  a true FP: tighten `_looks_opaque_secret` / the threshold (do NOT weaken a real detection or skip
  the gate). Report what tripped (if anything) and the fix.
- `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` healthy (the scan is ~6 regexes +
  a token pass over a few-hundred-char body — sub-ms; confirm the budget holds).
- Note (no code needed): a `SecretLeakError` on the pipeline's append path propagates to the
  runner's `_fail_safe` → per-class posture deny (no leaked record written) — the correct
  fail-closed outcome; a distinct runner reason is optional polish, out of scope for 4d.
Commit only if incidental fixes were needed.

## Self-review
AUD-04: content-based + name-agnostic gate over the canonical body in append AND append_event,
fail-closed (SecretLeakError → no write, head not advanced); regex set high-precision + entropy
gate FP-guarded against the body's own hex digests/UUIDs/versions; honest best-effort framing
documented; no existing test trips it; latency held.
