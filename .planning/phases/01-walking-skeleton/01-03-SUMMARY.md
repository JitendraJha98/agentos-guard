---
phase: 01-walking-skeleton
plan: 03
subsystem: pipeline
tags: [sec-01, prompt-injection, detector, regex, redos-safe, normalize, nfkc, base64, zero-width, determinism, risk-score, pydantic, stdlib]

# Dependency graph
requires:
  - phase: 01-walking-skeleton (01-01)
    provides: agentos-contract (RiskFinding, RiskScorer Protocol, AgentAction) — the typed boundary the scorer implements/returns
provides:
  - agentos-pipeline package (uv workspace member, editable-installed)
  - PromptInjectionScorer (prompt_injection.v1, inline=True) — deterministic regex detector behind the RiskScorer Protocol; returns a typed RiskFinding
  - normalize() — NFKC fold + zero-width/bidi strip + opportunistic base64 decode, run BEFORE matching (trivial-obfuscation mitigation)
  - assess_risk(action, scorers) — risk-stage aggregator; runs inline-only scorers, max-pools risk_score, no I/O
  - labeled reference dataset (8 attack + 8 benign probes) + determinism/purity/bounded-input tests (AI-SPEC §5)
affects: [01-05 graduated stage (consumes risk_score; the floor invariant lives there), 01-06 e2e/red-team (the exfil probe content), Phase-3 classifier tier (slots behind the same RiskScorer Protocol as inline=False)]

# Tech tracking
tech-stack:
  added: [stdlib re / unicodedata / base64 (hot-path only); no new runtime dependency]
  patterns:
    - "Compile-once: regex patterns are class attributes compiled at class definition, never per-call (Pitfall 2, ReDoS-safe). re.compile count == pattern count (asserted)."
    - "Bounded quantifiers only ([^.\\n]{0,N}); no nested unbounded groups — ReDoS-safe over attacker-controlled content."
    - "normalize() FIRST: NFKC + zero-width strip + opportunistic base64 decode before matching (honest partial evasion mitigation; paraphrase/typoglycemia deferred)."
    - "Deterministic byte-budget truncation at 32 KB computed on raw bytes BEFORE normalization; truncation recorded in finding.detail (no silent under-coverage)."
    - "Advisory-only: the scorer only contributes risk_score; it can never relax the policy floor (the floor invariant is enforced in the graduated stage, 01-05)."
    - "Invisible smuggling codepoints declared NUMERICALLY (chr()/range) in source — never literal invisible chars (repo injection-hook safe, reviewable)."

key-files:
  created:
    - packages/pipeline/pyproject.toml
    - packages/pipeline/README.md
    - packages/pipeline/src/agentos_pipeline/__init__.py
    - packages/pipeline/src/agentos_pipeline/risk/__init__.py
    - packages/pipeline/src/agentos_pipeline/risk/normalize.py
    - packages/pipeline/src/agentos_pipeline/risk/prompt_injection.py
    - packages/pipeline/src/agentos_pipeline/risk/aggregator.py
    - tests/unit/test_detector_recall.py
  modified:
    - pyproject.toml (workspace: add agentos-pipeline member dependency + source)
    - tests/conftest.py (wire the prompt_injection_scorer fixture to the real PromptInjectionScorer)
    - uv.lock (agentos-pipeline editable install)

key-decisions:
  - "SEC-01 detector is stdlib re + Pydantic only — no LLM/model/network on the hot path (P0-killer Pitfall 1, CONTEXT.md D-12). inline=True, sub-ms, pure CPU."
  - "Scorer is stateless and pure — no accumulation across calls (statefulness would reintroduce flakiness into the D-04 CI gate)."
  - "32 KB input cap, deterministic byte budget; truncation recorded in detail so a past-cap injection is auditable, not silently missed (Critical Failure Mode 5)."
  - "Out-of-scope evasion (typoglycemia, sharded exfil, paraphrase/novel encoding) is honestly xfail-marked (strict=True) so the suite never overclaims coverage — full coverage is the deferred Phase-3 classifier."
  - "_B64 regex uses a trailing negative-lookahead instead of \\b so '='/'==' padding is captured (Rule 1 fix; the AI-SPEC verbatim trailing \\b dropped padding and made the blob undecodable)."

patterns-established:
  - "RiskScorer implementations live in agentos-pipeline; only the Protocol + RiskFinding are in the stable contract boundary."
  - "Honest coverage discipline: every claimed class is exercised by a regression_lock test; every uncovered class is an explicit strict-xfail with a documented deferral reason."

requirements-completed: [SEC-01]
---

# Phase 1 Plan 03: SEC-01 Deterministic Prompt-Injection Detector Summary

The SEC-01 risk stage — a deterministic, inline, ReDoS-safe `PromptInjectionScorer` (stdlib `re` + Pydantic `RiskFinding`) behind the `RiskScorer` Protocol, with a `normalize()` de-obfuscation pass (NFKC + zero-width strip + opportunistic base64 decode) and an `assess_risk` max-pooling aggregator — built TDD (RED→GREEN), with 100% recall on the covered injection/exfil classes, zero false-fires on the benign set, byte-identical findings across 100 runs, and no network/model import reachable from the detector graph.

## What Was Built

`agentos-pipeline` workspace package with the `risk/` subpackage:

- **`normalize.py`** — `normalize(text)`: `unicodedata.normalize("NFKC", ...)` to fold homoglyphs/compatibility chars, strips zero-width/bidi/BOM smuggling codepoints (U+200B..U+200F, U+202A..U+202E, U+2060, U+FEFF — declared numerically via `chr()`/`range`, never literal invisibles), and opportunistically base64-decodes long ASCII blobs (`{16,}` with padding) appending the plaintext so `_EXFIL`/`_OVERRIDE` can match decoded content. Never raises on bad base64.
- **`prompt_injection.py`** — `PromptInjectionScorer` (`name="prompt_injection.v1"`, `inline=True`). `_OVERRIDE`/`_ROLE_HIJACK`/`_EXFIL` compiled **once** as class attributes with bounded quantifiers. `score()` normalizes the payload first, caps inspected text at 32 KB (deterministic byte budget, truncation noted in `detail`), matches the three pattern classes, computes `min(1.0, 0.4 + 0.3 * len(matched))`, and returns a typed `RiskFinding`.
- **`aggregator.py`** — `assess_risk(action, scorers)` runs only `inline=True` scorers, max-pools `risk_score` (most-severe wins), performs no I/O.
- **`tests/unit/test_detector_recall.py`** — the AI-SPEC §5 reference dataset: 8 attack probes (instruction-override, role-hijack ×2, exfil-directive incl. the canonical indirect-injection-via-fetched-page-content probe, + zero-width / NFKC-homoglyph / base64 obfuscation variants) and 8 benign samples (trigger-adjacent words: "ignore the noise", "system requirements", "the token bucket algorithm", etc.), plus determinism, import-guard purity, bounded-input, aggregator, and normalize unit tests. Out-of-scope evasion (typoglycemia, sharded exfil) is `strict=True` xfail.

## Verification Evidence

- `uv run pytest tests/unit/test_detector_recall.py -q` → **27 passed, 2 xfailed** (recall 100% on covered classes; 0 false-fires on benign; obfuscation variants caught after normalize()).
- `uv run pytest tests/unit/test_detector_recall.py --count=100 -q` → **2700 passed, 200 xfailed** — byte-identical `model_dump_json()` across all 100 runs (deterministic, no RNG/wall-clock).
- Import-guard (`test_purity_no_network_or_model_imports`) green: the detector modules add **none** of `socket`/`http`/`urllib.request`/`transformers`/`anthropic`. (Verified separately: `socket` is pulled transitively by `agentos_contract`/Pydantic at import — a pre-existing contract-package condition, **not** the detector's code and not reachable from `score()`'s runtime path.)
- `re.compile` count (non-comment) in `prompt_injection.py` = **3** = number of pattern class-attributes (compiled once at construction, never per-call).
- Full repo suite: `uv run pytest -q` → **46 passed, 2 xfailed** (no regressions).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `_B64` regex dropped base64 padding, making padded blobs undecodable**
- **Found during:** Task 1 GREEN (the `obf_base64_exfil` recall probe and `test_normalize_decodes_base64_opportunistically` failed).
- **Issue:** The AI-SPEC §4 verbatim pattern `\b[A-Za-z0-9+/]{16,}={0,2}\b` ends with `\b`. A padded base64 blob ends in `=`/`==` (non-word) followed by a non-word boundary (whitespace/EOL), so no `\b` exists after the padding; the match stopped before `=`, yielding an unpadded substring of invalid length that `base64.b64decode(..., validate=True)` rejected — so the injected exfil plaintext was never decoded and the probe silently passed (a false negative — the exact "silent under-coverage" failure mode).
- **Fix:** Replaced the trailing `\b` with a negative lookahead `(?![A-Za-z0-9+/=])` so the full padded blob is captured and decodes correctly. Bounded-input/ReDoS posture unchanged (input is 32 KB-capped upstream).
- **Files modified:** `packages/pipeline/src/agentos_pipeline/risk/normalize.py`
- **Commit:** (this plan's task commit)

**2. [Rule 3 - Blocking] Invisible smuggling chars / `tests` not importable**
- **Found during:** Task 1 (RED→GREEN wiring).
- **Issue (a):** The editor serialized intended `\u`-escapes as literal invisible codepoints on disk (the repo's PreToolUse injection hook correctly flags literal invisibles). **Fix:** declared the zero-width/bidi codepoints numerically (`chr()` over explicit `range`s) in `normalize.py`, and built the zero-width test probe via `chr(0x200B)` — source is now pure ASCII with zero literal invisibles (verified).
- **Issue (b):** `from tests.conftest import make_http_get` failed (`tests` is not a package; no `tests/__init__.py`, and the parametrize lists build `AgentAction`s at import time before fixtures resolve). **Fix:** added a module-local `make_http_get` helper mirroring the conftest one — keeps the test self-contained without making `tests` a package (which could affect sibling tests).
- **Files modified:** `packages/pipeline/src/agentos_pipeline/risk/normalize.py`, `tests/unit/test_detector_recall.py`

### Threat-model mitigations applied (Rule 2)

All `mitigate` dispositions in the plan's `<threat_model>` are implemented and tested:
- **T-01-08/09** (indirect/obfuscated injection): deterministic regex over **normalized** text; recall + evasion tested (D1/D3).
- **T-01-10** (ReDoS): bounded-quantifier patterns compiled once; 32 KB input cap with recorded truncation (D4 bounded-input).
- **T-01-11** (info disclosure): `matched` holds pattern IDs only (the `RiskFinding` validator from 01-01 rejects URL-like/long strings); no raw payload enters the finding.
- **T-01-12** (P0-killer LLM on hot path): stdlib-only, `inline=True`; import-guard asserts no model/network import (D4 purity).

## Known Stubs

None. The detector is fully wired; the only intentionally-deferred behaviors are the `strict=True` xfail probes (typoglycemia, sharded exfil), documented as out-of-Phase-1 scope (Phase-3 classifier).

## Authentication Gates

None.

## Self-Check: PASSED

- All created files exist on disk (normalize.py, prompt_injection.py, aggregator.py, pyproject.toml, test_detector_recall.py, 01-03-SUMMARY.md).
- Task commit `96e46ee` present in git log.
