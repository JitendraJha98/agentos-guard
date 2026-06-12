# Phase 3 · Slice 4 — Guardrail Scorers, Tiering, Remediation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> Commits end with second `-m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"`.
> Tests: `./.venv/Scripts/python.exe -m pytest` from repo root. TDD per task.

**Goal:** Real PII / unsafe-content / format guardrails run inline (SEC-02), wired into BOTH the
enrichment flags (so principle 3.2's PII-egress deny actually fires — wedge A) and the risk
findings — without double-running. Explicit cheap-inline / expensive-flag-gated tiering (SEC-03)
with a proof test. Denials carry concrete `remediation` derived from authored principle hints
(PIPE-08).

**Architecture:** Three new `RiskScorer`-protocol scorers in `agentos_pipeline/risk/` (stdlib
`re` compiled once, ReDoS-safe bounded patterns, 32 KB cap, pattern-IDs-only findings — exactly
the `PromptInjectionScorer` house style). `enrich()` runs them ONCE; `Enrichment` carries the
findings + real flags; the aggregator merges them into stage-4 risk (no re-run) and gains the
expensive-scorer gate. The Constitution `Principle` schema gains an optional authored
`remediation: list[str]`; the runner derives `Decision.remediation` on restrictive outcomes.

**Requirements:** SEC-02, SEC-03, PIPE-08 (remediation).

---

## Locked decisions

- **Scores stay advisory-calibrated:** PII alone = 0.35 (below the 0.4 sandbox band — PII to an
  *allowlisted* host stays `allow`; the 3.2 *floor* does the denying when the host isn't
  approved). Unsafe content = 0.45 (sandbox band). Format violations = 0.2.
- **Credit-card matches are Luhn-verified** (kills 16-digit false positives). `matched` carries
  ids only (`email`, `ssn`, `credit_card`, `phone`, `destructive_shell`, …) — never raw text.
- **Guardrails run once, in `enrich()`** (pre-policy, pure CPU); stage 4 consumes the carried
  findings via a new `extra_findings` aggregator param. The `scorers` list passed to `Pipeline`
  keeps only `PromptInjectionScorer` + `IntentScorer`.
- **Expensive tier is a real seam, no fake model:** `inline=False` scorers run ONLY when the
  inline pass produced at least one finding with `matched` non-empty. Proven by a counting stub.
- **Remediation is authored-first:** principle authors write hints (schema `remediation`,
  ≤5 items × ≤256 chars); the runner concatenates fired principles' hints (dedup, cap 10) and
  falls back per-outcome when none authored (`deny` → "Review principle {ref} — {title}";
  `require_approval` → "Await operator resolution of the parked approval request").
  Derived only when the final outcome is restrictive (`OUTCOME_RESTRICTIVENESS` rank ≥ sandbox).
- **Goldens regenerate** (the schema gains a field → canonical dump → version hashes change).
  Regenerate ONCE, manually inspect the diff (only `remediation:` additions + new hash headers),
  recommit.

## File structure

- Modify: `packages/contract/src/agentos_contract/risk.py` (category Literal +3, additive)
- Create: `packages/pipeline/src/agentos_pipeline/risk/{_text.py, pii.py, unsafe_content.py, format_check.py}`
- Modify: `risk/__init__.py`, `risk/aggregator.py`, `enrichment.py`, `runner.py`
- Modify: `packages/constitution/src/agentos_constitution/{schema.py, compiler.py}`
- Modify: `tests/_opa.py` (meta gains remediation), `tests/fixtures/test_constitution.yaml`
  (+ remediation on 1.1/2.1), `policies/constitution.yaml` (+ remediation on 1.1/3.2),
  goldens regenerated
- Tests: new `tests/unit/test_guardrail_scorers.py`, `test_risk_tiering.py`; additions to
  `test_enrichment.py`, `test_pipeline.py`, `test_constitution_schema.py`, `test_constitution_compiler.py`

---

### Task 1: Contract — widen `RiskFinding.category` (additive)

- [ ] Failing test (`tests/unit/test_contract.py` append): construct `RiskFinding` with each of
  `"pii"`, `"unsafe_content"`, `"format_violation"` → valid; `"bogus"` → ValidationError.
- [ ] Implement: extend the Literal in `risk.py` line 24 with the three new members. Nothing else.
- [ ] Green; commit `feat(contract): guardrail finding categories pii/unsafe_content/format_violation (SEC-02)`.

### Task 2: PII scorer

**Files:** create `risk/_text.py` + `risk/pii.py`; test `tests/unit/test_guardrail_scorers.py`.

- [ ] Failing tests:

```python
def _tool(payload):  # helper used across this file
    return AgentAction(agent_id="a", type=ActionType.tool_call, target="http_post", payload=payload)

def test_email_detected():
    f = PiiScorer().score(_tool({"content": "contact: jane.doe@example.com"}))
    assert f.category == "pii" and "email" in f.matched and f.risk_score == 0.35

def test_ssn_detected():
    assert "ssn" in PiiScorer().score(_tool({"content": "ssn 123-45-6789"})).matched

def test_credit_card_requires_luhn():
    assert "credit_card" in PiiScorer().score(_tool({"content": "4111 1111 1111 1111"})).matched   # Luhn-valid
    assert "credit_card" not in PiiScorer().score(_tool({"content": "1234 5678 9012 3456"})).matched  # Luhn-invalid

def test_phone_e164_detected():
    assert "phone" in PiiScorer().score(_tool({"content": "+14155550123"})).matched

def test_clean_payload_scores_zero():
    f = PiiScorer().score(_tool({"content": "the weather is nice"}))
    assert f.risk_score == 0.0 and f.matched == []

def test_matched_never_carries_raw_values():
    f = PiiScorer().score(_tool({"content": "jane.doe@example.com 123-45-6789"}))
    assert all(m in {"email", "ssn", "credit_card", "phone"} for m in f.matched)
```

- [ ] Implement `_text.py`: `payload_text(action, cap=32*1024) -> str` — join `str(v)` over
  payload values, truncate at cap (the same surface `PromptInjectionScorer._inspect_text` scans;
  NO normalize() here — PII patterns match raw text; document why). Implement `pii.py`:
  `PiiScorer` (`name="pii.v1"`, `inline=True`), patterns compiled once: email
  `[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}`; ssn `\b\d{3}-\d{2}-\d{4}\b`;
  card candidates `\b(?:\d[ -]?){13,19}\b` each Luhn-checked (strip spaces/dashes, standard
  Luhn); phone `\+\d{7,15}\b` or `\(\d{3}\)\s?\d{3}-\d{4}`. `risk_score=0.35 if matched else 0.0`.
- [ ] Green; commit `feat(pipeline): inline deterministic PII scorer with Luhn-verified cards (SEC-02)`.

### Task 3: Unsafe-content + format scorers

**Files:** create `risk/unsafe_content.py`, `risk/format_check.py`; same test file.

- [ ] Failing tests: `rm -rf /` → `destructive_shell` @ 0.45; `DROP TABLE users` (inside payload
  *content*, not the target) → `destructive_sql`; `:(){ :|:& };:` → `fork_bomb`;
  `Remove-Item -Recurse -Force` → `destructive_shell`; clean → 0.0/[].
  Format: a payload value containing `\x00` → `control_chars` @ 0.2; a single value > 32 KB →
  `oversized_value`; payload nested deeper than 8 levels → `excessive_nesting`; clean → 0.0.
- [ ] Implement `UnsafeContentScorer` (`unsafe_content.v1`, patterns: `rm\s+-[rf]{1,4}\b`,
  `\bdrop\s+table\b` / `\btruncate\s+table\b` (IGNORECASE), the literal fork bomb,
  `remove-item\s+.{0,40}-recurse` (IGNORECASE), `\bmkfs\b`, `\bdd\s+if=`); and
  `FormatViolationScorer` (`format.v1`: C0 control chars excluding `\t\n\r` in any string value;
  single value len > 32_768; dict/list nesting depth > 8 via iterative walk).
- [ ] Green; commit `feat(pipeline): unsafe-content + format-violation inline scorers (SEC-02)`.

### Task 4: Enrichment wiring + aggregator merge (3.2 fires end-to-end)

**Files:** `enrichment.py`, `risk/aggregator.py`, `runner.py`; tests in `test_enrichment.py` +
`test_pipeline.py`.

- [ ] Failing tests:

```python
# enrichment
def test_pii_payload_sets_flag_and_carries_finding():
    e = enrich(_tool({"content": "mail jane.doe@example.com"}))
    assert e.guardrails["pii"] is True
    assert any(f.category == "pii" for f in e.guardrail_findings)

def test_clean_payload_all_flags_false():
    e = enrich(_tool({"content": "hello"}))
    assert e.guardrails == {"pii": False, "unsafe": False, "format": False}
    assert all(not f.matched for f in e.guardrail_findings)

# pipeline e2e (real constitution engine fixture, like the Slice-3 intent test)
async def test_pii_to_unlisted_host_denied_by_principle_3_2(...):
    # payload url -> attacker.example + content with an email
    # -> guardrails.pii True -> 3.2 fires -> outcome deny, a policy Reason with principle_ref "3.2"
    # (1.1 also fires on the unlisted host - both refs present)

async def test_pii_to_allowlisted_host_stays_allow(...):
    # email + api.example.com -> 3.2 cannot fire (host approved), pii risk 0.35 < 0.4 -> allow
    # AND the pii finding appears in decision.reasons (stage "risk", code "pii")
```

- [ ] Implement: `Enrichment` gains `guardrail_findings: tuple[RiskFinding, ...] = ()`;
  `enrich()` runs the three scorers, derives flags
  (`pii=any(f.category=="pii" and f.matched ...)`, `unsafe` ← `unsafe_content`, `format` ←
  `format_violation`); update the module docstring (the seam is now REAL).
  `assess_risk(action, scorers, extra_findings=())` — findings = inline scorer results +
  extra_findings; max-pool over the union. `runner.py` stage 4 passes
  `extra_findings=enrichment.guardrail_findings`.
- [ ] Green (the e2e tests prove SEC-02 feeds policy); commit
  `feat(pipeline): guardrails wired into enrichment flags + risk findings — principle 3.2 live (SEC-02)`.

### Task 5: Expensive-scorer tiering gate (SEC-03)

**Files:** `risk/aggregator.py`, `runner.py`; test `tests/unit/test_risk_tiering.py`.

- [ ] Failing tests: a `CountingExpensiveScorer` (`inline=False`, counts `.score()` calls,
  returns a 0.6 finding): (a) benign action (no inline matches) → expensive NOT called, count 0;
  (b) flagged action (PII present) → called once, its finding in the result, max-pool includes
  0.6; (c) expensive scorers NEVER run when `expensive_scorers=()` (default).
- [ ] Implement: `assess_risk(action, scorers, extra_findings=(), expensive_scorers=())` —
  after the inline pass, `if any(f.matched for f in findings): findings += [s.score(action) for
  s in expensive_scorers if not s.inline]`. `Pipeline.__init__` gains
  `expensive_scorers: list[RiskScorer] = []` passed through. Docstring: SEC-03 — expensive
  detectors only on inline flags, never unconditionally (Pitfall 1).
- [ ] Green; commit `feat(pipeline): flag-gated expensive-scorer tier (SEC-03)`.

### Task 6: Authored remediation in the Constitution

**Files:** `packages/constitution/src/agentos_constitution/{schema.py, compiler.py}`,
`tests/_opa.py`, fixture + example constitutions, goldens.

- [ ] Failing tests: schema accepts `remediation: ["Add the host to egress_allowlist"]` on a
  principle (≤5 items, each ≤256 chars; 6 items → ValidationError; 300-char item →
  ValidationError); compiled `yaml_policy` carries it; `build_constitution_wasm(...)
  .principles_meta["1.1"]["remediation"]` round-trips.
- [ ] Implement: `Principle.remediation: list[str] = Field(default_factory=list, max_length=5)`
  + per-item 256 validator; compiler includes it in the per-principle yaml_policy doc (Rego
  UNCHANGED — remediation is metadata, not enforcement); `tests/_opa.py` meta dict gains
  `"remediation": p.remediation`. Add remediation lines to `tests/fixtures/test_constitution.yaml`
  (1.1: "Add the destination host to the egress_allowlist list and re-apply the constitution.";
  2.1: "Request operator approval, or use a non-destructive alternative.") and
  `policies/constitution.yaml` (1.1 + 3.2 sensible hints). `test_constitution_no_egress.yaml`:
  add the same 2.1 hint (keep the two fixtures differing ONLY by 1.1).
- [ ] Regenerate goldens once (schema change → new version hashes), inspect the diff is ONLY
  remediation additions + hash headers, recommit. All constitution tests green.
- [ ] Commit `feat(constitution): authored per-principle remediation hints (PIPE-08)`.

### Task 7: Runner derives `Decision.remediation`

**Files:** `runner.py`; tests in `test_pipeline.py`.

- [ ] Failing tests: (a) unlisted-host deny → `decision.remediation` contains 1.1's authored
  hint; (b) destructive-intent require_approval → remediation == 2.1's authored hint (authored
  wins over fallback); (c) a deny whose fired principle has NO authored remediation (use a stub
  engine + meta without remediation) → fallback `"Review principle {ref} — {title}"`;
  (d) plain allow → `remediation == []`.
- [ ] Implement in `runner.py` after the graduated outcome: if
  `OUTCOME_RESTRICTIVENESS[outcome] >= OUTCOME_RESTRICTIVENESS[Outcome.sandbox]`: collect
  authored hints from fired principles via the non-throwing meta access (dedup, preserve order,
  cap 10); if empty → per-outcome fallback (`require_approval` → await-operator line; else →
  per-fired-principle review line; engine failure paths keep `remediation=[]`). Set on the
  Decision before audit append (it's hash-covered).
- [ ] Green; commit `feat(pipeline): explainable denials carry concrete remediation (PIPE-08)`.

### Task 8: Full gate

- [ ] `pytest -q` fully green (~690 expected); `-m floor_invariant` 430; `-m regression_lock` 10;
  `-m latency` still under ceiling (three more inline regex passes — confirm mean stays single-
  digit ms; report the number).
- [ ] Commit only if fixes were needed.

## Self-review checklist
SEC-02 (3 scorers + flags + risk merge + 3.2 e2e) / SEC-03 (gate + proof) / PIPE-08 (authored +
fallback remediation, restrictive-only) / no double-run (guardrails only in enrich) / goldens
inspected / `matched` never carries raw text / floor & regression gates untouched.
