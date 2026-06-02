# agentos-pipeline

The 4-stage decision pipeline (identity → policy → risk → graduated).

Phase 1 ships the **risk stage (SEC-01)**: a deterministic, `inline=True`
prompt-injection detector behind the `RiskScorer` Protocol.

- `risk/normalize.py` — NFKC fold + zero-width/bidi strip + opportunistic base64
  decode, run *before* matching (trivial-obfuscation mitigation, Pitfall 4).
- `risk/prompt_injection.py` — `PromptInjectionScorer`: stdlib `re` patterns
  compiled **once** at construction (bounded quantifiers, ReDoS-safe), returns a
  typed `RiskFinding`. No LLM, no model, no network on the hot path (P0-killer).
- `risk/aggregator.py` — `assess_risk` runs only `inline` scorers, max-pools
  `risk_score`, performs no I/O.

The detector is **advisory** — it can only *contribute* risk, never relax the
deterministic opa-wasm policy floor (POL-05 / TRST-02 invariant; enforced in the
graduated stage, plan 01-05).
