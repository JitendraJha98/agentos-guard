# Phase 3 · Slice 7 — Sequence-Intent Correlator + Wedge Demo (SEC-13)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> Commits: second `-m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD. Gates `floor_invariant` (430) + `regression_lock`
> (10) green at every commit.

**Goal:** Multi-step evasions (`rename_then_drop`) that no single action reveals are caught by a
deterministic, windowed sequence-intent correlator over conversation/lineage, feeding the
compiled constitution's sequence principles (Slice 2's `input.sequence.matched_refs` membership
rules) — and proven by a scripted wedge demo where **each action is individually allowed but the
sequence is denied with a cited principle and remediation** (ROADMAP Phase 3 success criterion 5).

**Requirements:** SEC-13.

## Locked design
- **`SequenceCorrelator`** (`packages/pipeline/src/agentos_pipeline/sequence.py`): in-process,
  bounded, deterministic, pure CPU. State: `OrderedDict[key, deque(maxlen=window)]` of OBSERVED
  intent classes (untagged actions are NOT appended — they don't break a sequence); key =
  `action.context.conversation_id or action.agent_id`; max_conversations=1024 FIFO evict;
  window=8. `observe(key, intent_class, sequences) -> tuple[str, ...]`: for each declared
  sequence `{principle_ref, intent_classes, effect}`, match iff `intent_classes` is an **ordered
  subsequence** of (window + current class) ENDING at the current class (the current action is
  the one being gated); append the current class to the window AFTER matching. Returns matched
  refs sorted. Untagged (`None`) class → no match, no append, return ().
- **Pipeline integration:** `Pipeline(sequences: list[dict] | None = None, correlator:
  SequenceCorrelator | None = None)` — when sequences given and correlator None, construct one.
  In `_evaluate` after `enrich`: `matched_refs = correlator.observe(key, e.intent_class,
  self._sequences)` (empty when unwired). `build_policy_input(action, enrichment,
  sequence_matched_refs=())` gains the additive keyword and emits it as
  `sequence.matched_refs` (registry path unchanged — the Slice-3 drift test must keep passing).
  The compiled WASM membership rule (e.g. 3.5) then fires as a REAL deterministic floor —
  citation + remediation flow through the existing matched-principle machinery. Conftest wires
  `sequences=built.bundle.sequences` into `pipeline_with_principle` (the bundle already carries
  them since Slice 2).
- **State honesty:** correlator state is in-process and unbounded-time (no TTL) — document in the
  module docstring (Phase 7 reconcilers own distributed/persistent state; D-14 single-process).
- **Remediation:** add an authored `remediation` line to principle 3.5 in
  `tests/fixtures/test_constitution.yaml` AND `policies/constitution.yaml` (e.g. "Request an
  operator-approved temporary exception, or perform the rename and destruction as separately
  approved operations."). Do NOT touch `tests/golden/` fixtures.
- **Wedge demo:** `examples/wedge_constitution.yaml` (principles 1.1 egress-allowlist + 3.5
  sequence ONLY — so destruction alone is individually ALLOWED) + `examples/wedge_demo.py`: a
  scripted, runnable narrative (compile constitution → wire pipeline+SQLite → register agent →
  (1) `drop_table` alone → ALLOW [individually permitted]; (2) `rename_table` → ALLOW; (3)
  `drop_table` (same conversation) → **DENY citing principle 3.5** with statement + remediation
  printed; (4) prints the audit-chain tail proving evidence). Exit code 0; runtime well under
  5 minutes; `examples/README.md` two-liner.

## Tasks
### 7-1: correlator
Tests (`tests/unit/test_sequence_correlator.py`): rename→drop matches 3.5; drop alone → ();
rename→(untagged http_get)→drop still matches (untagged skipped, not sequence-breaking);
drop→rename (wrong order) → (); two conversations isolated; window eviction (rename pushed out
by >window tagged actions → no match); max_conversations FIFO bound; deterministic given same
inputs; sorted multi-match. **Commit** `feat(pipeline): bounded windowed sequence-intent correlator (SEC-13)`.
### 7-2: pipeline integration (the SEC-13 floor proof)
Tests (`tests/unit/test_pipeline.py` additions, real constitution engine fixture): same
conversation `rename_table` then `drop_table` → second decision outcome from 3.5's effect (deny)
with a policy Reason `principle_ref == "3.5"` AND remediation carrying 3.5's authored hint;
`drop_table` first action of a fresh conversation → 3.5 does NOT fire (2.1 still does —
require_approval — that's fine and asserted); unwired pipeline (no sequences) → unchanged
behavior; drift test still green. **Commit** `feat(pipeline): sequence matches feed the constitution floor via input.sequence.matched_refs (SEC-13)`.
### 7-3: wedge demo
`tests/integration/test_wedge_demo.py`: runs the demo flow programmatically (drop-alone ALLOW,
rename ALLOW, drop-after-rename DENY citing 3.5 + remediation + audited) AND
`subprocess`-executes `examples/wedge_demo.py` asserting exit 0 + "3.5" in stdout (skipif no
OPA). **Commit** `feat(examples): rename_then_drop wedge demo — individually allowed, sequence denied (SEC-13)`.
### 7-4: final gate
Full suite green; floor_invariant 430; regression_lock 10; latency gate green (correlator adds
sub-ms dict ops; confirm). Report counts.

## Self-review
SEC-13 (ordered-subsequence over lineage window, conversation-scoped, deterministic, feeds the
REAL policy floor with citation+remediation) / wedge criterion (each action individually allowed
in the demo constitution; sequence denied; scripted+tested) / bounded state documented / no
golden churn / additive signatures only.
