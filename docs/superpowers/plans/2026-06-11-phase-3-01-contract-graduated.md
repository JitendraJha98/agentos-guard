# Phase 3 · Slice 1 — Contract & Graduated-Response Vocabulary — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to
> implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
> **Commit convention:** every commit ends with a `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
> trailer (pass it as a second `-m`). Run tests from the repo root with the workspace venv.

**Goal:** Extend the stable `contract` package for Phase 3's full graduated spectrum + explainable
denials, and teach the `graduated` stage to map the spectrum while strictly preserving the
floor invariant (risk/trust may only RESTRICT, never relax, the policy floor).

**Architecture:** Pure changes to `agentos-contract` (the serializable boundary) and
`agentos-pipeline/graduated.py` (the terminal stage). No external dependencies, no I/O. The
`Decision`/`Reason` get their full Phase-3 shape now (some fields populated by later slices);
`graduated_response` gains policy-driven thresholds + a conservative trust band, and a
restrictiveness-ladder clamp that can never drop below the policy floor.

**Tech Stack:** Python 3.12, Pydantic v2 (`extra="forbid"`), `@dataclass(frozen=True)`, pytest.

**Requirements covered:** PIPE-08 (Decision/Reason shape), PIPE-09 (`side_effects`), POL-13/POL-14
(outcome vocabulary), TRST-02 (trust band), SEC-12 (`inferred_intent` field).

---

## Key design decisions (locked)

- **Trust band is hardening-only by default.** `trust <= trust_harden_at` tightens the risk
  outcome by one ladder step; high trust is the neutral baseline. Trust **never** relaxes a risk
  outcome (defends Pitfall 10 trust-farming) and never crosses the policy floor. Softening is a
  future, opt-in threshold — not in this slice. *This keeps every existing `test_graduated.py`
  band test green; only the floor-invariant tests are extended.*
- **Rich outcomes come from the policy floor, not risk thresholds.** Risk alone produces only
  `{allow, sandbox, deny}` (unchanged from Phase 1). `warn / require_approval / require_consensus /
  governance_review / temporary_exception` arrive as `policy_outcome` (principle effects, Slice 2/3)
  or from the approval workflow (Slice 6). `graduated_response` clamps the result to be **at least
  as restrictive** as `policy_outcome` via a restrictiveness ladder.
- **New `Decision` fields are nullable/empty now**, populated by later slices: `constitution_version`
  /`policy_version` (Slice 3), `inferred_intent`/`remediation` (Slice 4), `expires_at` (Slice 6).
  Adding them to the contract now keeps the serializable boundary stable across the phase.

## File structure

- Modify `packages/contract/src/agentos_contract/decision.py` — `Outcome` (+2), new `SideEffect`,
  enriched `Reason`, extended `Decision`.
- Modify `packages/contract/src/agentos_contract/__init__.py` — export `SideEffect`.
- Modify `packages/pipeline/src/agentos_pipeline/graduated.py` — `GraduatedThresholds`,
  restrictiveness ladder, trust band, new `graduated_response`.
- Modify `tests/unit/test_contract.py` — round-trip + `extra="forbid"` for the new fields.
- Modify `tests/unit/test_graduated.py` — keep floor-invariant tests, extend the sweep to the full
  spectrum, add trust-band + policy-floor-clamp tests.

---

### Task 1: Outcome spectrum + SideEffect enum

**Files:**
- Modify: `packages/contract/src/agentos_contract/decision.py`
- Modify: `packages/contract/src/agentos_contract/__init__.py`
- Test: `tests/unit/test_contract.py`

- [ ] **Step 1: Write the failing test** (append to `tests/unit/test_contract.py`)

```python
from agentos_contract import SideEffect  # add to the existing import block


def test_outcome_has_full_phase3_spectrum():
    names = {o.value for o in Outcome}
    assert names == {
        "allow", "warn", "sandbox", "require_consensus",
        "require_approval", "temporary_exception", "governance_review", "deny",
    }


def test_side_effect_members():
    assert {s.value for s in SideEffect} == {
        "notify", "additional_monitoring", "risk_flag", "create_incident",
    }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_contract.py::test_outcome_has_full_phase3_spectrum tests/unit/test_contract.py::test_side_effect_members -v`
Expected: FAIL — `ImportError: cannot import name 'SideEffect'` / spectrum mismatch.

- [ ] **Step 3: Implement** — in `decision.py` add two `Outcome` members and the `SideEffect` enum

In `class Outcome`, insert before `deny`:
```python
    temporary_exception = "temporary_exception"   # POL-13 — human-ratified, time-boxed allow
    governance_review = "governance_review"        # POL-14 — proceed + async non-blocking review
```
After `class Outcome`, add:
```python
class SideEffect(str, Enum):
    """Composable, outcome-orthogonal escalations (PIPE-09). A Decision may carry any subset."""
    notify = "notify"
    additional_monitoring = "additional_monitoring"
    risk_flag = "risk_flag"
    create_incident = "create_incident"
```
In `__init__.py`, add `SideEffect` to the `from agentos_contract.decision import ...` line and to `__all__`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_contract.py -v`
Expected: PASS (new + all existing contract tests).

- [ ] **Step 5: Commit**

```bash
git add packages/contract/src/agentos_contract/decision.py packages/contract/src/agentos_contract/__init__.py tests/unit/test_contract.py
git commit -m "feat(contract): add temporary_exception/governance_review outcomes + SideEffect (POL-13/14, PIPE-09)" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Explainable-denial fields on Reason

**Files:**
- Modify: `packages/contract/src/agentos_contract/decision.py`
- Test: `tests/unit/test_contract.py`

- [ ] **Step 1: Write the failing test**

```python
def test_reason_carries_explainable_denial_fields():
    r = Reason(
        stage="policy", code="pii_egress_violation", detail="PII to non-allowlisted host",
        policy_id="constitution.3_2", principle_ref="3.2",
        rationale="Principle 3.2 forbids sending user PII to unapproved hosts.",
        evidence={"matched": "email_address", "host": "attacker.example"},
    )
    restored = Reason.model_validate_json(r.model_dump_json())
    assert restored == r
    assert restored.principle_ref == "3.2"
    assert restored.evidence == {"matched": "email_address", "host": "attacker.example"}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_contract.py::test_reason_carries_explainable_denial_fields -v`
Expected: FAIL — `Reason` has no `principle_ref`/`rationale`/`evidence` (extra="forbid" on the model rejects them).

- [ ] **Step 3: Implement** — extend `class Reason` in `decision.py`

Add three fields after `policy_id`:
```python
    principle_ref: str | None = None   # constitution principle id (e.g. "3.2") — PIPE-08
    rationale: str = ""                # short human rationale — PIPE-08 (NEVER raw payload)
    evidence: dict | None = None       # small structured evidence — PIPE-08
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_contract.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/contract/src/agentos_contract/decision.py tests/unit/test_contract.py
git commit -m "feat(contract): Reason carries {principle_ref, rationale, evidence} (PIPE-08)" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Extended Decision shape

**Files:**
- Modify: `packages/contract/src/agentos_contract/decision.py`
- Test: `tests/unit/test_contract.py`

- [ ] **Step 1: Write the failing test**

```python
from datetime import datetime, timezone


def test_decision_full_phase3_shape_roundtrip():
    d = Decision(
        action_id="11111111-1111-1111-1111-111111111111",
        outcome=Outcome.temporary_exception,
        side_effects=[SideEffect.notify, SideEffect.additional_monitoring],
        inferred_intent="DATA_DESTRUCTION",
        remediation=["Request approval via the dashboard", "Narrow the tool scope"],
        constitution_version="sha256:abc",
        policy_version="sha256:def",
        expires_at=datetime(2026, 6, 11, 12, 0, tzinfo=timezone.utc),
    )
    restored = Decision.model_validate_json(d.model_dump_json())
    assert restored == d
    assert restored.side_effects == [SideEffect.notify, SideEffect.additional_monitoring]
    assert restored.inferred_intent == "DATA_DESTRUCTION"


def test_decision_defaults_are_empty_and_still_forbid_unknown():
    d = Decision(action_id="11111111-1111-1111-1111-111111111111", outcome=Outcome.allow)
    assert d.side_effects == [] and d.remediation == []
    assert d.inferred_intent is None and d.policy_version is None and d.expires_at is None
    with pytest.raises(ValidationError):
        Decision(action_id="11111111-1111-1111-1111-111111111111", outcome=Outcome.allow, mystery=1)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_contract.py::test_decision_full_phase3_shape_roundtrip tests/unit/test_contract.py::test_decision_defaults_are_empty_and_still_forbid_unknown -v`
Expected: FAIL — `Decision` has no `side_effects`/`inferred_intent`/etc.

- [ ] **Step 3: Implement** — extend `class Decision` and add the `datetime` import

At the top of `decision.py`, change `from datetime import ...` (add it):
```python
from datetime import datetime
```
Add fields to `Decision` (after `reasons`, before `evidence_ref`):
```python
    side_effects: list[SideEffect] = Field(default_factory=list)   # PIPE-09
    inferred_intent: str | None = None                             # SEC-12 coarse intent class
    remediation: list[str] = Field(default_factory=list)           # PIPE-08 next steps
    constitution_version: str | None = None                        # POL-08 (populated Slice 3)
    policy_version: str | None = None                              # POL-08 (populated Slice 3)
    expires_at: datetime | None = None                             # POL-13 temporary_exception expiry
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_contract.py -v`
Expected: PASS (incl. existing `test_decision_json_roundtrip_preserves_reasons`, which uses defaults).

- [ ] **Step 5: Commit**

```bash
git add packages/contract/src/agentos_contract/decision.py tests/unit/test_contract.py
git commit -m "feat(contract): Decision carries side_effects/intent/remediation/version/expires_at (PIPE-08/09, POL-08/13, SEC-12)" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: GraduatedThresholds + restrictiveness ladder + risk→outcome

**Files:**
- Modify: `packages/pipeline/src/agentos_pipeline/graduated.py`
- Test: `tests/unit/test_graduated.py`

- [ ] **Step 1: Write the failing test** (append to `tests/unit/test_graduated.py`)

```python
from agentos_pipeline.graduated import GraduatedThresholds, _more_restrictive, _risk_to_outcome


def test_risk_to_outcome_default_bands():
    t = GraduatedThresholds()
    assert _risk_to_outcome(0.0, t) is Outcome.allow
    assert _risk_to_outcome(0.39, t) is Outcome.allow
    assert _risk_to_outcome(0.4, t) is Outcome.sandbox
    assert _risk_to_outcome(0.69, t) is Outcome.sandbox
    assert _risk_to_outcome(0.7, t) is Outcome.deny


def test_more_restrictive_picks_higher_rank():
    assert _more_restrictive(Outcome.allow, Outcome.require_approval) is Outcome.require_approval
    assert _more_restrictive(Outcome.deny, Outcome.sandbox) is Outcome.deny
    assert _more_restrictive(Outcome.warn, Outcome.allow) is Outcome.warn
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_graduated.py::test_risk_to_outcome_default_bands tests/unit/test_graduated.py::test_more_restrictive_picks_higher_rank -v`
Expected: FAIL — `cannot import name 'GraduatedThresholds'`.

- [ ] **Step 3: Implement** — rewrite the top of `graduated.py` (keep the module docstring; replace the threshold constants + add the ladder). Replace the `_DENY_THRESHOLD`/`_SANDBOX_THRESHOLD` block with:

```python
from __future__ import annotations

from dataclasses import dataclass

from agentos_contract import Outcome


@dataclass(frozen=True)
class GraduatedThresholds:
    """Policy-driven graduated thresholds (POL-06). Defaults preserve the Phase-1 risk
    bands (sandbox at 0.4, deny at 0.7) and realize the TRST-02 trust band as
    conservative hardening-only (low trust tightens; trust never relaxes risk)."""

    sandbox_at: float = 0.4
    deny_at: float = 0.7
    trust_harden_at: float = 0.2   # trust <= this -> tighten one risk step (TRST-02, conservative)


# Restrictiveness ladder for the floor clamp (higher = more restrictive). The graduated
# stage NEVER returns a result less restrictive than the policy floor.
_RANK: dict[Outcome, int] = {
    Outcome.allow: 0,
    Outcome.warn: 1,
    Outcome.governance_review: 2,
    Outcome.temporary_exception: 2,
    Outcome.sandbox: 3,
    Outcome.require_consensus: 4,
    Outcome.require_approval: 5,
    Outcome.deny: 6,
}
# The subset risk alone can produce, ordered least->most restrictive (for trust stepping).
_RISK_LADDER = [Outcome.allow, Outcome.sandbox, Outcome.deny]


def _more_restrictive(a: Outcome, b: Outcome) -> Outcome:
    return a if _RANK[a] >= _RANK[b] else b


def _risk_to_outcome(risk_score: float, t: GraduatedThresholds) -> Outcome:
    if risk_score >= t.deny_at:
        return Outcome.deny
    if risk_score >= t.sandbox_at:
        return Outcome.sandbox
    return Outcome.allow
```

(The existing `graduated_response` function below this block is rewritten in Task 5.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_graduated.py::test_risk_to_outcome_default_bands tests/unit/test_graduated.py::test_more_restrictive_picks_higher_rank -v`
Expected: PASS. (The old `graduated_response` tests may transiently fail until Task 5 — that is expected; proceed.)

- [ ] **Step 5: Commit**

```bash
git add packages/pipeline/src/agentos_pipeline/graduated.py tests/unit/test_graduated.py
git commit -m "feat(pipeline): GraduatedThresholds + restrictiveness ladder for the full spectrum (POL-06)" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: Trust band + new graduated_response (floor-preserving)

**Files:**
- Modify: `packages/pipeline/src/agentos_pipeline/graduated.py`
- Test: `tests/unit/test_graduated.py`

- [ ] **Step 1: Write the failing test**

```python
def test_low_trust_hardens_within_band():
    # trust <= 0.2 tightens the risk outcome one step; never below floor, never relaxes.
    assert graduated_response(Outcome.allow, risk_score=0.45, trust=0.1) is Outcome.deny     # sandbox -> deny
    assert graduated_response(Outcome.allow, risk_score=0.0, trust=0.1) is Outcome.sandbox   # allow -> sandbox


def test_high_trust_is_neutral_baseline():
    # high trust does NOT relax risk (conservative hardening-only band).
    assert graduated_response(Outcome.allow, risk_score=0.45, trust=1.0) is Outcome.sandbox
    assert graduated_response(Outcome.allow, risk_score=0.0, trust=1.0) is Outcome.allow


def test_policy_floor_is_a_lower_bound():
    # A principle effect of require_approval is never relaxed by low risk/high trust.
    assert graduated_response(Outcome.require_approval, risk_score=0.0, trust=1.0) is Outcome.require_approval
    # ...but risk can still escalate ABOVE the floor.
    assert graduated_response(Outcome.sandbox, risk_score=0.8, trust=1.0) is Outcome.deny
    assert graduated_response(Outcome.warn, risk_score=0.0, trust=1.0) is Outcome.warn
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python -m pytest tests/unit/test_graduated.py::test_low_trust_hardens_within_band tests/unit/test_graduated.py::test_policy_floor_is_a_lower_bound -v`
Expected: FAIL — old `graduated_response` ignores thresholds/floor clamp.

- [ ] **Step 3: Implement** — replace the existing `graduated_response` function body with:

```python
def _apply_trust_band(base: Outcome, trust: float, t: GraduatedThresholds) -> Outcome:
    """TRST-02: trust modulates WITHIN a band. Conservative default = hardening-only —
    low trust (<= trust_harden_at) tightens the risk outcome by one ladder step; trust
    NEVER relaxes (defends Pitfall 10 trust-farming) and never crosses the deny ceiling."""
    if trust <= t.trust_harden_at and base in _RISK_LADDER:
        i = _RISK_LADDER.index(base)
        return _RISK_LADDER[min(i + 1, len(_RISK_LADDER) - 1)]
    return base


def graduated_response(
    policy_outcome: Outcome,
    risk_score: float,
    trust: float,
    thresholds: GraduatedThresholds = GraduatedThresholds(),
) -> Outcome:
    """Map {policy, risk, trust} to one outcome, never relaxing the policy floor.

    INVARIANT (POL-05/TRST-02): the result is never LESS restrictive than
    `policy_outcome`; a policy `deny` is terminal; risk/trust may only RESTRICT.
    """
    if policy_outcome == Outcome.deny:
        return Outcome.deny  # terminal floor (POL-05)
    risk_outcome = _apply_trust_band(_risk_to_outcome(risk_score, thresholds), trust, thresholds)
    return _more_restrictive(policy_outcome, risk_outcome)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/unit/test_graduated.py -v`
Expected: PASS — the new tests AND every pre-existing band/floor test in the file (defaults preserve the Phase-1 bands; high trust is neutral).

- [ ] **Step 5: Commit**

```bash
git add packages/pipeline/src/agentos_pipeline/graduated.py tests/unit/test_graduated.py
git commit -m "feat(pipeline): floor-preserving graduated_response with conservative trust band (TRST-02)" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Extend the floor-invariant property sweep to the full spectrum

**Files:**
- Modify: `tests/unit/test_graduated.py`

- [ ] **Step 1: Write the failing test**

```python
from agentos_pipeline.graduated import _RANK

_ALL_RISK = [0.0, 0.1, 0.39, 0.4, 0.6, 0.69, 0.7, 0.99, 1.0]
_ALL_TRUST = [0.0, 0.2, 0.25, 0.5, 0.75, 1.0]


@pytest.mark.floor_invariant
@pytest.mark.parametrize("floor", [
    Outcome.allow, Outcome.warn, Outcome.sandbox,
    Outcome.require_consensus, Outcome.require_approval,
])
@pytest.mark.parametrize("risk", _ALL_RISK)
@pytest.mark.parametrize("trust", _ALL_TRUST)
def test_result_never_less_restrictive_than_policy_floor(floor, risk, trust):
    # For ANY (risk, trust) and ANY policy floor, the result rank is >= the floor rank.
    result = graduated_response(floor, risk_score=risk, trust=trust)
    assert _RANK[result] >= _RANK[floor]


@pytest.mark.floor_invariant
@pytest.mark.parametrize("trust", _ALL_TRUST)
def test_more_risk_is_monotonically_non_relaxing(trust):
    # Fix trust; increasing risk never produces a LESS restrictive outcome.
    ranks = [_RANK[graduated_response(Outcome.allow, risk_score=r, trust=trust)] for r in _ALL_RISK]
    assert ranks == sorted(ranks)
```

- [ ] **Step 2: Run it to verify it fails or passes**

Run: `python -m pytest tests/unit/test_graduated.py -m floor_invariant -v`
Expected: PASS (the implementation already satisfies these — this test *locks* the invariant). If any case FAILS, STOP: the graduated logic violates the floor and must be fixed before proceeding.

- [ ] **Step 3: (No impl change expected.)** If Step 2 passed, skip. If it failed, fix `graduated_response` so the floor clamp / monotonicity holds, then re-run.

- [ ] **Step 4: Run the whole unit suite to confirm no regressions**

Run: `python -m pytest tests/unit -q`
Expected: PASS (all unit tests).

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_graduated.py
git commit -m "test(pipeline): lock floor invariant across the full graduated spectrum (POL-05/TRST-02)" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Full-suite regression gate

**Files:** none (verification only)

- [ ] **Step 1: Run the entire test suite**

Run: `python -m pytest -q`
Expected: PASS — contract + pipeline + integration + redteam suites all green. The Phase-1/2
end-to-end and red-team tests must remain green (the contract additions are backward-compatible:
new `Decision`/`Reason` fields default to empty/None; `graduated_response`'s new `thresholds`
param defaults to the Phase-1 bands).

- [ ] **Step 2: If anything is red**, diagnose with `superpowers:systematic-debugging`. Do NOT
weaken the floor-invariant tests to make a failure pass.

- [ ] **Step 3: Commit** (only if Step 1 required incidental fixes; otherwise nothing to commit)

```bash
git commit -am "test: green full suite after Slice 1 contract/graduated extension" -m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Self-review (run before dispatch)

- **Spec coverage:** PIPE-08 (Reason fields T2 + Decision fields T3), PIPE-09 (`side_effects` T1/T3),
  POL-13/14 (Outcome members T1; `expires_at` T3), TRST-02 (trust band T5 + sweep T6), SEC-12
  (`inferred_intent` field T3). All slice-1 requirements have a task. ✓
- **Placeholder scan:** every code step shows complete code; no TODO/TBD. ✓
- **Type consistency:** `GraduatedThresholds` (T4) used in T5; `_RANK`/`_RISK_LADDER`/`_more_restrictive`/
  `_risk_to_outcome` defined T4, used T5/T6; `SideEffect` defined T1, used T3. ✓
