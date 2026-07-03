# Phase 3 · Slice 3 — Enrichment, Policy Integration, Caches, Versions, Posture — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.
> **Commit convention:** second `-m "Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"`.
> Tests: `./.venv/Scripts/python.exe -m pytest` from repo root. TDD per task.

**Goal:** The live pipeline evaluates the **compiled constitution** (multi-principle WASM) instead
of the Phase-1 egress bundle: a deterministic enrichment stage feeds `intent.class` to policy
(SEC-12), every Decision pins constitution+policy versions (POL-08), the control plane keeps its
own version-invalidated compiled-policy/identity caches (PIPE-06), and per-action-class
fail-closed posture guarantees no silent allow on any control-plane failure (PIPE-05).

**Architecture:** New pipeline stage order: `identity → enrichment → policy → risk → graduated`.
New units in `agentos_pipeline`: `enrichment/` (intent tagger + flags), `policy_input.py` (the D4
input builder), `ConstitutionPolicyEngine` (replaces `WasmPolicyEngine`), `posture.py`
(per-action-class `FailPosture` + no-match floor), an identity TTL cache. The runner gains
total-failure semantics (posture-applied deny/allow + payload-free fail-safe audit record).
`graduated._RANK` consolidates onto `policy_io.OUTCOME_RESTRICTIVENESS`. The Phase-1 egress
engine, `policies/egress.rego`, and its CI build step are **removed** — the constitution subsumes
them; the D-04 red-team gate migrates to a *real* compiled constitution-without-the-principle.

**Requirements:** SEC-12, PIPE-05, PIPE-06, POL-08 (+ PIPE-08 reasons enrichment; PIPE-04 trend).

---

## Locked decisions (carry-forwards from reviews + overview D4/D6)

- **Absent-field semantics are deliberate and fail-closed:** `build_policy_input` ALWAYS emits
  every registry field applicable to the action type, using `""`/`False`/`[]` defaults — never an
  absent key. A tool_call with an unparseable URL gets `egress.host: ""`, which is not in any
  allowlist → principle 1.1 (`not_in`) fires → deny. (Mirrors Phase-1 `_host` fail-closed.)
- **Guardrail flags are a seam in this slice:** `guardrails: {pii: False, unsafe: False,
  format: False}` always emitted; the real detectors wire in Slice 4. Intent tagging is REAL now.
- **No whole-Decision cache** (review-locked): the caches are compiled-policy (engine loads WASM
  once + explicit `reload()` invalidation), identity verification (TTL), and later interpreter
  verdicts (Slice 5). Document this in `posture.py`/engine docstrings.
- **Posture:** all five action types default `FailPosture.closed` and `no_match_floor=allow`.
  The fail-open path is implemented + tested via an explicitly-configured open class; a fail-open
  that cannot write its audit record becomes a deny (**no record → no allow**).
- **Tests own their constitution:** `tests/fixtures/test_constitution.yaml` (principles 1.1, 2.1,
  3.2, 3.5 — NO 4.1, so benign egress stays `allow`) and
  `tests/fixtures/test_constitution_no_egress.yaml` (same minus 1.1 — the REAL D-04 deleted-
  principle variant). `policies/constitution.yaml` remains the operator example (its own test only).
- **OPA locator:** `tools/opa/opa.exe` if present, else `shutil.which("opa")` (CI installs Linux
  OPA on PATH). Fixtures build the test WASM once per session; skip cleanly if no OPA found.

## File structure

- Create: `packages/pipeline/src/agentos_pipeline/enrichment.py` (intent table + `enrich()`),
  `policy_input.py`, `posture.py`
- Rewrite: `packages/pipeline/src/agentos_pipeline/policy.py` (`ConstitutionPolicyEngine`;
  `WasmPolicyEngine`/`PolicyResult` deleted)
- Modify: `runner.py` (stage order, floor selection, reasons, versions, failure semantics),
  `graduated.py` (`_RANK` → import), `identity.py` (TTL cache wrapper),
  `risk/__init__.py` + new `risk/intent_scorer.py` (intent → advisory risk finding),
  `packages/controlplane/src/agentos_controlplane/audit.py` (digest non-str payload values)
- Delete: `policies/egress.rego`, `policies/egress_test.rego`; egress step in `.github/workflows/ci.yml`
- Tests: new `tests/unit/test_enrichment.py`, `test_policy_input.py`, `test_posture.py`,
  `test_identity_cache.py`, `tests/integration/test_pipeline_constitution.py`,
  `tests/benchmarks/test_latency_trend.py`; rewrite `tests/unit/test_policy_engine.py`;
  migrate `tests/conftest.py`, e2e + redteam tests; new `tests/fixtures/*.yaml`, `tests/_opa.py`

---

### Task 1: Redactor digests non-str payload values

**Files:** `packages/controlplane/src/agentos_controlplane/audit.py`; test additions in
`tests/unit/test_audit_phase2_payloads.py`.

- [ ] **Step 1 (failing tests):** an mcp_call payload `{"server": "s", "tool": "t",
  "args": {"count": 5, "filters": ["a", "b"]}}` appends successfully — body's `args` is a
  `{len, sha256}` digest of its canonical JSON; a tool_call payload `{"url": "https://api.example.com/x",
  "content": 42}` (non-str digest-key) also appends. A non-str VERBATIM-key value
  (`{"server": 5}`) still raises `RedactionError` (identifiers must stay strings).
- [ ] **Step 3 (implement):** in `_redact_or_raise`, digest-keys accept ANY JSON-serializable
  value: `_redact_content` gains a bytes path — for non-str, serialize with the module's
  `canonical_json(value)` and digest those bytes (raise `RedactionError` on `TypeError`).
  Verbatim keys keep the `isinstance(str)` requirement. `url` unchanged.
- [ ] **Step 4:** suite green. **Step 5: commit** `fix(audit): digest non-str payload values fail-closed (PIPE-05 seed)`.

---

### Task 2: Intent tagger + advisory intent risk scorer (SEC-12)

**Files:** create `packages/pipeline/src/agentos_pipeline/enrichment.py`,
`packages/pipeline/src/agentos_pipeline/risk/intent_scorer.py`; export from `risk/__init__.py`;
test `tests/unit/test_enrichment.py`.

- [ ] **Step 1 (failing tests):**

```python
from agentos_contract import ActionType
from agentos_pipeline.enrichment import enrich, tag_intent

def _act(type_, target, payload=None):
    return AgentAction(agent_id="a", type=type_, target=target, payload=payload or {})

def test_destruction_targets_tagged():
    for t in ("drop_table", "DROP_TABLE", "delete_user", "truncate_logs", "rm"):
        assert tag_intent(_act(ActionType.tool_call, t)) == "DATA_DESTRUCTION"

def test_rename_targets_tagged():
    for t in ("rename_table", "mv", "move_file"):
        assert tag_intent(_act(ActionType.tool_call, t)) == "RESOURCE_RENAME"

def test_memory_delete_operation_tagged():
    a = _act(ActionType.memory_access, "memory", {"operation": "delete", "key": "k"})
    assert tag_intent(a) == "DATA_DESTRUCTION"

def test_benign_target_untagged():
    assert tag_intent(_act(ActionType.tool_call, "http_get")) is None

def test_enrich_shape():
    e = enrich(_act(ActionType.tool_call, "drop_table"))
    assert e.intent_class == "DATA_DESTRUCTION"
    assert e.guardrails == {"pii": False, "unsafe": False, "format": False}  # Slice-4 seam

def test_intent_scorer_contributes_advisory_finding():
    from agentos_pipeline.risk import IntentScorer
    score, findings = IntentScorer().score(_act(ActionType.tool_call, "drop_table"))
    assert 0.0 < score < 0.4            # advisory: never reaches the sandbox band alone
    assert findings and findings[0].category == "intent"
```

(Adapt `IntentScorer` to the EXISTING `RiskScorer` protocol in `agentos_contract/risk.py` — read
it first; mirror `PromptInjectionScorer`'s interface exactly.)

- [ ] **Step 3 (implement) `enrichment.py`:**

```python
"""Deterministic pre-policy enrichment (SEC-12, D6). Pure CPU, sub-ms, stateless.
Intent classes are a small closed vocabulary; matching is exact/prefix on the
normalized target (lower/strip) + memory operation — NO regex, NO models."""

@dataclass(frozen=True)
class Enrichment:
    intent_class: str | None
    guardrails: dict[str, bool]   # real detectors land in Slice 4 (SEC-02)

_DESTRUCTION_EXACT = frozenset({"rm", "drop", "delete", "truncate"})
_DESTRUCTION_PREFIX = ("drop_", "delete_", "remove_", "truncate_")
_RENAME_EXACT = frozenset({"mv", "rename", "move"})
_RENAME_PREFIX = ("rename_", "move_", "mv_")

def tag_intent(action: AgentAction) -> str | None:
    if action.type is ActionType.memory_access and \
            str(action.payload.get("operation", "")).lower() == "delete":
        return "DATA_DESTRUCTION"
    t = action.target.strip().lower()
    if t in _DESTRUCTION_EXACT or t.startswith(_DESTRUCTION_PREFIX):
        return "DATA_DESTRUCTION"
    if t in _RENAME_EXACT or t.startswith(_RENAME_PREFIX):
        return "RESOURCE_RENAME"
    return None

def enrich(action: AgentAction) -> Enrichment:
    return Enrichment(intent_class=tag_intent(action),
                      guardrails={"pii": False, "unsafe": False, "format": False})
```

`intent_scorer.py`: `IntentScorer` re-derives via `tag_intent` (stateless), contributing
`risk_score=0.15` + one finding (`category="intent"`, detail=the class) when tagged, else `(0, [])`.

- [ ] **Step 4:** green. **Step 5: commit** `feat(pipeline): deterministic intent tagger + enrichment seam + advisory intent scorer (SEC-12)`.

---

### Task 3: `build_policy_input` — the D4 builder

**Files:** create `packages/pipeline/src/agentos_pipeline/policy_input.py`; test
`tests/unit/test_policy_input.py`.

- [ ] **Step 1 (failing tests):** assert for each action type the EXACT emitted document
  (deliberate defaults, never-absent fields), e.g.:

```python
def test_tool_call_input_complete_and_fail_closed():
    a = AgentAction(agent_id="a", type=ActionType.tool_call, target="http_get",
                    payload={"url": "https://API.Example.com:443/p?q=1"})
    doc = build_policy_input(a, enrich(a))
    assert doc == {
        "type": "tool_call", "target": "http_get",
        "intent": {"class": ""}, "guardrails": {"pii": False, "unsafe": False, "format": False},
        "sequence": {"matched_refs": []},
        "egress": {"host": "api.example.com"},
    }

def test_unparseable_url_yields_empty_host_fail_closed():
    a = AgentAction(agent_id="a", type=ActionType.tool_call, target="http_get", payload={})
    assert build_policy_input(a, enrich(a))["egress"]["host"] == ""

def test_intent_class_flows_from_enrichment():
    a = AgentAction(agent_id="a", type=ActionType.tool_call, target="drop_table", payload={})
    assert build_policy_input(a, enrich(a))["intent"]["class"] == "DATA_DESTRUCTION"
```

plus one test per remaining type asserting its per-type section with `""` defaults
(`memory: {operation, key}`, `mcp: {server, tool}` — mcp also emits `egress.host` from a
payload `url` if present else `""`, `delegation: {to_agent}`, `model: {name}` from payload
`model`). Keys/values MUST match the `POLICY_INPUT_FIELDS` registry paths exactly.

- [ ] **Step 3 (implement):** move/reuse the `_host` URL parser from `runner.py` (relocate it
  here; runner imports it or stops needing it). Base doc always: `type`, `target`,
  `intent.class` (enrichment or `""`), `guardrails` (from enrichment), `sequence.matched_refs: []`
  (Slice-7 populates). Per-type sections per the tests. Module docstring: this builder and
  `POLICY_INPUT_FIELDS` are the same versioned schema (`POLICY_INPUT_SCHEMA_VERSION`).
- [ ] **Step 4:** green. **Step 5: commit** `feat(pipeline): build_policy_input — versioned D4 input builder, fail-closed defaults`.

---

### Task 4: `ConstitutionPolicyEngine` (replaces WasmPolicyEngine)

**Files:** rewrite `packages/pipeline/src/agentos_pipeline/policy.py`; create `tests/_opa.py`
(locator + build helper); rewrite `tests/unit/test_policy_engine.py`; create
`tests/fixtures/test_constitution.yaml` + `tests/fixtures/test_constitution_no_egress.yaml`.

- [ ] **Step 1:** author the fixtures — `test_constitution.yaml` = principles 1.1 (egress
  allowlist deny, list `egress_allowlist: [api.example.com]`), 2.1 (intent any-of
  DATA_DESTRUCTION/DATA_EXFILTRATION → require_approval), 3.2 (PII+not-allowlisted → deny),
  3.5 (sequence RESOURCE_RENAME→DATA_DESTRUCTION → deny). `test_constitution_no_egress.yaml` =
  identical minus 1.1 (and minus 3.2's allowlist clause dependency — keep 3.2 but it can't fire
  while pii is False; keep the SAME `lists` section so only 1.1's absence differs). And `tests/_opa.py`:

```python
"""Locate OPA (vendored exe on Windows dev box; PATH on CI) + build test WASM once."""
def find_opa() -> str | None:
    vendored = Path("tools/opa/opa.exe")
    return str(vendored) if vendored.exists() else shutil.which("opa")

def build_constitution_wasm(constitution_path: Path, out_dir: Path) -> "BuiltPolicy":
    """compile_constitution + agentos_constitution.wasm.build_wasm via find_opa().
    Returns wasm path + CompiledBundle + a principles_meta dict {ref: {title, statement,
    effect, side_effects}} derived from the loaded Constitution."""
```

(Adjust `agentos_constitution.wasm.build_wasm` ONLY if it hardcodes the vendored path — if so,
add an optional `opa_bin: str | None = None` parameter defaulting to the current behavior; do
not change its signature otherwise.)

- [ ] **Step 2 (failing tests, `tests/unit/test_policy_engine.py` rewritten):**

```python
pytestmark = pytest.mark.skipif(find_opa() is None, reason="no OPA binary")

@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    built = build_constitution_wasm(Path("tests/fixtures/test_constitution.yaml"),
                                    tmp_path_factory.mktemp("wasm"))
    return ConstitutionPolicyEngine(
        wasm_path=str(built.wasm_path), lists=built.bundle.lists,
        constitution_version=built.bundle.constitution_version,
        principles_meta=built.principles_meta)

def test_unlisted_host_matches_egress_principle(engine):
    r = engine.evaluate({"type": "tool_call", "egress": {"host": "attacker.example"}})
    assert isinstance(r, ConstitutionResult) and not r.no_match
    assert any(m.principle_ref == "1.1" and m.effect == "deny" for m in r.matched)

def test_benign_input_is_no_match(engine):
    r = engine.evaluate({"type": "tool_call", "egress": {"host": "api.example.com"},
                         "intent": {"class": ""}})
    assert r.no_match and r.matched == ()

def test_versions_exposed(engine):
    assert engine.constitution_version.startswith("sha256:")
    assert engine.policy_version.startswith("sha256:")        # hash of the wasm bytes

def test_reload_invalidates_compiled_policy(tmp_path_factory):   # PIPE-06
    built_a = build_constitution_wasm(Path("tests/fixtures/test_constitution.yaml"), ...)
    built_b = build_constitution_wasm(Path("tests/fixtures/test_constitution_no_egress.yaml"), ...)
    eng = ConstitutionPolicyEngine(...built_a...)
    attack = {"type": "tool_call", "egress": {"host": "attacker.example"}}
    assert not eng.evaluate(attack).no_match                  # 1.1 fires
    old_version = eng.policy_version
    eng.reload(wasm_path=str(built_b.wasm_path), lists=built_b.bundle.lists,
               constitution_version=built_b.bundle.constitution_version,
               principles_meta=built_b.principles_meta)
    assert eng.evaluate(attack).no_match                      # principle gone -> no match
    assert eng.policy_version != old_version

def test_malformed_result_fails_closed(engine, monkeypatch):
    monkeypatch.setattr(engine, "_policy", SimpleNamespace(evaluate=lambda i: [{"weird": 1}]))
    with pytest.raises(PolicyEvaluationError):
        engine.evaluate({"type": "tool_call"})
```

- [ ] **Step 3 (implement `policy.py` rewrite):**

```python
class PolicyEvaluationError(RuntimeError):
    """Engine could not produce a structured result — the runner applies the
    per-action-class posture (PIPE-05); NEVER silently allow."""

class ConstitutionPolicyEngine:
    """Compiled-constitution floor. The WASM bundle is the compiled-policy CACHE:
    loaded ONCE here (Pitfall 2), invalidated only via reload() on version change
    (PIPE-06). No whole-Decision cache by design (trust drift / per-action audit)."""
    def __init__(self, *, wasm_path, lists, constitution_version, principles_meta): ...
        # OPAPolicy(wasm_path); set_data({"lists": lists});
        # self.policy_version = "sha256:" + sha256(Path(wasm_path).read_bytes()).hexdigest()
    def reload(self, *, wasm_path, lists, constitution_version, principles_meta): ...
    def evaluate(self, input: dict) -> ConstitutionResult:
        # result[0]["result"] must be {"matched": [...], "no_match": bool} — anything
        # else raises PolicyEvaluationError. matched items -> MatchedPrinciple(...).
```

Keep a `PolicyEngine` Protocol (`evaluate(dict) -> ConstitutionResult`) for the toggle seam.
DELETE `WasmPolicyEngine`, `PolicyResult`, `_extract_bool`.

- [ ] **Step 4:** the new engine tests green (old ones replaced). Other suites will be RED until
  Task 6 migrates them — run only `tests/unit/test_policy_engine.py tests/unit/test_enrichment.py
  tests/unit/test_policy_input.py` at this step.
- [ ] **Step 5: commit** `feat(pipeline): ConstitutionPolicyEngine — multi-principle WASM floor with version-keyed reload (PIPE-06, POL-08)`.

---### Task 5: Posture map + runner migration (the core of the slice)

**Files:** create `packages/pipeline/src/agentos_pipeline/posture.py`; modify `runner.py`,
`graduated.py`; tests `tests/unit/test_posture.py` + `tests/unit/test_pipeline.py` additions.

- [ ] **Step 1 (failing tests, key cases):**

```python
# posture
def test_defaults_all_closed_allow_floor():
    p = PostureMap()
    for t in ActionType:
        assert p.fail_posture(t) is FailPosture.closed
        assert p.no_match_floor(t) is Outcome.allow

def test_override_per_class():
    p = PostureMap(fail_open_types=frozenset({ActionType.model_invocation}))
    assert p.fail_posture(ActionType.model_invocation) is FailPosture.open

# runner (async tests; build Pipeline with stub identity/audit per existing test_pipeline.py style)
async def test_enrichment_feeds_policy_destructive_intent_requires_approval(...):
    # engine = real constitution engine fixture; action target "drop_table", benign host
    # -> matched 2.1 -> decision.outcome require_approval; inferred_intent == "DATA_DESTRUCTION"
    # -> a policy Reason with principle_ref "2.1" and nonempty rationale

async def test_no_match_floor_allows_and_records_reason(...):
    # benign http_get to allowlisted host -> no principle -> outcome allow,
    # reasons include stage="policy", code="no_principle_matched"

async def test_decision_pins_versions(...):       # POL-08
    # EVERY decision: constitution_version + policy_version both "sha256:..." and
    # the audit body carries the same values

async def test_engine_failure_fails_closed_with_audit_record(...):   # PIPE-05 kill-the-CP
    # policy engine stub raising PolicyEvaluationError -> outcome deny,
    # reason code "control_plane_failure_fail_closed", audit record written
    # (payload-free: body["redacted_payload"] == {}), evidence_ref set

async def test_engine_failure_fail_open_class_is_audited(...):
    # PostureMap(fail_open_types={model_invocation}) + raising engine ->
    # model_invocation action -> outcome allow + reason "control_plane_failure_fail_open"
    # + audit record EXISTS (no silent allow)

async def test_fail_open_without_audit_record_becomes_deny(...):
    # raising engine AND audit writer that raises -> fail-open class still returns DENY
    # ("no record -> no allow")

async def test_redaction_failure_writes_payload_free_record_and_applies_posture(...):
    # audit.append raises RedactionError on first call -> decision deny (closed),
    # second append (payload-free) succeeds, reason "redaction_failed" present
```

- [ ] **Step 3 (implement):**

`posture.py`:
```python
class FailPosture(Enum): closed = "closed"; open = "open"

@dataclass(frozen=True)
class PostureMap:
    """Per-action-class control-plane-failure posture + no-match floor (PIPE-05/D4).
    Defaults: every class fail-CLOSED, no-match floor allow. fail-open is explicit,
    per-class, and every fail-open MUST be audited (no record -> no allow)."""
    fail_open_types: frozenset[ActionType] = frozenset()
    no_match_floors: Mapping[ActionType, Outcome] = field(default_factory=dict)
    def fail_posture(self, t) -> FailPosture: ...
    def no_match_floor(self, t) -> Outcome: return self.no_match_floors.get(t, Outcome.allow)
```

`graduated.py`: replace the `_RANK` literal with
`from agentos_contract.policy_io import OUTCOME_RESTRICTIVENESS as _RANK` (delete the dict;
tests importing `_RANK` keep working).

`runner.py` rewrite of `evaluate` (preserve identity short-circuit exactly; it stays FIRST and
its deny is still audited via the fail-safe path below):

```python
async def evaluate(self, action):
    try:
        return await self._evaluate(action)
    except Exception as exc:                      # total control-plane failure (PIPE-05)
        return await self._fail_safe(action, exc)

async def _evaluate(self, action):
    # 1 identity (unchanged short-circuit)
    # 2 enrichment: e = enrich(action)            [pure CPU]
    # 3 policy: doc = build_policy_input(action, e); res = self._policy.evaluate(doc)
    #   floor = select_floor(res.matched) or self._posture.no_match_floor(action.type)
    #   reasons += per-matched Reason(stage="policy", code="constitution_principle_fired",
    #       policy_id=f"constitution.{m.principle_ref}", principle_ref=m.principle_ref,
    #       rationale=self._policy.principles_meta[m.principle_ref]["title"],
    #       evidence={"effect": m.effect})
    #   or on no_match: Reason(stage="policy", code="no_principle_matched")
    # 4 risk (unchanged) ; 5 graduated(floor, risk, trust, self._thresholds)
    # decision.inferred_intent = e.intent_class
    # decision.constitution_version / policy_version = engine attrs
    # audit append with RedactionError fallback:
    #   try: evidence_ref = await audit.append(action, decision)
    #   except RedactionError: append payload-free copy + reason "redaction_failed";
    #       decision falls to posture outcome first (closed -> deny) BEFORE the retry append

async def _fail_safe(self, action, exc):
    posture = self._posture.fail_posture(action.type)
    outcome = Outcome.allow if posture is FailPosture.open else Outcome.deny
    reasons = [Reason(stage="pipeline", code=f"control_plane_failure_fail_{posture.value}",
                      detail=type(exc).__name__)]      # exception CLASS only, never payload
    decision = Decision(action_id=action.id, outcome=outcome, reasons=reasons)
    stripped = action.model_copy(update={"payload": {}})
    try:
        decision.evidence_ref = await self._audit.append(stripped, decision)
    except Exception:
        if outcome is Outcome.allow:               # no record -> no allow
            return Decision(action_id=action.id, outcome=Outcome.deny, reasons=reasons + [
                Reason(stage="pipeline", code="fail_open_unaudited_demoted_to_deny")])
        return decision                            # deny stands even without evidence
    return decision
```

`Pipeline.__init__` gains `posture: PostureMap = PostureMap()`. Note: `_host` moved to
`policy_input.py` (Task 3) — update imports; the old hardcoded
`{"host": ..., "method": "GET", "type": ...}` input dict is GONE.

- [ ] **Step 4:** new tests green (e2e/conftest still red until Task 6).
- [ ] **Step 5: commit** `feat(pipeline): enrichment-fed constitution floor, per-class fail posture, version stamping (SEC-12, PIPE-05, POL-08)`.

---

### Task 6: Test-suite + CI migration (egress engine removed)

**Files:** `tests/conftest.py`, `tests/integration/test_e2e_slice.py`,
`test_all_action_types_e2e.py`, `test_real_agent_governance.py`,
`tests/redteam/test_exfil_injection.py`, `tests/unit/test_middleware.py` (only if it wires the
old engine), `.github/workflows/ci.yml`; DELETE `policies/egress.rego`,
`policies/egress_test.rego`.

- [ ] **Step 1: conftest migration.** Session-scoped builds (skip cleanly when `find_opa()` is
  None): `constitution_wasm` (from `tests/fixtures/test_constitution.yaml`) and
  `constitution_wasm_no_egress`. `_wire(policy_engine)` unchanged;
  `pipeline_with_principle` = `ConstitutionPolicyEngine` over the full test constitution;
  `pipeline_without_principle` = engine over the no-egress constitution — DELETE
  `_AllowAllPolicyEngine` (the structural stub is replaced by the REAL deleted-principle compile;
  update the fixture docstring to say so). Pass `posture=PostureMap()` defaults.
- [ ] **Step 2: expected-reason migration.** Tests asserting the old codes migrate as:
  `egress_allowlist_violation` → a `stage="policy"` reason with `principle_ref == "1.1"`;
  `egress_allowlisted`/`no_egress_policy_applicable` → `code == "no_principle_matched"` (benign
  paths). The D-04 red-team test keeps asserting deny-with-principle vs allow-without-principle
  (the regression lock's CI-break property is now proven against a genuinely recompiled
  constitution). Mechanical sweep: `grep -rn "egress_allowlist\|no_egress_policy\|WasmPolicyEngine\|EGRESS_WASM\|PolicyResult" tests/` and fix every hit.
- [ ] **Step 3: CI.** In `.github/workflows/ci.yml`: DELETE the "Build egress policy WASM" step
  (fixtures build at test time via PATH opa); KEEP the OPA install step (now load-bearing for
  pytest) and the `opa test policies/` step's existing no-rego guard (egress_test.rego is gone;
  the constitution compiler's golden/behavioral tests cover policy logic now).
- [ ] **Step 4:** FULL suite: `./.venv/Scripts/python.exe -m pytest -q` → green
  (expect ~640+ passed, 2 xfailed, 0 failures, 0 errors) AND
  `-m regression_lock -q` green AND `-m floor_invariant -q` green (430).
- [ ] **Step 5: commit** `refactor(tests,ci)!: pipeline + suite migrate to the compiled constitution; egress engine retired (D-04 gate preserved)`.

---

### Task 7: Identity TTL cache (PIPE-06)

**Files:** `packages/pipeline/src/agentos_pipeline/identity.py`; test
`tests/unit/test_identity_cache.py`.

- [ ] **Step 1 (failing tests):** `CachingIdentityStage(engine, ttl_seconds=60, max_entries=1024)` —
  (a) two verifies of the same `(token, agent_id)` hit the underlying engine ONCE (count with a
  stub); (b) after `ttl_seconds` elapses (inject a `clock` callable, don't sleep) the engine is
  hit again; (c) a FAILED verdict (`ok=False`) is NEVER cached (forged tokens always re-verify);
  (d) `invalidate()` clears everything (the policy-version-change hook); (e) bounded:
  `max_entries+1` distinct tokens never grow the dict past `max_entries`.
- [ ] **Step 3 (implement):** small dict cache `{(token, agent_id): (verdict, expires_at)}` with
  the injectable `clock=time.monotonic`; evict-oldest-on-full (simple FIFO via dict order);
  docstring: this is the PIPE-06 identity cache; whole-Decision caching deliberately rejected
  (trust drift, per-action audit). Wire NOTHING by default — `Pipeline` accepts it transparently
  since it satisfies the same `verify(action)` shape as `IdentityStage` when wrapped:
  `CachingIdentityStage` WRAPS an `IdentityStage` and exposes `verify(action)`.
- [ ] **Step 4:** green. **Step 5: commit** `feat(pipeline): bounded TTL identity-verification cache with explicit invalidation (PIPE-06)`.

---

### Task 8: Non-gating latency trend benchmark (PIPE-04 seed) + final gate

**Files:** create `tests/benchmarks/test_latency_trend.py` (+ `tests/benchmarks/__init__.py` if
needed).

- [ ] **Step 1:** `@pytest.mark.latency` benchmark (pytest-benchmark is a dev dep; the `latency`
  marker is registered): full wired pipeline (constitution engine + SQLite audit, the
  `pipeline_with_principle` fixture), benign allowlisted http_get, `benchmark.pedantic`-style
  rounds ≥ 200 measuring `asyncio.get_event_loop().run_until_complete(...)`? NO — the fixture is
  async; use `benchmark(lambda: asyncio.run(pipeline.evaluate(action)))` with a FRESH action per
  call (unique action.id so the audit chain appends). Record mean/p95 via pytest-benchmark stats;
  assert a deliberately GENEROUS smoke ceiling (`stats.stats.mean < 0.050`) so the test is real
  but non-flaky — the HARD budget gate is Slice 6c. Print the numbers.
- [ ] **Step 2:** run `-m latency -v`; note the measured mean in the commit message (the trend
  baseline). **Step 3:** FULL suite green one more time.
- [ ] **Step 4: commit** `test(benchmark): non-gating cached-path latency trend baseline (PIPE-04 seed)`.

---

## Self-review checklist
- SEC-12: tagger + scorer + `inferred_intent` + intent-feeds-policy test (T2/T3/T5) ✓
- PIPE-05: posture map, kill-the-CP closed test, audited fail-open, no-record→no-allow,
  redaction fallback, non-str redactor (T1/T5) ✓
- PIPE-06: engine reload invalidation + identity TTL cache + no-Decision-cache documented (T4/T7) ✓
- POL-08: versions on every Decision + in audit body (T5; audit body already persists from H3) ✓
- D-04 regression lock preserved with REAL recompiled constitution (T6) ✓; egress engine fully
  removed, no `WasmPolicyEngine`/`PolicyResult`/`egress.rego` references anywhere ✓
- `_RANK` consolidated; runner stage order identity→enrich→policy→risk→graduated ✓
- Types consistent: `ConstitutionResult`/`MatchedPrinciple` from `agentos_contract.policy_io`;
  `Enrichment`; `PostureMap`/`FailPosture`; `PolicyEvaluationError` ✓
