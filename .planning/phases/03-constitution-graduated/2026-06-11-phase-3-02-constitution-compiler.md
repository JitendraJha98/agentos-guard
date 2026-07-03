# Phase 3 · Slice 2 — Constitution Authoring + Deterministic Compiler — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development.
> **Commit convention:** every commit ends with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
> (second `-m`). Tests: `./.venv/Scripts/python.exe -m pytest` from repo root. TDD per task.

**Goal:** Operators author a structured-YAML Constitution of numbered principles (POL-01); a
**deterministic** compiler lowers it `Constitution → YAML policy → Rego` (POL-02) with
principle-citation provenance, content-hash versioning, deny-overrides-allow precedence, and a
WASM bundle that builds via the vendored OPA CLI and evaluates correctly under `opa-wasmtime`.

**Architecture:** New `packages/constitution/` (agentos-constitution) + a new
`agentos_contract.policy_io` module that locks the D4 policy I/O contract (input-field registry,
`MatchedPrinciple`, `ConstitutionResult`, restrictiveness rank + `select_floor`). The compiler is
pure functions: schema → canonical form → content hash → YAML middle layer → Rego (via DNF
normalization). Generated Rego exposes ONE entrypoint `agentos/constitution/result` returning
`{"matched": [...], "no_match": bool}`; named lists are runtime `data` (like the existing egress
allowlist); sequence principles also emit bundle metadata for Slice 7's correlator. The existing
`policies/egress.rego` and its engine wiring are NOT touched (Slice 3 migrates; D-04 gate stays).

**Verified capabilities (2026-06-11, this machine):** `glob.match` evaluates correctly in
OPA-built WASM under `opa-wasmtime` (smoke-tested); vendored CLI `tools/opa/opa.exe` (v1.17.0)
builds WASM. The full locked op set is therefore implementable.

**Requirements covered:** POL-01, POL-02 (+ the D4 contract that PIPE-05/POL-04/POL-05 build on).

---

## Design (locked, from overview rev 2 — D1/D4/D5)

- **Authorable effects** = `allow | warn | sandbox | require_consensus | require_approval |
  governance_review | deny`. `temporary_exception` is REJECTED by the schema (POL-13).
- **`when` algebra:** combinators `all` / `any` / `not` over leaves `{field, op, value|list_ref}`;
  ops `eq ne in not_in prefix glob gte lte`; fields ONLY from the policy-input registry; nesting
  depth ≤ 3; no regex. Lowered to Rego via **DNF**: each disjunct → one `matched contains` rule
  (Rego OR = separate rules); `not` pushed to leaves by De Morgan.
- **Precedence:** multi-match resolves most-restrictive-wins via `select_floor` (deny overrides
  allow). Ambiguity ≡ `no_match` (floor for that = per-class posture, Slice 3).
- **Determinism:** principles canonically sorted by id, lists sorted+deduped; same content (any
  order) → byte-identical YAML/Rego and the same `sha256:` version. Golden tests lock bytes.
- **Provenance:** every generated rule carries `principle_ref` in its matched object AND a comment
  block citing id/title/statement. Round-trip test: refs extracted from Rego == constitution ids.
- **Sequence principles** (`kind: sequence`, e.g. `rename_then_drop`): compile to (a) a membership
  rule over `input.sequence.matched_refs` (populated by the Slice-7 correlator; `[]` until then)
  and (b) `bundle.sequences` metadata `[{principle_ref, intent_classes, effect}]`.
- **`graduated:` section** → `bundle.graduated_config` (consumed by Slice 3; not Rego).

## File structure

- Create: `packages/contract/src/agentos_contract/policy_io.py` (+ export in `__init__.py`)
- Create: `packages/constitution/pyproject.toml`,
  `packages/constitution/src/agentos_constitution/{__init__,schema,version,compiler,wasm}.py`
- Modify: root `pyproject.toml` (dep + uv source for `agentos-constitution`)
- Create: `policies/constitution.yaml` (example incl. wedge principles)
- Tests: `tests/unit/test_policy_io.py`, `tests/unit/test_constitution_schema.py`,
  `tests/unit/test_constitution_version.py`, `tests/unit/test_constitution_compiler.py`,
  `tests/integration/test_constitution_wasm.py`, golden fixtures under `tests/golden/`

---

### Task 1: `agentos_contract.policy_io` — the D4 contract

**Files:** Create `packages/contract/src/agentos_contract/policy_io.py`; modify
`packages/contract/src/agentos_contract/__init__.py`; test `tests/unit/test_policy_io.py`.

- [ ] **Step 1: failing tests** (`tests/unit/test_policy_io.py`)

```python
"""D4 policy I/O contract — input-field registry, result types, precedence."""
import pytest
from agentos_contract import Outcome
from agentos_contract.policy_io import (
    AUTHORABLE_EFFECTS, OUTCOME_RESTRICTIVENESS, POLICY_INPUT_FIELDS,
    POLICY_INPUT_SCHEMA_VERSION, ConstitutionResult, MatchedPrinciple, select_floor,
)


def test_authorable_effects_exclude_temporary_exception():
    assert Outcome.temporary_exception.value not in AUTHORABLE_EFFECTS
    assert AUTHORABLE_EFFECTS == {
        "allow", "warn", "sandbox", "require_consensus",
        "require_approval", "governance_review", "deny",
    }


def test_restrictiveness_covers_all_outcomes_deny_max():
    assert set(OUTCOME_RESTRICTIVENESS) == set(Outcome)
    assert max(OUTCOME_RESTRICTIVENESS, key=OUTCOME_RESTRICTIVENESS.get) is Outcome.deny
    assert OUTCOME_RESTRICTIVENESS[Outcome.allow] == 0


def test_registry_has_core_fields_and_version():
    assert POLICY_INPUT_SCHEMA_VERSION == 1
    for f in ("type", "target", "intent.class", "guardrails.pii",
              "egress.host", "sequence.matched_refs"):
        assert f in POLICY_INPUT_FIELDS


def test_select_floor_most_restrictive_wins():
    m = lambda ref, eff: MatchedPrinciple(principle_ref=ref, effect=eff)
    assert select_floor([m("1", "allow"), m("2", "deny")]) is Outcome.deny
    assert select_floor([m("1", "warn"), m("2", "require_approval")]) is Outcome.require_approval
    assert select_floor([m("1", "allow")]) is Outcome.allow
    assert select_floor([]) is None  # no_match — floor is the per-class posture (Slice 3)


def test_matched_principle_is_frozen():
    mp = MatchedPrinciple(principle_ref="3.2", effect="deny")
    with pytest.raises(Exception):
        mp.effect = "allow"
```

- [ ] **Step 2: run, confirm fail** (`ImportError`).
- [ ] **Step 3: implement** `policy_io.py`:

```python
"""D4 policy I/O contract — the seam shared by the constitution compiler (Slice 2),
the policy engine/runner (Slice 3), and the interpreter trigger (Slice 5).

The INPUT registry is versioned: `when.field` in a Constitution may reference only
these dotted paths, and `build_policy_input` (Slice 3) emits exactly this shape.
OUTCOME_RESTRICTIVENESS is the single restrictiveness order (graduated._RANK
consolidates onto it in Slice 3)."""

from dataclasses import dataclass

from agentos_contract.decision import Outcome

POLICY_INPUT_SCHEMA_VERSION = 1

# field -> (python type, action types it applies to; "all" = every type)
POLICY_INPUT_FIELDS: dict[str, tuple[type, frozenset[str] | str]] = {
    "type": (str, "all"),
    "target": (str, "all"),
    "intent.class": (str, "all"),
    "guardrails.pii": (bool, "all"),
    "guardrails.unsafe": (bool, "all"),
    "guardrails.format": (bool, "all"),
    "sequence.matched_refs": (list, "all"),
    "egress.host": (str, frozenset({"tool_call", "mcp_call"})),
    "memory.operation": (str, frozenset({"memory_access"})),
    "memory.key": (str, frozenset({"memory_access"})),
    "mcp.server": (str, frozenset({"mcp_call"})),
    "mcp.tool": (str, frozenset({"mcp_call"})),
    "delegation.to_agent": (str, frozenset({"delegation"})),
    "model.name": (str, frozenset({"model_invocation"})),
}

# Single source of restrictiveness (ties: governance_review/temporary_exception both
# "proceed with oversight"). deny is maximal; allow minimal.
OUTCOME_RESTRICTIVENESS: dict[Outcome, int] = {
    Outcome.allow: 0,
    Outcome.warn: 1,
    Outcome.governance_review: 2,
    Outcome.temporary_exception: 2,
    Outcome.sandbox: 3,
    Outcome.require_consensus: 4,
    Outcome.require_approval: 5,
    Outcome.deny: 6,
}

# POL-13: temporary_exception is human-ratified only — never authorable as an effect.
AUTHORABLE_EFFECTS: frozenset[str] = frozenset(
    o.value for o in Outcome if o is not Outcome.temporary_exception
)


@dataclass(frozen=True)
class MatchedPrinciple:
    """One fired principle from the deterministic floor (provenance for Reason)."""
    principle_ref: str
    effect: str
    evidence: dict | None = None


@dataclass(frozen=True)
class ConstitutionResult:
    """PolicyResult v2 — the structured verdict of the compiled constitution."""
    matched: tuple[MatchedPrinciple, ...]
    no_match: bool


def select_floor(matched: list[MatchedPrinciple] | tuple[MatchedPrinciple, ...]) -> Outcome | None:
    """Deny-overrides-allow: the most restrictive matched effect is the floor.
    Returns None on no match — that floor is the per-action-class posture (PIPE-05)."""
    if not matched:
        return None
    return max((Outcome(m.effect) for m in matched), key=OUTCOME_RESTRICTIVENESS.__getitem__)
```

Export `policy_io` names from `agentos_contract/__init__.py` (append to imports + `__all__`:
`MatchedPrinciple`, `ConstitutionResult`, `select_floor`, `AUTHORABLE_EFFECTS`,
`OUTCOME_RESTRICTIVENESS`, `POLICY_INPUT_FIELDS`, `POLICY_INPUT_SCHEMA_VERSION`).

- [ ] **Step 4: green** (`pytest tests/unit/test_policy_io.py -v`), full contract suite still green.
- [ ] **Step 5: commit** `feat(contract): D4 policy I/O contract — input registry, ConstitutionResult, select_floor precedence (POL-02 seed)`.

---

### Task 2: `agentos-constitution` package scaffold

**Files:** Create `packages/constitution/pyproject.toml` + `src/agentos_constitution/__init__.py`;
modify root `pyproject.toml`.

- [ ] **Step 1:** `packages/constitution/pyproject.toml` (mirror the contract package's shape):

```toml
[project]
name = "agentos-constitution"
version = "0.1.0"
description = "Human-readable Constitution schema + deterministic Constitution -> YAML -> Rego compiler (POL-01/POL-02)."
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
    "pydantic>=2.13,<3",
    "PyYAML>=6,<7",
    "agentos-contract",
]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/agentos_constitution"]
```

Create a one-line `packages/constitution/README.md` and an `__init__.py` exporting the public
surface (filled by later tasks). Root `pyproject.toml`: add `"agentos-constitution",` to
`[project].dependencies` and `agentos-constitution = { workspace = true }` to `[tool.uv.sources]`.

- [ ] **Step 2:** `uv sync` (from repo root). Then verify:
`./.venv/Scripts/python.exe -c "import agentos_constitution; print('ok')"` → `ok`.
- [ ] **Step 3: commit** `chore(constitution): scaffold agentos-constitution workspace package`.

---

### Task 3: Constitution schema (POL-01)

**Files:** Create `packages/constitution/src/agentos_constitution/schema.py`; test
`tests/unit/test_constitution_schema.py`.

- [ ] **Step 1: failing tests** — write these (plus the obvious happy-path construction test):

```python
"""POL-01 schema: structured principles; temporary_exception unauthorable; field registry."""
import pytest
from pydantic import ValidationError
from agentos_constitution.schema import Constitution, Leaf, Principle

BASE = dict(schema_version=1, name="test")


def _p(**kw):
    d = dict(id="1.1", title="t", statement="s", effect="deny")
    d.update(kw)
    return d


def test_minimal_constitution_parses():
    c = Constitution(**BASE, principles=[_p(when={"field": "egress.host", "op": "not_in", "list_ref": "egress_allowlist"})],
                     lists={"egress_allowlist": ["api.example.com"]})
    assert c.principles[0].id == "1.1"


def test_temporary_exception_effect_rejected():        # POL-13
    with pytest.raises(ValidationError, match="temporary_exception"):
        Constitution(**BASE, principles=[_p(effect="temporary_exception")])


def test_unknown_when_field_rejected():                # registry-validated algebra
    with pytest.raises(ValidationError, match="unknown policy-input field"):
        Constitution(**BASE, principles=[_p(when={"field": "nope.nope", "op": "eq", "value": "x"})])


def test_list_ref_must_exist():
    with pytest.raises(ValidationError, match="unknown list"):
        Constitution(**BASE, principles=[_p(when={"field": "egress.host", "op": "in", "list_ref": "ghost"})])


def test_duplicate_principle_ids_rejected():
    with pytest.raises(ValidationError, match="duplicate"):
        Constitution(**BASE, principles=[_p(), _p(title="other")])


def test_sequence_principle_needs_two_classes_and_no_when():
    ok = Constitution(**BASE, principles=[_p(kind="sequence", sequence=["RESOURCE_RENAME", "DATA_DESTRUCTION"])])
    assert ok.principles[0].sequence == ["RESOURCE_RENAME", "DATA_DESTRUCTION"]
    with pytest.raises(ValidationError):
        Constitution(**BASE, principles=[_p(kind="sequence", sequence=["ONLY_ONE"])])
    with pytest.raises(ValidationError):
        Constitution(**BASE, principles=[_p(kind="sequence", sequence=["A", "B"],
                                            when={"field": "type", "op": "eq", "value": "tool_call"})])


def test_nesting_depth_bounded_at_3():
    deep = {"not": {"all": [{"any": [{"not": {"field": "type", "op": "eq", "value": "x"}}]}]}}
    with pytest.raises(ValidationError, match="depth"):
        Constitution(**BASE, principles=[_p(when=deep)])


def test_op_type_compatibility():
    with pytest.raises(ValidationError, match="op"):   # prefix on a bool field
        Constitution(**BASE, principles=[_p(when={"field": "guardrails.pii", "op": "prefix", "value": "x"})])
```

- [ ] **Step 2: confirm fail.**
- [ ] **Step 3: implement `schema.py`.** Required shape (all models `extra="forbid"`):

```python
Op = Literal["eq", "ne", "in", "not_in", "prefix", "glob", "gte", "lte"]

class Leaf(BaseModel):           # {field, op, value | list_ref}
    field: str; op: Op
    value: str | int | float | bool | list[str] | None = None
    list_ref: str | None = None
    # validators: field in POLICY_INPUT_FIELDS (msg "unknown policy-input field");
    # exactly one of value/list_ref; list_ref only with in/not_in;
    # op/type compatibility against the registry (msg starts "op"):
    #   prefix/glob -> str fields, str value; gte/lte -> int/float value on numeric fields;
    #   eq/ne -> scalar matching field type; in/not_in -> list[str] value or list_ref on str fields.

class AllNode(BaseModel):  all: list["Node"]           # field name "all" via alias or exact name
class AnyNode(BaseModel):  any: list["Node"]
class NotNode(BaseModel):  not_: "Node" = Field(alias="not")
Node = Leaf | AllNode | AnyNode | NotNode              # structural union (extra=forbid disambiguates)

class Principle(BaseModel):
    id: str                       # pattern ^\d+(\.\d+)*$
    title: str                    # max_length 120
    statement: str                # max_length 2000 — VERBATIM, never normalized
    kind: Literal["action", "sequence"] = "action"
    applies_to: list[ActionType] | Literal["all"] = "all"
    effect: str                   # validator: in AUTHORABLE_EFFECTS, msg mentions temporary_exception when that's the value
    when: Node | None = None      # action kind only (sequence: must be None)
    sequence: list[str] | None = None   # sequence kind only; min_length 2; UPPER_SNAKE strings
    side_effects: list[SideEffect] = Field(default_factory=list)
    # model_validator: kind/when/sequence consistency; condition depth <= 3 (msg contains "depth")

class GraduatedThresholdsCfg(BaseModel):
    sandbox_at: float = 0.4; deny_at: float = 0.7; trust_harden_at: float = 0.2
    # same ordering validation as pipeline GraduatedThresholds

class GraduatedSection(BaseModel):
    default: GraduatedThresholdsCfg = GraduatedThresholdsCfg()
    per_action_type: dict[ActionType, GraduatedThresholdsCfg] = Field(default_factory=dict)

class Constitution(BaseModel):
    schema_version: Literal[1]
    name: str
    principles: list[Principle]   # model_validator: unique ids (msg contains "duplicate")
    lists: dict[str, list[str]] = Field(default_factory=dict)   # names ^[a-z][a-z0-9_]*$
    graduated: GraduatedSection | None = None
    # model_validator: every list_ref used by any Leaf exists in lists (msg "unknown list")

def load_constitution(path) -> Constitution: ...  # yaml.safe_load + model_validate
```

Use Pydantic field name `all`/`any` directly (they're not reserved); `not` needs an alias.
Walk conditions recursively for depth/list_ref checks.

- [ ] **Step 4: green**; full suite still green.
- [ ] **Step 5: commit** `feat(constitution): POL-01 schema — principles, when-algebra, graduated section; temporary_exception unauthorable`.

---

### Task 4: Canonicalization + content-hash version

**Files:** Create `version.py`; test `tests/unit/test_constitution_version.py`.

- [ ] **Step 1: failing tests:**

```python
def test_version_is_sha256_prefixed(small_constitution):
    v = constitution_version(small_constitution)
    assert v.startswith("sha256:") and len(v) == 7 + 64


def test_version_invariant_to_principle_and_list_order(small_constitution_factory):
    a = small_constitution_factory(order="forward")    # same content, different YAML order
    b = small_constitution_factory(order="reversed")
    assert constitution_version(a) == constitution_version(b)


def test_version_changes_when_statement_changes(small_constitution_factory):
    a = small_constitution_factory()
    b = small_constitution_factory(statement_suffix=" v2")
    assert constitution_version(a) != constitution_version(b)
```

(Define the small fixtures in the test file: 2 principles + 1 list, factory reorders
`principles` and list values.)

- [ ] **Step 3: implement `version.py`:** `canonical_form(c) -> dict` = `model_dump(mode="json")`
with principles sorted by id (natural numeric segments: `tuple(int(x) for x in id.split(".")`),
list values sorted+deduped, `per_action_type` keys sorted; `constitution_version(c) -> str` =
`"sha256:" + sha256(canonical_json(canonical_form(c))).hexdigest()` — reuse the canonical-JSON
idiom (sorted keys, compact separators) locally; do NOT import from controlplane.
- [ ] **Step 4: green.** **Step 5: commit** `feat(constitution): canonical form + content-hash version (POL-08 key)`.

---

### Task 5: Compiler — YAML middle layer + Rego generation (POL-02)

**Files:** Create `compiler.py`; tests `tests/unit/test_constitution_compiler.py` + golden
fixtures `tests/golden/constitution_small.yaml`, `tests/golden/expected_small.rego`,
`tests/golden/expected_small_policy.yaml`.

- [ ] **Step 1: failing tests:**

```python
GOLDEN = Path("tests/golden")

def _compile_small():
    c = load_constitution(GOLDEN / "constitution_small.yaml")
    return compile_constitution(c)


def test_golden_rego_bytes():
    assert _compile_small().rego == (GOLDEN / "expected_small.rego").read_text(encoding="utf-8")


def test_golden_yaml_policy_bytes():
    assert _compile_small().yaml_policy == (GOLDEN / "expected_small_policy.yaml").read_text(encoding="utf-8")


def test_compile_is_deterministic():
    assert compile_constitution(load_constitution(GOLDEN / "constitution_small.yaml")).rego == _compile_small().rego


def test_every_rule_cites_a_real_principle():          # provenance round-trip
    bundle = _compile_small()
    refs = set(re.findall(r'"principle_ref":\s*"([^"]+)"', bundle.rego))
    c = load_constitution(GOLDEN / "constitution_small.yaml")
    assert refs == {p.id for p in c.principles}


def test_any_lowers_to_multiple_rules():               # DNF: OR = separate rules
    bundle = _compile_small()                          # fixture includes one `any` principle
    assert bundle.rego.count('matched contains {"principle_ref": "2.1"') == 2


def test_sequence_principle_emits_membership_rule_and_metadata():
    bundle = _compile_small()
    assert '"3.5" in input.sequence.matched_refs' in bundle.rego
    assert {"principle_ref": "3.5", "intent_classes": ["RESOURCE_RENAME", "DATA_DESTRUCTION"],
            "effect": "deny"} in bundle.sequences


def test_bundle_carries_version_and_config():
    bundle = _compile_small()
    assert bundle.constitution_version.startswith("sha256:")
    assert bundle.graduated_config["default"]["deny_at"] == 0.7
    assert bundle.input_schema_version == 1
```

- [ ] **Step 2:** author `tests/golden/constitution_small.yaml`:

```yaml
schema_version: 1
name: golden-small
lists:
  egress_allowlist: [api.example.com]
graduated:
  default: {sandbox_at: 0.4, deny_at: 0.7, trust_harden_at: 0.2}
principles:
  - id: "1.1"
    title: Egress allowlist
    statement: An agent may only make outbound requests to allowlisted hosts.
    applies_to: [tool_call]
    effect: deny
    when: {field: egress.host, op: not_in, list_ref: egress_allowlist}
  - id: "2.1"
    title: Destructive or exfiltrating intent requires approval
    statement: Destructive or exfiltrating actions require human approval.
    effect: require_approval
    when:
      any:
        - {field: intent.class, op: eq, value: DATA_DESTRUCTION}
        - {field: intent.class, op: eq, value: DATA_EXFILTRATION}
  - id: "3.2"
    title: PII never leaves approved hosts
    statement: An agent must never send user PII to a host outside the approved allowlist.
    applies_to: [tool_call, mcp_call]
    effect: deny
    when:
      all:
        - {field: guardrails.pii, op: eq, value: true}
        - {field: egress.host, op: not_in, list_ref: egress_allowlist}
  - id: "3.5"
    title: Rename-then-drop is forbidden
    statement: A rename followed by destruction of the renamed resource is forbidden, even when each step looks benign alone.
    kind: sequence
    sequence: [RESOURCE_RENAME, DATA_DESTRUCTION]
    effect: deny
```

- [ ] **Step 3: implement `compiler.py`.** Core pieces (complete logic, mechanical glue at the
implementer's discretion — golden files lock the exact bytes):

```python
@dataclass(frozen=True)
class CompiledBundle:
    constitution_version: str
    input_schema_version: int
    yaml_policy: str          # the reviewable middle layer
    rego: str                 # deterministic Rego, one entrypoint agentos/constitution/result
    sequences: list[dict]     # [{principle_ref, intent_classes, effect}] for the Slice-7 correlator
    graduated_config: dict    # from the graduated: section (defaults if absent)
    lists: dict[str, list[str]]   # runtime data document (set_data({"lists": ...}))


# ---- condition lowering ----
def _to_dnf(node) -> list[list[tuple[Leaf, bool]]]:
    """Normalize to a list of disjuncts; each disjunct is [(leaf, negated)].
    not(all) / not(any) via De Morgan; not(leaf) -> (leaf, True). Depth<=3 keeps the
    product expansion tiny (validated at schema level)."""

_OP_TEMPLATES = {
    "eq":     "input.{f} == {v}",
    "ne":     "input.{f} != {v}",
    "in":     "input.{f} in {v}",          # {v} = set literal or data.lists.<name>
    "not_in": "not input.{f} in {v}",
    "prefix": "startswith(input.{f}, {v})",
    "glob":   'glob.match({v}, ["."], input.{f})',
    "gte":    "input.{f} >= {v}",
    "lte":    "input.{f} <= {v}",
}
# leaf lowering: values via json.dumps (str quoting/escaping; true/false; numbers);
# list values -> "{" + ", ".join(sorted(json.dumps(x))) + "}"; list_ref -> f"data.lists.{name}".
# negated leaf: not_in negates to plain `in`; others wrap with `not (...)` /
# invert (eq<->ne). Keep it simple and DETERMINISTIC; golden tests lock the output.


def _principle_rules(p: Principle) -> str:
    # comment block: "# Principle {id} — {title}" + "# " per statement line
    # scope line (when applies_to != "all"): input.type in {"tool_call", ...} (sorted)
    # action kind: one rule per DNF disjunct; body lines sorted? NO — preserve lowering order
    #   (deterministic by construction), one condition per line, tab-indented (match egress.rego)
    # sequence kind: single rule, body line: "{id}" in input.sequence.matched_refs
    # rule head: matched contains {"principle_ref": "<id>", "effect": "<effect>"} if { ... }


REGO_HEADER = """# GENERATED by agentos-constitution — DO NOT EDIT.
# constitution_version: {version}
# policy_input_schema_version: {schema_v}
package agentos.constitution

import rego.v1

"""
# footer:
# result := {"matched": matched, "no_match": count(matched) == 0}
```

YAML middle layer (`yaml_policy`): `yaml.safe_dump` (sort_keys=True, default_flow_style=False,
allow_unicode=True) of `{"constitution_version": ..., "policies": [per-principle docs in
canonical id order: {id, title, statement (verbatim), kind, applies_to, effect, side_effects,
condition (the raw when dump) | sequence}]}`.

`compile_constitution(c)`: canonical-sort principles (Task 4 helper), build yaml_policy, rego
(header + rules in id order + footer), sequences metadata, graduated_config
(`c.graduated.model_dump()` or defaults), lists from canonical form.

- [ ] **Step 4:** generate the two golden files BY RUNNING the compiler once
(`python -c "...write bundle.rego/yaml_policy to tests/golden/expected_small*"`), then
**manually inspect them** for correctness (rules cite right principles, conditions correct,
`2.1` appears twice, scope lines right) before committing — goldens lock what you inspected.
Then all tests green; verify with the vendored CLI: `./tools/opa/opa.exe check --strict <tmp rego file>` exits 0 (add it as a test that writes `bundle.rego` to `tmp_path`).
- [ ] **Step 5: commit** `feat(constitution): deterministic Constitution->YAML->Rego compiler with provenance + golden lock (POL-02)`.

---

### Task 6: WASM build + behavioral evaluation (the proof)

**Files:** Create `wasm.py`; test `tests/integration/test_constitution_wasm.py`.

- [ ] **Step 1: failing tests:**

```python
"""Compile golden constitution -> WASM via vendored OPA -> evaluate via opa-wasmtime."""
import pytest
from pathlib import Path
from agentos_constitution import compile_constitution, load_constitution
from agentos_constitution.wasm import build_wasm

OPA = Path("tools/opa/opa.exe")
pytestmark = pytest.mark.skipif(not OPA.exists(), reason="vendored OPA CLI not present")


@pytest.fixture(scope="module")
def policy(tmp_path_factory):
    from opa_wasmtime import OPAPolicy
    bundle = compile_constitution(load_constitution(Path("tests/golden/constitution_small.yaml")))
    wasm = build_wasm(bundle.rego, tmp_path_factory.mktemp("wasm"))
    p = OPAPolicy(str(wasm))
    p.set_data({"lists": bundle.lists})
    return p


def _result(p, inp):
    r = p.evaluate(inp)
    return r[0]["result"]


def test_unlisted_host_matches_egress_principle(policy):
    r = _result(policy, {"type": "tool_call", "egress": {"host": "attacker.example"}})
    assert {"principle_ref": "1.1", "effect": "deny"} in r["matched"]
    assert r["no_match"] is False


def test_pii_to_unlisted_host_fires_both_deny_principles(policy):
    r = _result(policy, {"type": "tool_call", "egress": {"host": "attacker.example"},
                         "guardrails": {"pii": True}})
    refs = {m["principle_ref"] for m in r["matched"]}
    assert {"1.1", "3.2"} <= refs


def test_destruction_intent_requires_approval_any_branch(policy):
    for intent in ("DATA_DESTRUCTION", "DATA_EXFILTRATION"):
        r = _result(policy, {"type": "memory_access", "intent": {"class": intent}})
        assert {"principle_ref": "2.1", "effect": "require_approval"} in r["matched"]


def test_sequence_membership_rule(policy):
    r = _result(policy, {"type": "tool_call", "egress": {"host": "api.example.com"},
                         "sequence": {"matched_refs": ["3.5"]}})
    assert {"principle_ref": "3.5", "effect": "deny"} in r["matched"]


def test_benign_input_is_no_match(policy):
    r = _result(policy, {"type": "tool_call", "egress": {"host": "api.example.com"}})
    assert r["matched"] == [] and r["no_match"] is True


def test_precedence_select_floor_on_conflict(policy):
    """allow+deny both matched -> select_floor picks deny (deny-overrides-allow)."""
    from agentos_contract.policy_io import MatchedPrinciple, select_floor
    from agentos_contract import Outcome
    r = _result(policy, {"type": "tool_call", "egress": {"host": "attacker.example"},
                         "sequence": {"matched_refs": ["3.5"]}, "intent": {"class": "DATA_DESTRUCTION"}})
    matched = [MatchedPrinciple(principle_ref=m["principle_ref"], effect=m["effect"]) for m in r["matched"]]
    assert len(matched) >= 3            # 1.1 deny, 2.1 require_approval, 3.5 deny
    assert select_floor(matched) is Outcome.deny
```

- [ ] **Step 2: implement `wasm.py`:**

```python
OPA_BIN = Path(__file__).resolve().parents[4] / "tools" / "opa" / "opa.exe"   # repo-root anchored; verify depth!

def build_wasm(rego_text: str, out_dir: Path) -> Path:
    """opa build -t wasm -e agentos/constitution/result; extract /policy.wasm."""
    rego = out_dir / "constitution.rego"; rego.write_text(rego_text, encoding="utf-8")
    bundle = out_dir / "bundle.tar.gz"
    subprocess.run([str(OPA_BIN), "build", "-t", "wasm",
                    "-e", "agentos/constitution/result", str(rego), "-o", str(bundle)],
                   check=True, capture_output=True)
    with tarfile.open(bundle) as tf:                    # member is "/policy.wasm"
        member = next(m for m in tf.getmembers() if m.name.lstrip("/") == "policy.wasm")
        tf.extract(member, out_dir, filter="data")
    extracted = out_dir / "policy.wasm"
    if not extracted.exists():                          # extraction may preserve the leading path
        extracted = next(out_dir.rglob("policy.wasm"))
    return extracted
```

(Adapt the OPA_BIN parents[] depth to the actual file location — write a quick assert/test.
The smoke script `scripts/smoke_opa_wasmtime.py` shows the exact build/extract recipe that
already works on this machine — mirror it.)

- [ ] **Step 3: green** (these are the behavioral proof of the whole slice).
- [ ] **Step 4: commit** `feat(constitution): WASM build via vendored OPA + behavioral eval proof (POL-02)`.

---

### Task 7: Example operator constitution + full-suite gate

**Files:** Create `policies/constitution.yaml`; test additions in
`tests/unit/test_constitution_schema.py`.

- [ ] **Step 1:** author `policies/constitution.yaml` — the real example operators copy. Same
principles as the golden fixture (1.1, 2.1, 3.2, 3.5 — these ARE the Phase-3 wedge: PII egress +
rename_then_drop) plus a `4.1` governance_review example:

```yaml
  - id: "4.1"
    title: External sends proceed under governance review
    statement: Outbound communication to approved hosts proceeds, but is opened for asynchronous governance review.
    applies_to: [tool_call]
    effect: governance_review
    when: {field: egress.host, op: in, list_ref: egress_allowlist}
    side_effects: [notify]
```

- [ ] **Step 2: test** (append): `policies/constitution.yaml` loads, compiles, version stable,
`opa check --strict` passes on its rego (reuse the tmp-file check pattern from Task 5).
- [ ] **Step 3:** FULL suite: `./.venv/Scripts/python.exe -m pytest -q` → everything green
(expect ~600+ passed, 2 xfailed; zero regressions — this slice only ADDS files except the two
contract/root-pyproject touches).
- [ ] **Step 4: commit** `feat(constitution): example operator constitution with wedge principles (POL-01)`.

---

## Self-review checklist (run before reporting)
- POL-01: schema + example constitution + load path ✓ (Tasks 3, 7)
- POL-02: deterministic compile → YAML → Rego, provenance, precedence, golden lock, WASM proof ✓ (Tasks 1, 5, 6)
- temporary_exception unauthorable ✓ (Task 3); sequences → Slice-7 seam ✓ (Tasks 3, 5, 6)
- No placeholder steps; types consistent across tasks (Leaf/Node names, CompiledBundle fields,
  select_floor signature); egress.rego/engine untouched; only `packages/contract/__init__`,
  `policy_io.py`, root `pyproject.toml` + new files modified/created.
