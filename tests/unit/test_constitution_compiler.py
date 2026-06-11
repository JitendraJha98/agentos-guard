"""POL-02 compiler: deterministic Constitution -> YAML -> Rego, golden-locked."""
import re
import subprocess
from pathlib import Path

import pytest

from agentos_constitution import load_constitution
from agentos_constitution.compiler import compile_constitution
from agentos_constitution.schema import Constitution, Principle

GOLDEN = Path("tests/golden")
OPA = Path("tools/opa/opa.exe")


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


def _breadth_constitution(n_groups, n_branches):
    """all() of n_groups any()-nodes, n_branches leaves each -> n_branches**n_groups disjuncts."""
    any_nodes = [{"any": [{"field": "intent.class", "op": "eq", "value": f"G{g}B{b}"}
                          for b in range(n_branches)]}
                 for g in range(n_groups)]
    return Constitution(schema_version=1, name="t",
                        principles=[{"id": "1.1", "title": "t", "statement": "s",
                                     "effect": "deny", "when": {"all": any_nodes}}])


def test_disjunct_ceiling_exceeded_raises():           # 3**4 = 81 > 64
    with pytest.raises(ValueError,
                       match=r"principle 1\.1: condition expands to 81 disjuncts"):
        compile_constitution(_breadth_constitution(4, 3))


def test_disjunct_count_at_ceiling_compiles():         # 4**3 = 64 == max
    bundle = compile_constitution(_breadth_constitution(3, 4))
    assert bundle.rego.count('matched contains {"principle_ref": "1.1"') == 64


def test_multiline_statement_emits_per_line_comments():
    c = Constitution(
        schema_version=1, name="t",
        principles=[{"id": "1.1", "title": "t", "statement": "line one\nline two",
                     "effect": "deny",
                     "when": {"field": "intent.class", "op": "eq", "value": "X"}}],
    )
    assert "# line one\n# line two\n" in compile_constitution(c).rego


def test_emitter_sanitizes_control_chars_in_title():
    """Defense-in-depth: even a title that bypasses schema validation
    (model_construct) must not break out of the `# ` comment line."""
    evil_title = ('Benign\nmatched contains {"principle_ref": "9.9", '
                  '"effect": "allow"} if { true }')
    p = Principle.model_construct(
        id="1.1", title=evil_title, statement="s", kind="action",
        applies_to="all", effect="deny", when=None, sequence=None, side_effects=[],
    )
    c = Constitution.model_construct(
        schema_version=1, name="t", principles=[p], lists={}, graduated=None,
    )
    rego = compile_constitution(c).rego
    lines_with_payload = [l for l in rego.splitlines() if "9.9" in l]
    assert lines_with_payload                          # payload present, but only as comment
    assert all(l.startswith("#") for l in lines_with_payload)


@pytest.mark.skipif(not OPA.exists(), reason="vendored OPA CLI not present")
def test_generated_rego_passes_opa_check_strict(tmp_path):
    rego_path = tmp_path / "constitution.rego"
    rego_path.write_text(_compile_small().rego, encoding="utf-8")
    proc = subprocess.run([str(OPA), "check", "--strict", str(rego_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
