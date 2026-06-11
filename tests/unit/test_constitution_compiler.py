"""POL-02 compiler: deterministic Constitution -> YAML -> Rego, golden-locked."""
import re
import subprocess
from pathlib import Path

import pytest

from agentos_constitution import load_constitution
from agentos_constitution.compiler import compile_constitution

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


@pytest.mark.skipif(not OPA.exists(), reason="vendored OPA CLI not present")
def test_generated_rego_passes_opa_check_strict(tmp_path):
    rego_path = tmp_path / "constitution.rego"
    rego_path.write_text(_compile_small().rego, encoding="utf-8")
    proc = subprocess.run([str(OPA), "check", "--strict", str(rego_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
