"""POL-01 schema: structured principles; temporary_exception unauthorable; field registry."""
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError
from agentos_constitution.schema import Constitution, Leaf, Principle, load_constitution

BASE = dict(schema_version=1, name="test")
EXAMPLE = Path("policies/constitution.yaml")
OPA = Path("tools/opa/opa.exe")


def _p(**kw):
    d = dict(id="1.1", title="t", statement="s", effect="deny")
    d.update(kw)
    return d


def test_minimal_constitution_parses():
    c = Constitution(**BASE, principles=[_p(applies_to=["tool_call"],
                                            when={"field": "egress.host", "op": "not_in", "list_ref": "approved_hosts"})],
                     lists={"approved_hosts": ["api.example.com"]})
    assert c.principles[0].id == "1.1"


def test_temporary_exception_effect_rejected():        # POL-13
    with pytest.raises(ValidationError, match="temporary_exception"):
        Constitution(**BASE, principles=[_p(effect="temporary_exception")])


def test_unknown_when_field_rejected():                # registry-validated algebra
    with pytest.raises(ValidationError, match="unknown policy-input field"):
        Constitution(**BASE, principles=[_p(when={"field": "nope.nope", "op": "eq", "value": "x"})])


def test_list_ref_must_exist():
    with pytest.raises(ValidationError, match="unknown list"):
        Constitution(**BASE, principles=[_p(applies_to=["tool_call"],
                                            when={"field": "egress.host", "op": "in", "list_ref": "ghost"})])


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


def test_scoped_field_rejected_when_applies_to_all():  # egress.host is tool_call/mcp_call only
    with pytest.raises(ValidationError, match="subset"):
        Constitution(**BASE, principles=[_p(when={"field": "egress.host", "op": "eq", "value": "x"})])


def test_scoped_field_rejected_outside_its_action_types():
    with pytest.raises(ValidationError, match="subset"):
        Constitution(**BASE, principles=[_p(applies_to=["memory_access"],
                                            when={"field": "egress.host", "op": "eq", "value": "x"})])


def test_title_with_newline_rejected():               # Rego comment-injection gate
    with pytest.raises(ValidationError, match="control"):
        Constitution(**BASE, principles=[_p(title="Benign\ninjected := true")])


def test_statement_with_carriage_return_rejected():
    with pytest.raises(ValidationError, match="control"):
        Constitution(**BASE, principles=[_p(statement="line one\rline two")])


def test_multiline_statement_accepted():
    c = Constitution(**BASE, principles=[_p(statement="line one\nline two")])
    assert c.principles[0].statement == "line one\nline two"


def test_op_type_compatibility():
    with pytest.raises(ValidationError, match="op"):   # prefix on a bool field
        Constitution(**BASE, principles=[_p(when={"field": "guardrails.pii", "op": "prefix", "value": "x"})])


def test_happy_path_full_construction():
    c = Constitution(
        **BASE,
        principles=[
            _p(when={"all": [{"field": "guardrails.pii", "op": "eq", "value": True},
                             {"field": "egress.host", "op": "not_in", "list_ref": "approved_hosts"}]},
               applies_to=["tool_call", "mcp_call"]),
            _p(id="2.1", effect="require_approval",
               when={"any": [{"field": "intent.class", "op": "eq", "value": "DATA_DESTRUCTION"},
                             {"field": "intent.class", "op": "eq", "value": "DATA_EXFILTRATION"}]}),
        ],
        lists={"approved_hosts": ["api.example.com"]},
        graduated={"default": {"sandbox_at": 0.4, "deny_at": 0.7, "trust_harden_at": 0.2}},
    )
    assert [p.id for p in c.principles] == ["1.1", "2.1"]
    assert c.graduated.default.deny_at == 0.7
    assert c.principles[0].applies_to == ["tool_call", "mcp_call"]


# --- Slice 4: authored remediation hints (PIPE-08) ---

def test_remediation_accepted_on_principle():
    c = Constitution(**BASE, principles=[_p(remediation=["Add the host to egress_allowlist"])])
    assert c.principles[0].remediation == ["Add the host to egress_allowlist"]


def test_remediation_defaults_empty():
    c = Constitution(**BASE, principles=[_p()])
    assert c.principles[0].remediation == []


def test_remediation_rejects_more_than_five_items():
    with pytest.raises(ValidationError):
        Constitution(**BASE, principles=[_p(remediation=[f"hint {i}" for i in range(6)])])


def test_remediation_rejects_oversized_item():
    with pytest.raises(ValidationError):
        Constitution(**BASE, principles=[_p(remediation=["a" * 300])])


def test_remediation_rejects_control_chars():
    # Hints flow onto audit-bound Decisions and operator UIs — same control-char
    # discipline as title.
    with pytest.raises(ValidationError, match="control"):
        Constitution(**BASE, principles=[_p(remediation=["line one\nline two"])])


# --- the shipped example operator constitution (POL-01, Task 7) ---

def test_example_constitution_loads_and_compiles_with_stable_version():
    from agentos_constitution import compile_constitution, constitution_version
    c = load_constitution(EXAMPLE)
    assert {p.id for p in c.principles} >= {"1.1", "2.1", "3.2", "3.5", "4.1", "5.1", "5.2"}
    by_id = {p.id: p for p in c.principles}
    assert by_id["4.1"].effect == "governance_review"
    assert by_id["3.5"].kind == "sequence"
    # ECON-02: the shipped budget principles. Named here so deleting one from the example file is a
    # deliberate edit that turns a test red, not a silent removal of the fleet's only spend gate.
    assert by_id["5.1"].effect == "require_approval"
    assert by_id["5.2"].effect == "governance_review"
    bundle = compile_constitution(c)
    assert bundle.constitution_version.startswith("sha256:")
    # stable: re-loading + re-compiling yields the identical version and bytes
    again = compile_constitution(load_constitution(EXAMPLE))
    assert again.constitution_version == bundle.constitution_version
    assert again.rego == bundle.rego


@pytest.mark.skipif(not OPA.exists(), reason="vendored OPA CLI not present")
def test_example_constitution_rego_passes_opa_check_strict(tmp_path):
    from agentos_constitution import compile_constitution
    bundle = compile_constitution(load_constitution(EXAMPLE))
    rego_path = tmp_path / "constitution.rego"
    rego_path.write_text(bundle.rego, encoding="utf-8")
    proc = subprocess.run([str(OPA), "check", "--strict", "constitution.rego"],
                          capture_output=True, text=True, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
