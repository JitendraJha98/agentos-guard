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


def test_not_combinator_non_readlike_memory_write_requires_approval(policy):
    """5.1: not(any(eq read, eq list)) — De Morgan lowers to two != lines."""
    write = _result(policy, {"type": "memory_access", "memory": {"operation": "write"}})
    assert {"principle_ref": "5.1", "effect": "require_approval"} in write["matched"]
    read = _result(policy, {"type": "memory_access", "memory": {"operation": "read"}})
    assert "5.1" not in {m["principle_ref"] for m in read["matched"]}


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
