"""ConstitutionPolicyEngine — the multi-principle compiled-constitution floor
(Slice-3 Task 4; POL-03 / PIPE-06 / POL-08).

Replaces the Phase-1 egress-engine tests: the engine evaluates the COMPILED
TEST CONSTITUTION (tests/fixtures/test_constitution.yaml) and returns the D4
ConstitutionResult (matched principles + no_match), exposes content-hash
versions for POL-08 stamping, reloads on version change (the compiled-policy
cache invalidation, PIPE-06), and fails CLOSED on any malformed WASM result.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from _opa import build_constitution_wasm, find_opa

from agentos_contract.policy_io import ConstitutionResult
from agentos_pipeline.policy import (
    ConstitutionPolicyEngine,
    PolicyEngine,
    PolicyEvaluationError,
)

pytestmark = pytest.mark.skipif(find_opa() is None, reason="no OPA binary")

CONSTITUTION = Path("tests/fixtures/test_constitution.yaml")
NO_EGRESS = Path("tests/fixtures/test_constitution_no_egress.yaml")


def _engine_from(built) -> ConstitutionPolicyEngine:
    return ConstitutionPolicyEngine(
        wasm_path=str(built.wasm_path),
        lists=built.bundle.lists,
        constitution_version=built.bundle.constitution_version,
        principles_meta=built.principles_meta,
    )


@pytest.fixture(scope="module")
def engine(tmp_path_factory) -> ConstitutionPolicyEngine:
    built = build_constitution_wasm(CONSTITUTION, tmp_path_factory.mktemp("wasm"))
    return _engine_from(built)


def test_unlisted_host_matches_egress_principle(engine) -> None:
    r = engine.evaluate({"type": "tool_call", "egress": {"host": "attacker.example"}})
    assert isinstance(r, ConstitutionResult) and not r.no_match
    assert any(m.principle_ref == "1.1" and m.effect == "deny" for m in r.matched)


def test_benign_input_is_no_match(engine) -> None:
    r = engine.evaluate(
        {"type": "tool_call", "egress": {"host": "api.example.com"}, "intent": {"class": ""}}
    )
    assert r.no_match and r.matched == ()


def test_destructive_intent_matches_approval_principle(engine) -> None:
    r = engine.evaluate(
        {"type": "memory_access", "intent": {"class": "DATA_DESTRUCTION"}}
    )
    assert any(
        m.principle_ref == "2.1" and m.effect == "require_approval" for m in r.matched
    )


def test_versions_exposed(engine) -> None:
    assert engine.constitution_version.startswith("sha256:")
    assert engine.policy_version.startswith("sha256:")  # hash of the wasm bytes


def test_principles_meta_exposed(engine) -> None:
    assert engine.principles_meta["1.1"]["title"] == "Egress allowlist"


def test_satisfies_policy_engine_protocol(engine) -> None:
    assert isinstance(engine, PolicyEngine)


def test_reload_invalidates_compiled_policy(tmp_path_factory) -> None:  # PIPE-06
    built_a = build_constitution_wasm(CONSTITUTION, tmp_path_factory.mktemp("wasm_a"))
    built_b = build_constitution_wasm(NO_EGRESS, tmp_path_factory.mktemp("wasm_b"))
    eng = _engine_from(built_a)
    attack = {"type": "tool_call", "egress": {"host": "attacker.example"}}
    assert not eng.evaluate(attack).no_match  # 1.1 fires
    old_policy_version = eng.policy_version
    old_constitution_version = eng.constitution_version
    eng.reload(
        wasm_path=str(built_b.wasm_path),
        lists=built_b.bundle.lists,
        constitution_version=built_b.bundle.constitution_version,
        principles_meta=built_b.principles_meta,
    )
    assert eng.evaluate(attack).no_match  # principle gone -> no match
    assert eng.policy_version != old_policy_version
    assert eng.constitution_version != old_constitution_version


def test_failed_reload_leaves_engine_on_old_policy(tmp_path_factory) -> None:
    """I1: reload must be exception-atomic — a failure mid-reload (set_data raises
    AFTER the new WASM loaded) leaves NO torn state: old WASM + old lists + old
    versions + old meta all still in force."""
    built_a = build_constitution_wasm(CONSTITUTION, tmp_path_factory.mktemp("wasm_atomic_a"))
    built_b = build_constitution_wasm(NO_EGRESS, tmp_path_factory.mktemp("wasm_atomic_b"))
    eng = _engine_from(built_a)
    attack = {"type": "tool_call", "egress": {"host": "attacker.example"}}
    assert not eng.evaluate(attack).no_match  # 1.1 fires on the OLD policy
    old_policy_version = eng.policy_version
    old_constitution_version = eng.constitution_version
    old_meta = eng.principles_meta
    with pytest.raises(Exception):
        eng.reload(
            wasm_path=str(built_b.wasm_path),
            lists={"egress_allowlist": {"not-json-serializable"}},  # set -> set_data raises
            constitution_version="sha256:torn",
            principles_meta={},
        )
    # The OLD policy still evaluates correctly and every version/meta is untouched.
    assert not eng.evaluate(attack).no_match
    assert eng.policy_version == old_policy_version
    assert eng.constitution_version == old_constitution_version
    assert eng.principles_meta == old_meta


def test_malformed_result_fails_closed(engine, monkeypatch) -> None:
    monkeypatch.setattr(engine, "_policy", SimpleNamespace(evaluate=lambda i: [{"weird": 1}]))
    with pytest.raises(PolicyEvaluationError):
        engine.evaluate({"type": "tool_call"})


def test_empty_result_set_fails_closed(engine, monkeypatch) -> None:
    monkeypatch.setattr(engine, "_policy", SimpleNamespace(evaluate=lambda i: []))
    with pytest.raises(PolicyEvaluationError):
        engine.evaluate({"type": "tool_call"})
