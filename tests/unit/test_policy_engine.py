"""Unit tests for the WasmPolicyEngine (01-04 Task 3, POL-03 / D-05).

Realizes the <behavior> cases from 01-04-PLAN.md:
  - allowlisted host  -> allow (code "egress_allowlisted")
  - attacker host     -> deny  (code "egress_allowlist_violation")
  - the WASM bundle is loaded ONCE at construction (Pitfall 2 — never per request)
  - WasmPolicyEngine satisfies the PolicyEngine Protocol (structural typing)

These tests run against the compiled `policies/build/egress.wasm` (a CI/build
artifact, `opa build -t wasm`). If the artifact is genuinely absent (no OPA CLI
in the dev env), the suite skips with a clear message — the wave-merge CI step
compiles it before running tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agentos_contract import Outcome
from agentos_pipeline.policy import PolicyEngine, PolicyResult, WasmPolicyEngine

REPO_ROOT = Path(__file__).resolve().parents[2]
WASM_PATH = REPO_ROOT / "policies" / "build" / "egress.wasm"

ALLOWLIST = ["api.example.com"]
ALLOW_INPUT = {"type": "tool_call", "host": "api.example.com", "method": "GET"}
DENY_INPUT = {"type": "tool_call", "host": "attacker.example", "method": "GET"}


pytestmark = pytest.mark.skipif(
    not WASM_PATH.is_file(),
    reason=(
        f"compiled egress.wasm not found at {WASM_PATH} — run "
        "`opa build -t wasm -e 'agentos/egress/allow' policies/egress.rego` first "
        "(the wave-merge CI step does this)."
    ),
)


@pytest.fixture
def engine() -> WasmPolicyEngine:
    """A single WasmPolicyEngine, loaded ONCE (mirrors startup construction)."""
    return WasmPolicyEngine(str(WASM_PATH), allowlist=ALLOWLIST)


def test_allowlisted_host_allowed(engine: WasmPolicyEngine) -> None:
    result = engine.evaluate(ALLOW_INPUT)
    assert isinstance(result, PolicyResult)
    assert result.outcome is Outcome.allow
    assert result.code == "egress_allowlisted"
    assert result.policy_id == "egress.allow"


def test_attacker_host_denied(engine: WasmPolicyEngine) -> None:
    result = engine.evaluate(DENY_INPUT)
    assert result.outcome is Outcome.deny
    assert result.code == "egress_allowlist_violation"
    assert result.policy_id == "egress.allow"


def test_mixed_case_allowlist_entry_matches_lowercased_host() -> None:
    """CR-02: a mixed-case allowlist entry must still match the host.

    `_host` (urlsplit.hostname) always lowercases, so without canonicalizing the
    allowlist a mixed-case entry like `API.Example.COM` could never match the
    lowercased host `api.example.com` — a silent fail-deny. The engine must
    lowercase (and strip) each allowlist entry at construction.
    """
    engine = WasmPolicyEngine(str(WASM_PATH), allowlist=["  API.Example.COM  "])
    result = engine.evaluate(ALLOW_INPUT)  # host == "api.example.com"
    assert result.outcome is Outcome.allow
    assert result.code == "egress_allowlisted"
    assert result.policy_id == "egress.allow"


def test_wasm_loaded_once_not_per_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the engine loads OPAPolicy exactly once; evaluate() must not
    reload it (Pitfall 2 — load once at startup, never per request)."""
    import agentos_pipeline.policy as policy_mod

    load_count = {"n": 0}
    real_opapolicy = policy_mod.OPAPolicy

    def counting_opapolicy(*args, **kwargs):
        load_count["n"] += 1
        return real_opapolicy(*args, **kwargs)

    monkeypatch.setattr(policy_mod, "OPAPolicy", counting_opapolicy)

    eng = WasmPolicyEngine(str(WASM_PATH), allowlist=ALLOWLIST)
    assert load_count["n"] == 1  # constructed once at __init__

    for _ in range(10):
        eng.evaluate(ALLOW_INPUT)
        eng.evaluate(DENY_INPUT)

    assert load_count["n"] == 1  # never reloaded per request


def test_satisfies_policy_engine_protocol(engine: WasmPolicyEngine) -> None:
    """WasmPolicyEngine is usable wherever the PolicyEngine Protocol is expected."""
    assert isinstance(engine, PolicyEngine)


@pytest.mark.parametrize(
    "action_type", ["model_invocation", "memory_access", "mcp_call", "delegation"]
)
def test_non_tool_action_types_pass_egress_floor(
    engine: WasmPolicyEngine, action_type: str
) -> None:
    """Phase 2 (INT-02..05): the egress principle governs tool egress only.

    Non-tool action types pass this floor (with NO host, even against an allowlist
    they are not on) and carry a type-appropriate reason — never the egress-allowlist
    claim, which the engine did not actually check for them. Their own deterministic
    policies arrive in Phase 3.
    """
    result = engine.evaluate({"type": action_type})
    assert result.outcome is Outcome.allow
    assert result.code == "no_egress_policy_applicable"
    assert result.policy_id == "egress.allow"


def test_tool_call_still_deny_by_default_after_phase2(engine: WasmPolicyEngine) -> None:
    """The non-tool clause must not weaken the tool_call deny-by-default floor (D-04)."""
    result = engine.evaluate({"type": "tool_call", "host": "attacker.example"})
    assert result.outcome is Outcome.deny
    assert result.code == "egress_allowlist_violation"
