package agentos.egress_test

import rego.v1

import data.agentos.egress

# Deterministic opa-test coverage for the egress-allowlist principle (D-02).
# `with data.allowlist as [...]` injects the host list the same way the engine
# does at runtime (set_data), so these tests exercise the real rule logic.

test_allowlisted_host_allowed if {
	egress.allow with input as {"type": "tool_call", "host": "api.example.com"}
		with data.allowlist as ["api.example.com"]
}

test_attacker_host_denied if {
	not egress.allow with input as {"type": "tool_call", "host": "attacker.example"}
		with data.allowlist as ["api.example.com"]
}

# Phase 2 (INT-02..05): non-tool action types are not governed by the egress
# principle and therefore pass this floor, regardless of allowlist contents.
test_model_invocation_not_governed_by_egress if {
	egress.allow with input as {"type": "model_invocation"}
		with data.allowlist as ["api.example.com"]
}

test_memory_access_not_governed_by_egress if {
	egress.allow with input as {"type": "memory_access"}
		with data.allowlist as []
}

test_mcp_call_not_governed_by_egress if {
	egress.allow with input as {"type": "mcp_call"}
		with data.allowlist as []
}

test_delegation_not_governed_by_egress if {
	egress.allow with input as {"type": "delegation"}
		with data.allowlist as []
}
