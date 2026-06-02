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
