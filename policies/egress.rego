package agentos.egress

import rego.v1

# D-02 — the single Phase-1 Constitution principle, authored directly as Rego:
# "an agent may only make outbound requests to allowlisted hosts" (egress
# data-exfiltration control). Deny-by-default is the floor (T-01-13): an action
# is denied unless it explicitly matches the allow rule.
#
# The principle (the rule logic) stays in Rego; the concrete hosts are supplied
# as a Rego `data` document at startup via OPAPolicy.set_data({"allowlist": [...]})
# (Claude's discretion, D-05 note). This keeps the rule in Rego while letting the
# host list be configuration — and lets the red-team test mutate the allowlist
# without recompiling the WASM bundle.
default allow := false

allow if {
	input.type == "tool_call"
	input.host in data.allowlist
}

# Phase 2 (INT-02..05): the egress principle governs OUTBOUND TOOL egress only.
# Model / memory / MCP / delegation actions are not outbound HTTP egress, so this
# principle does not apply to them — they pass this floor and are still fully
# intercepted, risk-scored, graduated, and audited through the same pipeline.
# Their own deterministic policies arrive in Phase 3 (Constitution → YAML → Rego).
# tool_call stays deny-by-default above, so the D-04 red-team gate is unchanged.
allow if {
	input.type != "tool_call"
}
