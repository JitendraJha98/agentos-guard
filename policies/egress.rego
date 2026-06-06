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
