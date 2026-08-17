# agentos-gateway

The framework-agnostic network Policy Enforcement Point (INT-07). It is a reverse proxy: an agent
adopts governance by pointing its `base_url` at the gateway, with **no SDK changes and no framework
support required**. Each incoming request is normalized into an `AgentAction` and handed to the same
`agentos_sdk.enforce.governed_call` core every other PEP form uses, with the upstream forward as the
governed operation — so `allow` proxies and returns the upstream response, while every governed
block (deny, quarantine, budget breach, missing consensus) raises *before* the forward exists and
returns a governed HTTP 403. The gateway contributes normalization and transport only; it never
re-implements the outcome map, so Phase-9 containment applies here unchanged.

The agent's governance token travels in `X-Agentos-Token`, which the gateway CONSUMES and never
forwards upstream; `Authorization` carries the upstream provider credential and is passed through
untouched.
