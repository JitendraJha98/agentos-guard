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
untouched, as is every header except the RFC 7230 hop-by-hop set (and whatever the caller's
`Connection` header names), which belongs to the client's connection and stops here.

`upstream_base_url` is the one permitted egress destination: every forward is built from it as an
absolute URL, so an injected `client` cannot redirect governed traffic elsewhere. Upstream
responses are relayed as bytes with their content type, so HTML errors, `204`s and
`text/event-stream` bodies survive the proxy — note that a `"stream": true` response is relayed
*complete* rather than incrementally, because the governed forward is a single awaited call. A
transport failure is a `502` (`agentos_guard_upstream_unreachable`), never a gateway `500`.

Two request shapes are refused before any governance runs, with a `400`
(`agentos_guard_bad_request`) rather than a traceback: a body that is not a JSON object (there is
no action to normalize) and a tool name outside `[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}` (a name that
cannot travel verbatim in the upstream path would be governed as one resource and requested as
another).
