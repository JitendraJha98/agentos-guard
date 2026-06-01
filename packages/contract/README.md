# agentos-contract

The stable, serializable contract package (PIPE-07 / D-08). It defines
`AgentAction`, `Decision`, `RiskFinding`, the `RiskScorer` Protocol, and the
`PipelineProtocol` — the single boundary every Policy Enforcement Point (SDK
now, gateway Phase 10, sidecar Phase 14) plugs into without change. It has zero
internal dependencies by design.
