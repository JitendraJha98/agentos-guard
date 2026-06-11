"""The decision pipeline runner — PIPE-01 / PIPE-02 / PIPE-03 (the PDP).

Source: 01-RESEARCH.md § "Pipeline Composition" (the async `evaluate` with ordered
stages, reason accumulation, identity short-circuit, audit-before-return) and
01-AI-SPEC.md §4b ("Async-First Design"); CONTEXT.md D-07/D-09.

`Pipeline.evaluate(action) -> Decision` is the one stable PEP<->PDP seam (it satisfies
`PipelineProtocol`). It is an in-process library call (D-07) — no network endpoint.
The four real stages run in order and each contributes machine-readable `reasons`:

    1. identity & trust  — verify the token; short-circuit to a terminal, audited deny
                           on forged/unknown identity WITHOUT running later stages (PIPE-03)
    2. policy            — the deterministic OPA WASM floor (authoritative)
    3. risk              — inline, pure-CPU prompt-injection scoring (advisory)
    4. graduated         — {policy, risk, trust} -> outcome, never relaxing the floor

Async discipline (AI-SPEC §4b): `evaluate` is `async` because the audit write is async;
the CPU-bound stages (`policy.evaluate`, `assess_risk`, `graduated_response`) stay plain
calls run inline within the coroutine. The runner NEVER spins a nested event loop — it
is already invoked from a running loop, so doing so would raise RuntimeError (AI-SPEC §4b).

The collaborators (identity stage, policy engine, scorers, audit writer) are injected and
typed structurally, so this package keeps its single internal dependency on
`agentos-contract` and never imports the control plane.
"""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from agentos_contract import AgentAction, Decision, Outcome, Reason, RiskScorer

from agentos_pipeline.graduated import GraduatedThresholds, graduated_response
from agentos_pipeline.identity import IdentityStage, IdentityVerdict
from agentos_pipeline.policy import PolicyResult
from agentos_pipeline.policy_input import _host
from agentos_pipeline.risk import assess_risk


class _PolicyEngine(Protocol):
    def evaluate(self, input: dict) -> PolicyResult: ...


class _AuditWriter(Protocol):
    async def append(self, action: AgentAction, decision: Decision) -> UUID: ...


class Pipeline:
    """The 4-stage PDP (async evaluate; CPU stages inline). Satisfies PipelineProtocol."""

    def __init__(
        self,
        *,
        identity: IdentityStage,
        policy: _PolicyEngine,
        scorers: list[RiskScorer],
        audit: _AuditWriter,
        thresholds: GraduatedThresholds = GraduatedThresholds(),
    ) -> None:
        self._identity = identity
        self._policy = policy
        self._scorers = scorers
        self._audit = audit
        self._thresholds = thresholds  # POL-06: injectable graduated risk bands

    async def evaluate(self, action: AgentAction) -> Decision:
        reasons: list[Reason] = []

        # Stage 1 — Identity & Trust (IDN-02, TRST-01); short-circuit on forged/unknown.
        ident: IdentityVerdict = self._identity.verify(action)
        if not ident.ok:
            reasons.append(
                Reason(
                    stage="identity",
                    code="forged_or_unknown_identity",
                    detail=ident.detail,
                )
            )
            decision = Decision(action_id=action.id, outcome=Outcome.deny, reasons=reasons)
            # Audited even on deny — evidence exists before enforcement (PIPE-03/AUD-01).
            decision.evidence_ref = await self._audit.append(action, decision)
            return decision  # TERMINAL — no later stages
        trust = ident.trust_score
        # Identity verified — record the stage that ran so every stage contributes a
        # machine-readable reason on the success path too (PIPE-02).
        reasons.append(Reason(stage="identity", code="identity_verified", detail=ident.detail))

        # Stage 2 — Policy (POL-03): the deterministic floor.
        pol = self._policy.evaluate(
            {"host": _host(action), "method": "GET", "type": action.type.value}
        )
        reasons.append(
            Reason(stage="policy", code=pol.code, policy_id=pol.policy_id, detail=pol.detail)
        )

        # Stage 3 — Risk (SEC-01): inline, pure-CPU (plain call — not awaited).
        risk_score, findings = assess_risk(action, self._scorers)
        for finding in findings:
            reasons.append(
                Reason(stage="risk", code=finding.category, detail=finding.detail)
            )

        # Stage 4 — Graduated (POL-06): risk/trust may only RESTRICT the policy floor.
        outcome = graduated_response(pol.outcome, risk_score, trust, self._thresholds)
        reasons.append(Reason(stage="graduated", code=outcome.value))

        decision = Decision(
            action_id=action.id,
            outcome=outcome,
            risk_score=risk_score,
            trust_score=trust,
            reasons=reasons,
        )
        # SYNC audit write on the hot path (AUD-01); sets evidence_ref before returning.
        decision.evidence_ref = await self._audit.append(action, decision)
        return decision
