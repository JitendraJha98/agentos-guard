"""The decision pipeline runner — PIPE-01 / PIPE-02 / PIPE-03 / PIPE-05 (the PDP).

Source: 01-RESEARCH.md § "Pipeline Composition" (the async `evaluate` with ordered
stages, reason accumulation, identity short-circuit, audit-before-return) and
01-AI-SPEC.md §4b ("Async-First Design"); CONTEXT.md D-07/D-09; Phase-3 overview
D4/D6 (enrichment-fed constitution floor, posture semantics).

`Pipeline.evaluate(action) -> Decision` is the one stable PEP<->PDP seam (it satisfies
`PipelineProtocol`). It is an in-process library call (D-07) — no network endpoint.
The stages run in order and each contributes machine-readable `reasons` (D6 order):

    1. identity & trust  — verify the token; short-circuit to a terminal, audited deny
                           on forged/unknown identity WITHOUT running later stages (PIPE-03)
    2. enrichment        — deterministic intent tag + guardrail flags (SEC-12, pure CPU)
    3. policy            — the compiled-constitution WASM floor (authoritative);
                           no-match floor = the per-action-class posture (D4)
    4. risk              — inline, pure-CPU scoring (advisory)
    5. graduated         — {floor, risk, trust} -> outcome, never relaxing the floor

Failure semantics (PIPE-05): ANY unhandled control-plane failure falls to the
per-action-class `PostureMap` — closed classes deny, explicitly-opened classes
allow ONLY with a written audit record (no record -> no allow). The fail-safe
audit record is payload-free (the payload may be the thing that failed redaction).
Every Decision pins constitution_version + policy_version (POL-08).

Async discipline (AI-SPEC §4b): `evaluate` is `async` because the audit write is async;
the CPU-bound stages stay plain calls run inline within the coroutine. The runner NEVER
spins a nested event loop.

The collaborators (identity stage, policy engine, scorers, audit writer) are injected
and typed structurally, so this package keeps its single internal dependency on
`agentos-contract` and never imports the control plane. That is also why redaction
failures are detected structurally (`_is_redaction_error` checks the exception's MRO
class names) instead of importing the control plane's RedactionError type.
"""

from __future__ import annotations

from typing import Protocol, Sequence
from uuid import UUID

from agentos_contract import AgentAction, Decision, Outcome, Reason, RiskScorer
from agentos_contract.policy_io import (
    OUTCOME_RESTRICTIVENESS,
    ConstitutionResult,
    select_floor,
)

from agentos_pipeline.enrichment import enrich
from agentos_pipeline.graduated import GraduatedThresholds, graduated_response
from agentos_pipeline.identity import IdentityStage, IdentityVerdict
from agentos_pipeline.policy_input import build_policy_input
from agentos_pipeline.posture import FailPosture, PostureMap
from agentos_pipeline.risk import assess_risk


class _PolicyEngine(Protocol):
    """The injected policy seam (ConstitutionPolicyEngine satisfies it)."""

    constitution_version: str
    policy_version: str
    principles_meta: dict[str, dict]

    def evaluate(self, input: dict) -> ConstitutionResult: ...


class _AuditWriter(Protocol):
    async def append(self, action: AgentAction, decision: Decision) -> UUID: ...


def _is_redaction_error(exc: BaseException) -> bool:
    """Structurally detect the audit writer's RedactionError (D-15) without
    importing the control plane (this package's one internal dependency is the
    contract — the same structural-typing discipline as the injected seams)."""
    return any(c.__name__ == "RedactionError" for c in type(exc).__mro__)


class Pipeline:
    """The 5-stage PDP (async evaluate; CPU stages inline). Satisfies PipelineProtocol."""

    def __init__(
        self,
        *,
        identity: IdentityStage,
        policy: _PolicyEngine,
        scorers: list[RiskScorer],
        audit: _AuditWriter,
        thresholds: GraduatedThresholds = GraduatedThresholds(),
        posture: PostureMap = PostureMap(),
        expensive_scorers: Sequence[RiskScorer] = (),
    ) -> None:
        self._identity = identity
        self._policy = policy
        self._scorers = scorers
        self._audit = audit
        self._thresholds = thresholds  # POL-06: injectable graduated risk bands
        self._posture = posture        # PIPE-05: per-action-class failure posture
        # SEC-03: inline=False detectors, run by stage 4 ONLY on inline flags —
        # never unconditionally (Pitfall 1).
        self._expensive_scorers = expensive_scorers

    async def evaluate(self, action: AgentAction) -> Decision:
        # Mutable holder: _evaluate records the computed floor as soon as it is
        # known, so a later exception cannot relax it through the fail-safe.
        floor_box: list[Outcome | None] = [None]
        try:
            return await self._evaluate(action, floor_box)
        except Exception as exc:  # total control-plane failure (PIPE-05)
            return await self._fail_safe(action, exc, computed_floor=floor_box[0])

    async def _evaluate(self, action: AgentAction, floor_box: list[Outcome | None]) -> Decision:
        reasons: list[Reason] = []

        # Stage 1 — Identity & Trust (IDN-02, TRST-01); short-circuit on forged/unknown.
        ident: IdentityVerdict = self._identity.verify(action)
        if not ident.ok:
            floor_box[0] = Outcome.deny  # forged identity: the deny may NEVER relax
            reasons.append(
                Reason(
                    stage="identity",
                    code="forged_or_unknown_identity",
                    detail=ident.detail,
                )
            )
            decision = Decision(
                action_id=action.id,
                outcome=Outcome.deny,
                reasons=reasons,
                constitution_version=self._policy.constitution_version,
                policy_version=self._policy.policy_version,
            )
            # Audited even on deny — evidence exists before enforcement (PIPE-03/AUD-01).
            # A RedactionError retries payload-free HERE (the deny stands); any other
            # append failure falls to the outer fail-safe, which inherits the deny floor.
            await self._append_with_redaction_fallback(action, decision)
            return decision  # TERMINAL — no later stages
        trust = ident.trust_score
        # Identity verified — record the stage that ran so every stage contributes a
        # machine-readable reason on the success path too (PIPE-02).
        reasons.append(Reason(stage="identity", code="identity_verified", detail=ident.detail))

        # Stage 2 — Enrichment (SEC-12/D6): deterministic, pure CPU, pre-policy.
        enrichment = enrich(action)

        # Stage 3 — Policy (POL-03): the compiled-constitution floor.
        res = self._policy.evaluate(build_policy_input(action, enrichment))
        floor = select_floor(res.matched)
        if floor is None:
            # Ambiguity ≡ no_match (D4): the floor is the per-class posture default.
            floor = self._posture.no_match_floor(action.type)
        # Captured the moment it is known: an exception in the reason loop below
        # (or any later stage) inherits the computed floor — it can never relax.
        floor_box[0] = floor
        if res.matched:
            for m in res.matched:
                meta = self._policy.principles_meta.get(m.principle_ref)
                reasons.append(
                    Reason(
                        stage="policy",
                        code="constitution_principle_fired",
                        policy_id=f"constitution.{m.principle_ref}",
                        principle_ref=m.principle_ref,
                        # malformed/missing meta must explain less, never crash the verdict.
                        rationale=meta.get("title", "") if isinstance(meta, dict) else "",
                        evidence={"effect": m.effect},
                    )
                )
        else:
            reasons.append(Reason(stage="policy", code="no_principle_matched"))

        # Stage 4 — Risk (SEC-01): inline, pure-CPU (plain call — not awaited).
        # The enrichment-carried guardrail findings (SEC-02) merge here — not
        # re-run; the expensive tier is gated on inline flags (SEC-03).
        risk_score, findings = assess_risk(
            action,
            self._scorers,
            extra_findings=enrichment.guardrail_findings,
            expensive_scorers=self._expensive_scorers,
        )
        for finding in findings:
            reasons.append(
                Reason(stage="risk", code=finding.category, detail=finding.detail)
            )

        # Stage 5 — Graduated (POL-06): risk/trust may only RESTRICT the policy floor.
        outcome = graduated_response(floor, risk_score, trust, self._thresholds)
        floor_box[0] = outcome  # the fail-safe inherits the FINAL verdict, not just
        # the policy floor — a post-verdict audit failure can never relax a
        # risk-driven deny on a fail-open class.
        reasons.append(Reason(stage="graduated", code=outcome.value))

        decision = Decision(
            action_id=action.id,
            outcome=outcome,
            risk_score=risk_score,
            trust_score=trust,
            reasons=reasons,
            inferred_intent=enrichment.intent_class,        # SEC-12 explainability
            # PIPE-08: set BEFORE the audit append — remediation is hash-covered.
            remediation=self._derive_remediation(outcome, res.matched),
            constitution_version=self._policy.constitution_version,  # POL-08
            policy_version=self._policy.policy_version,               # POL-08
        )
        # SYNC audit write on the hot path (AUD-01); sets evidence_ref before returning.
        await self._append_with_redaction_fallback(action, decision)
        return decision

    def _derive_remediation(self, outcome: Outcome, matched) -> list[str]:
        """PIPE-08: concrete next steps on restrictive outcomes (rank >= sandbox).

        Authored-first: the fired principles' `remediation` hints (dedup, order
        preserved, cap 10) via the same non-throwing meta access as the reason
        loop — malformed meta explains less, never crashes the verdict. When no
        hint is authored: require_approval -> the await-operator line; otherwise
        a per-fired-principle review line. Non-restrictive outcomes (and the
        engine-failure paths, which never reach here) keep remediation == []."""
        if OUTCOME_RESTRICTIVENESS[outcome] < OUTCOME_RESTRICTIVENESS[Outcome.sandbox]:
            return []
        hints: list[str] = []
        seen: set[str] = set()
        for m in matched:
            meta = self._policy.principles_meta.get(m.principle_ref)
            authored = meta.get("remediation") if isinstance(meta, dict) else None
            for hint in authored if isinstance(authored, list) else []:
                if isinstance(hint, str) and hint not in seen:
                    seen.add(hint)
                    hints.append(hint)
        if not hints:
            if outcome is Outcome.require_approval:
                hints = ["Await operator resolution of the parked approval request"]
            else:
                for m in matched:
                    meta = self._policy.principles_meta.get(m.principle_ref)
                    title = meta.get("title", "") if isinstance(meta, dict) else ""
                    hints.append(f"Review principle {m.principle_ref} — {title}")
        return hints[:10]  # Decision.remediation is audit-bound (<= 10 items)

    async def _append_with_redaction_fallback(
        self, action: AgentAction, decision: Decision
    ) -> None:
        """Append the audit record, setting decision.evidence_ref. A RedactionError
        (unclassifiable payload, D-15) is handled HERE — never escaping to the
        fail-safe: fall to the per-class posture FIRST (closed -> deny; an existing
        deny always stands), then append a payload-free copy so the decision still
        carries evidence. Exception CLASS only — never payload. Any OTHER audit
        failure propagates to the outer fail-safe (PIPE-05)."""
        try:
            decision.evidence_ref = await self._audit.append(action, decision)
        except Exception as exc:
            if not _is_redaction_error(exc):
                raise  # any other audit failure -> the outer fail-safe (PIPE-05)
            if self._posture.fail_posture(action.type) is FailPosture.closed:
                decision.outcome = Outcome.deny
            decision.reasons.append(
                Reason(stage="pipeline", code="redaction_failed", detail=type(exc).__name__)
            )
            stripped = action.model_copy(update={"payload": {}})
            decision.evidence_ref = await self._audit.append(stripped, decision)

    async def _fail_safe(
        self, action: AgentAction, exc: Exception, computed_floor: Outcome | None = None
    ) -> Decision:
        """Total-failure semantics (PIPE-05): posture-applied outcome + payload-free
        fail-safe audit record. A fail-open that cannot write its record is demoted
        to deny — no record, no allow. When a floor was already computed before the
        failure, the outcome is the MORE RESTRICTIVE of posture and floor — a
        fail-open allow can never override a computed deny/restrictive floor."""
        posture = self._posture.fail_posture(action.type)
        outcome = Outcome.allow if posture is FailPosture.open else Outcome.deny
        if computed_floor is not None:
            outcome = max(outcome, computed_floor, key=OUTCOME_RESTRICTIVENESS.__getitem__)
        reasons = [
            Reason(
                stage="pipeline",
                code=f"control_plane_failure_fail_{posture.value}",
                detail=type(exc).__name__,  # exception CLASS only, never payload
            )
        ]
        decision = Decision(action_id=action.id, outcome=outcome, reasons=reasons)
        stripped = action.model_copy(update={"payload": {}})
        try:
            decision.evidence_ref = await self._audit.append(stripped, decision)
        except Exception:
            if outcome is Outcome.allow:  # no record -> no allow
                return Decision(
                    action_id=action.id,
                    outcome=Outcome.deny,
                    reasons=reasons
                    + [Reason(stage="pipeline", code="fail_open_unaudited_demoted_to_deny")],
                )
            return decision  # deny stands even without evidence
        return decision
