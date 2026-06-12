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

from datetime import datetime, timezone
from typing import Mapping, Protocol, Sequence
from uuid import UUID

from agentos_contract import AgentAction, Decision, Outcome, Reason, RiskScorer
from agentos_contract.policy_io import (
    AUTHORABLE_EFFECTS,
    OUTCOME_RESTRICTIVENESS,
    ConstitutionResult,
    MatchedPrinciple,
    select_floor,
)

from agentos_pipeline.enrichment import enrich
from agentos_pipeline.graduated import GraduatedThresholds, graduated_response
from agentos_pipeline.identity import IdentityStage, IdentityVerdict
from agentos_pipeline.interpreter import InterpretationRequest, SemanticInterpreter
from agentos_pipeline.policy_input import build_policy_input
from agentos_pipeline.posture import FailPosture, PostureMap
from agentos_pipeline.risk import assess_risk
from agentos_pipeline.risk._text import payload_text


class _PolicyEngine(Protocol):
    """The injected policy seam (ConstitutionPolicyEngine satisfies it)."""

    constitution_version: str
    policy_version: str
    principles_meta: dict[str, dict]

    def evaluate(self, input: dict) -> ConstitutionResult: ...


class _AuditWriter(Protocol):
    async def append(self, action: AgentAction, decision: Decision) -> UUID: ...


class ExceptionLookup(Protocol):
    """The injected POL-13 seam (ApprovalStore.active_for satisfies it).

    Sync and pure-read: returns the ACTIVE (unexpired, unrevoked) temporary
    exceptions for (agent_id, ref in refs) as {ref: tz-aware expiry}.
    """

    def active_for(
        self, agent_id: str, refs: tuple[str, ...]
    ) -> Mapping[str, datetime]: ...


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
        interpreter: SemanticInterpreter | None = None,
        exceptions: ExceptionLookup | None = None,
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
        # POL-04/POL-05: the advisory semantic interpreter — runs ONLY on no_match,
        # may only RESTRICT the class-posture floor. None default: no new reasons
        # (and no network) anywhere unless explicitly wired at composition time.
        self._interpreter = interpreter
        # POL-13: the temporary-exception lookup. None default: the transform
        # never runs and deny floors stand exactly as before.
        self._exceptions = exceptions

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
            # Captured BEFORE the interpreter runs: a malformed verdict raising
            # below must inherit this floor through the fail-safe, never relax it.
            floor_box[0] = floor
            # POL-04: the advisory interpreter runs ONLY here (no_match) — never
            # when a principle matched, so it can never touch a real policy floor.
            if self._interpreter is not None:
                request = InterpretationRequest(
                    action_type=action.type.value,
                    target=action.target,
                    intent_class=enrichment.intent_class or "",
                    guardrails=tuple(sorted(enrichment.guardrails.items())),
                    payload_excerpt=payload_text(action)[0][:2048],
                    principles=tuple(
                        (
                            ref,
                            meta.get("title", "") if isinstance(meta, dict) else "",
                            meta.get("statement", "") if isinstance(meta, dict) else "",
                        )
                        for ref, meta in sorted(self._policy.principles_meta.items())
                    ),
                    constitution_version=self._policy.constitution_version,
                    policy_version=self._policy.policy_version,
                )
                # The try covers the WHOLE verdict-handling block: a malformed
                # verdict (unhashable outcome, non-str rationale/principle_ref)
                # degrades to interpreter_error exactly like a backend failure —
                # advisory failure, floor stands, NEVER _fail_safe.
                try:
                    verdict = await self._interpreter.interpret(request)
                    if verdict.outcome not in AUTHORABLE_EFFECTS:
                        reasons.append(
                            Reason(
                                stage="interpreter",
                                code="interpreter_invalid_verdict",
                                detail=str(verdict.outcome)[:64],
                            )
                        )
                    else:
                        rec = Outcome(verdict.outcome)
                        # POL-05 clamp: restrict-only — the verdict may tighten the
                        # no-match floor, never relax it.
                        floor = max(floor, rec, key=OUTCOME_RESTRICTIVENESS.__getitem__)
                        reasons.append(
                            Reason(
                                stage="interpreter",
                                code="interpreter_advisory",
                                principle_ref=(verdict.principle_ref or "")[:64] or None,
                                rationale=verdict.rationale[:512],
                                evidence={"recommended": verdict.outcome},
                            )
                        )
                except Exception as exc:  # advisory failure: floor stands, NEVER _fail_safe
                    reasons.append(
                        Reason(
                            stage="interpreter",
                            code="interpreter_error",
                            detail=type(exc).__name__,
                        )
                    )
        # Captured the moment it is known: an exception in the reason loop below
        # (or any later stage) inherits the computed floor — it can never relax.
        floor_box[0] = floor
        applied_expiry: datetime | None = None
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
            # POL-13 pre-graduated transform: a deny floor FROM MATCHED PRINCIPLES
            # converts to allow ONLY when every deny-effect ref carries an active
            # unexpired human-ratified exception. floor_box deliberately keeps the
            # deny — a mid-stage crash must fail-safe against the UNtransformed
            # floor; the box catches up to the final verdict after stage 5.
            if floor is Outcome.deny and self._exceptions is not None:
                floor, applied_expiry = self._apply_exception_transform(
                    action, res.matched, reasons
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
        expires_at: datetime | None = None
        if applied_expiry is not None and outcome is Outcome.allow:
            # POL-13 relabel: an exception-transformed floor that SURVIVED the
            # risk/trust stage is labeled as what it is — a ratified, time-boxed
            # allow — carrying the earliest consumed expiry. Any re-restricted
            # outcome (risk re-restricts, defense in depth) keeps its label.
            outcome = Outcome.temporary_exception
            expires_at = applied_expiry
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
            expires_at=expires_at,                                    # POL-13
        )
        # SYNC audit write on the hot path (AUD-01); sets evidence_ref before returning.
        await self._append_with_redaction_fallback(action, decision)
        return decision

    def _apply_exception_transform(
        self,
        action: AgentAction,
        matched: Sequence[MatchedPrinciple],
        reasons: list[Reason],
    ) -> tuple[Outcome, datetime | None]:
        """POL-13: convert a matched-principle deny floor to allow IFF every
        deny-effect ref has an active unexpired exception for this agent.

        Returns (floor, earliest consumed expiry | None). Expiry is re-checked
        HERE (not only in the store's read-time query) — defense in depth: a
        lookup that returns a stale grant still cannot revive it. Any partial
        coverage (one uncovered deny ref) keeps the deny floor untouched.
        """
        deny_refs: list[str] = []
        for m in matched:
            if m.effect == Outcome.deny.value and m.principle_ref not in deny_refs:
                deny_refs.append(m.principle_ref)
        if not deny_refs:
            # A deny floor with no deny-effect refs cannot be principle-attributed
            # (never the case for select_floor output) — never transform it.
            return Outcome.deny, None
        active = self._exceptions.active_for(action.agent_id, tuple(deny_refs))
        now = datetime.now(timezone.utc)
        expiries: list[datetime] = []
        for ref in deny_refs:
            expiry = active.get(ref)
            if expiry is None or expiry <= now:
                return Outcome.deny, None  # ALL deny refs must be covered
            expiries.append(expiry)
        earliest = min(expiries)
        reasons.append(
            Reason(
                stage="policy",
                code="temporary_exception_applied",
                evidence={"refs": deny_refs, "expires_at": earliest.isoformat()},
            )
        )
        return Outcome.allow, earliest

    def _derive_remediation(
        self, outcome: Outcome, matched: Sequence[MatchedPrinciple]
    ) -> list[str]:
        """PIPE-08: concrete next steps on restrictive outcomes (rank >= sandbox).

        Authored-first: the fired principles' `remediation` hints (dedup, order
        preserved, cap 10) via the same non-throwing meta access as the reason
        loop — malformed meta explains less, never crashes the verdict. When no
        hint is authored: require_approval -> the await-operator line; otherwise
        a review line per fired principle whose OWN effect is restrictive (rank
        >= sandbox) — advisory principles that fired alongside didn't drive the
        outcome and get no review line. Non-restrictive outcomes (and the
        engine-failure paths, which never reach here) keep remediation == []."""
        sandbox_rank = OUTCOME_RESTRICTIVENESS[Outcome.sandbox]
        if OUTCOME_RESTRICTIVENESS[outcome] < sandbox_rank:
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
                    # Outcome(m.effect) cannot raise here: select_floor already
                    # coerced every matched effect on the way to this verdict.
                    if OUTCOME_RESTRICTIVENESS[Outcome(m.effect)] < sandbox_rank:
                        continue
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
