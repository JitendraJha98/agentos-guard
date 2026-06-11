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


def _wire_real_engine(constitution_wasm, *, audit=None):
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
        scorers=[],
        audit=audit,
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
