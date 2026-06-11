"""The 4-stage decision pipeline runner — PIPE-01 / PIPE-02 / PIPE-03.

Behavior (plan 01-05 Task 2):
  - Ordering (PIPE-01): a valid action runs identity -> policy -> risk -> graduated and
    returns exactly one Decision carrying the graduated outcome.
  - Reasons (PIPE-02): the Decision.reasons has at least one Reason per stage that ran
    (identity, policy, risk, graduated), each with a machine-readable `code`.
  - Short-circuit (PIPE-03/IDN-02): a forged/unknown identity -> outcome deny, reasons
    contains ONLY the identity reason (code "forged_or_unknown_identity"), and
    policy.evaluate + assess_risk did NOT run (call counts 0, proven via spies).
  - Audit-before-return (PIPE-01/AUD-01): evaluate awaits audit.append and sets
    evidence_ref on BOTH the deny short-circuit path and the normal path.
  - Floor end-to-end: a policy-deny action returns deny regardless of risk/trust.
  - trust feeds graduated: the identity trust_score is passed to graduated_response and
    stamped on the Decision.

Fakes/spies stand in for the policy engine, scorers, and audit writer — no real DB is
needed for the ordering/short-circuit unit tests (the real AuditWriter is exercised in
tests/integration/test_audit_chain.py). The async runner is driven with asyncio.run,
matching the established convention in the integration suite.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding
from agentos_pipeline.graduated import GraduatedThresholds
from agentos_pipeline.policy import PolicyResult
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
    """Records call count; returns a preset PolicyResult."""

    def __init__(self, outcome: Outcome) -> None:
        self.calls = 0
        self.last_input: dict | None = None
        self._outcome = outcome

    def evaluate(self, input: dict) -> PolicyResult:
        self.calls += 1
        self.last_input = input
        if self._outcome is Outcome.allow:
            return PolicyResult(outcome=Outcome.allow, code="egress_allowlisted", policy_id="egress.allow")
        return PolicyResult(
            outcome=Outcome.deny,
            code="egress_allowlist_violation",
            policy_id="egress.allow",
            detail="host not in allowlist",
        )


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


def test_policy_input_carries_parsed_host() -> None:
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, policy=Outcome.allow, risk=0.0)
    asyncio.run(pipeline.evaluate(_action(url="https://api.example.com/path?q=1")))
    assert pol.last_input is not None
    assert pol.last_input["host"] == "api.example.com"
    assert pol.last_input["type"] == "tool_call"


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
