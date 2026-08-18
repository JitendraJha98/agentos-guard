"""Pipeline stage-1 shadow-agent reporting (DISC-04, Slice 10d).

An actor acting WITHOUT being registered is already denied at stage 1 (IDN-02). This seam makes it
VISIBLE — otherwise the probe is one deny among thousands. It is strictly OBSERVATION:

  * it runs only where identity ALREADY failed, so nothing is added to the allowed hot path;
  * it never becomes a second deny path and never appends a reason — the decision an operator sees
    is byte-for-byte the identity deny it was before;
  * a reporter that RAISES must still yield that clean identity deny. Degrading a real enforcement
    outcome into a fail-safe `control_plane_failure` because a *bookkeeping* call threw would let
    observation weaken governance, which is exactly backwards.

`shadow=None` (the default) leaves behaviour unchanged (backward compat).
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_pipeline.runner import Pipeline

# --- fakes (mirroring tests/unit/test_kill_switch_pipeline.py) ----------------


class FakeIdentityStage:
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
    constitution_version = "sha256:stub-constitution"
    policy_version = "sha256:stub-policy"
    principles_meta = {"1.1": {"title": "Egress allowlist", "effect": "deny"}}

    def __init__(self, outcome: Outcome = Outcome.allow) -> None:
        self.calls = 0
        self._outcome = outcome

    def evaluate(self, input: dict) -> ConstitutionResult:
        self.calls += 1
        if self._outcome is Outcome.allow:
            return ConstitutionResult(matched=(), no_match=True)
        return ConstitutionResult(
            matched=(MatchedPrinciple(principle_ref="1.1", effect="deny"),), no_match=False
        )


class SpyScorer:
    name = "spy.v1"
    inline = True

    def __init__(self, risk_score: float = 0.0) -> None:
        self.calls = 0
        self._risk = risk_score

    def score(self, action: AgentAction) -> RiskFinding:
        self.calls += 1
        return RiskFinding(
            scorer=self.name,
            category="prompt_injection",
            risk_score=self._risk,
            matched=[],
            detail="spy",
        )


class FakeAuditWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[AgentAction, object]] = []
        self._id = uuid4()

    async def append(self, action: AgentAction, decision) -> UUID:
        self.calls.append((action, decision))
        return self._id


class StubShadowReporter:
    """A structural ShadowReporter. `raises=True` models the store being down / the chain
    refusing the append — the failure mode that must NOT reach the decision."""

    def __init__(self, raises: bool = False) -> None:
        self.calls: list[tuple[str, str]] = []
        self._raises = raises

    async def record(self, claimed_agent_id: str, action_type: str) -> bool:
        self.calls.append((claimed_agent_id, action_type))
        if self._raises:
            raise RuntimeError("shadow store unavailable")
        return True


def _action(agent_id: str = "ghost-agent", token: str | None = "forged") -> AgentAction:
    return AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/data"},
        identity_token=token,
    )


def _build(*, identity_ok: bool, shadow: StubShadowReporter | None):
    ident = FakeIdentityStage(
        ok=identity_ok, trust_score=0.5, detail="" if identity_ok else "unknown agent"
    )
    pol = SpyPolicyEngine()
    scorer = SpyScorer()
    audit = FakeAuditWriter()
    pipeline = Pipeline(
        identity=ident, policy=pol, scorers=[scorer], audit=audit, shadow=shadow
    )
    return pipeline, ident, pol, scorer, audit


# --- tests -------------------------------------------------------------------


def test_unregistered_actor_is_denied_and_reported() -> None:
    """The deny is unchanged; the sighting is the NEW part."""
    reporter = StubShadowReporter()
    pipeline, ident, pol, scorer, audit = _build(identity_ok=False, shadow=reporter)

    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    assert reporter.calls == [("ghost-agent", "tool_call")]
    assert pol.calls == 0 and scorer.calls == 0  # still terminal — no later stage ran


def test_reporting_adds_no_reason_to_the_decision() -> None:
    """Observation only: the decision an operator reads must be identical with and without the
    reporter — same outcome, same reasons, no extra `shadow` stage."""
    with_reporter, *_ = _build(identity_ok=False, shadow=StubShadowReporter())
    without, *_ = _build(identity_ok=False, shadow=None)

    a = asyncio.run(with_reporter.evaluate(_action()))
    b = asyncio.run(without.evaluate(_action()))

    assert a.outcome is b.outcome
    assert [(r.stage, r.code, r.detail) for r in a.reasons] == [
        (r.stage, r.code, r.detail) for r in b.reasons
    ]
    assert "shadow" not in {r.stage for r in a.reasons}


def test_verified_agent_is_never_reported() -> None:
    """A registered agent is not a shadow agent — the reporter must not see it, on the allowed
    path or anywhere else."""
    reporter = StubShadowReporter()
    pipeline, ident, pol, scorer, audit = _build(identity_ok=True, shadow=reporter)

    decision = asyncio.run(pipeline.evaluate(_action(agent_id="agent-1", token="valid")))

    assert decision.outcome is Outcome.allow
    assert reporter.calls == []


def test_shadow_none_is_backward_compatible() -> None:
    """No shadow wired -> nothing runs, the identity deny is exactly as before."""
    pipeline, ident, pol, scorer, audit = _build(identity_ok=False, shadow=None)

    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    assert len(audit.calls) == 1


def test_raising_reporter_still_yields_the_clean_identity_deny() -> None:
    """THE constraint: a broken observer must never degrade enforcement. The outcome stays a deny
    with the identity reason — NOT the fail-safe `control_plane_failure_fail_*` reason the outer
    handler would produce if the exception escaped."""
    reporter = StubShadowReporter(raises=True)
    pipeline, ident, pol, scorer, audit = _build(identity_ok=False, shadow=reporter)

    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.deny
    assert [r.code for r in decision.reasons] == ["forged_or_unknown_identity"]
    assert not any(r.code.startswith("control_plane_failure") for r in decision.reasons)
    assert reporter.calls == [("ghost-agent", "tool_call")]
    assert len(audit.calls) == 1  # the deny record, and no second fail-safe record


def test_reporting_happens_after_the_deny_is_audited() -> None:
    """Evidence ordering: the DECISION record is the audit of a per-action gate deny (Phase-9
    convention). The sighting is an observation layered on top and can never be what delays or
    displaces it."""
    order: list[str] = []

    class OrderedAudit(FakeAuditWriter):
        async def append(self, action, decision):
            order.append("decision")
            return await super().append(action, decision)

    class OrderedReporter(StubShadowReporter):
        async def record(self, claimed_agent_id, action_type):
            order.append("sighting")
            return await super().record(claimed_agent_id, action_type)

    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=False, detail="unknown agent"),
        policy=SpyPolicyEngine(),
        scorers=[SpyScorer()],
        audit=OrderedAudit(),
        shadow=OrderedReporter(),
    )

    asyncio.run(pipeline.evaluate(_action()))

    assert order == ["decision", "sighting"]


def test_claimed_id_is_passed_through_untouched_for_the_store_to_bound() -> None:
    """The pipeline hands over the RAW claimed id. Bounding/sanitizing/digesting is the store's
    job (one place, tested there) — the pipeline must not half-do it and lose the full string the
    digest needs."""
    reporter = StubShadowReporter()
    pipeline, *_ = _build(identity_ok=False, shadow=reporter)
    hostile = "g" * 5000

    asyncio.run(pipeline.evaluate(_action(agent_id=hostile)))

    assert reporter.calls == [(hostile, "tool_call")]
