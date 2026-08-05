"""Pipeline stage-1f circuit-breaker gate + graduated-path signal recording (RUN-06, Slice 9d, T3/T4).

Stage 1f denies while a breaker is OPEN. It sits AFTER identity (so the breaker keys on a VERIFIED
agent_id) and immediately after 9b's stage-1e privilege gate; the deny is terminal and audited as a
DECISION record carrying `circuit_breaker`/`circuit_open`. The lookup is in-memory (no per-action DB
read). `breaker=None` (the default) leaves behavior unchanged.

The two correctness traps this file exists to nail down:

1. **No feedback loop.** Signals are recorded from the GRADUATED path ONLY. Every short-circuit deny
   (kill switch, identity, delegation, MCP quarantine, privilege, and the breaker's OWN deny) records
   NOTHING — otherwise an OPEN breaker would feed itself and could never close.
2. **No cross-agent DoS.** Nothing is ever recorded against an UNVERIFIED agent_id, so a forged id
   cannot trip somebody else's breaker.

The PEP half (Task 4) reports governed EXECUTION failures, which the PDP cannot see — but skips the
`GovernanceDenied` family, because the PDP already counted those.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest

from agentos_contract import ActionType, AgentAction, Decision, Outcome, RiskFinding, SandboxResult
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_pipeline.runner import Pipeline
from agentos_sdk.enforce import (
    GovernanceDenied,
    GovernanceQuarantined,
    governed_call,
)


# --- fakes (mirroring tests/unit/test_privilege_pipeline.py) -----------------


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

    def __init__(self, outcome: Outcome) -> None:
        self.calls = 0
        self._outcome = outcome

    def evaluate(self, input: dict) -> ConstitutionResult:
        self.calls += 1
        if self._outcome is Outcome.allow:
            return ConstitutionResult(matched=(), no_match=True)
        return ConstitutionResult(
            matched=(MatchedPrinciple(principle_ref="1.1", effect=self._outcome.value),),
            no_match=False,
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
            scorer=self.name, category="prompt_injection", risk_score=self._risk,
            matched=[], detail="spy",
        )


class FakeAuditWriter:
    def __init__(self) -> None:
        self.calls: list[tuple[AgentAction, object]] = []
        self._id = uuid4()

    async def append(self, action: AgentAction, decision) -> UUID:
        self.calls.append((action, decision))
        return self._id


class _BV:
    """A structural BreakerVerdictProtocol (key + scope + state)."""

    def __init__(self, key: str, scope: str = "agent", state: str = "open") -> None:
        self.key = key
        self.scope = scope
        self.state = state


class StubBreaker:
    """A structural CircuitBreakerLookup: sync `status` (never handed a session — proving the hot-path
    check is in-memory), plus async recorders that log every signal they receive."""

    def __init__(self, verdict: _BV | None) -> None:
        self._verdict = verdict
        self.status_calls: list[tuple[str, str]] = []
        self.failures: list[tuple[str, str]] = []
        self.successes: list[tuple[str, str]] = []

    def status(self, agent_id: str, target: str):
        self.status_calls.append((agent_id, target))
        return self._verdict

    async def record_failure(self, agent_id: str, target: str) -> None:
        self.failures.append((agent_id, target))

    async def record_success(self, agent_id: str, target: str) -> None:
        self.successes.append((agent_id, target))

    @property
    def signals(self) -> list[tuple[str, str]]:
        return self.failures + self.successes


def _action(token: str | None = "tok", agent_id: str = "agent-1") -> AgentAction:
    return AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/data"},
        identity_token=token,
    )


def _build(*, verdict: _BV | None, identity_ok: bool = True, policy: Outcome = Outcome.allow):
    ident = FakeIdentityStage(
        ok=identity_ok, trust_score=0.5, detail="forged" if not identity_ok else ""
    )
    pol = SpyPolicyEngine(policy)
    scorer = SpyScorer()
    audit = FakeAuditWriter()
    breaker = StubBreaker(verdict)
    pipeline = Pipeline(
        identity=ident, policy=pol, scorers=[scorer], audit=audit, breaker=breaker
    )
    return pipeline, ident, pol, scorer, audit, breaker


# --- Stage 1f: the gate ------------------------------------------------------


def test_open_breaker_denies_and_later_stages_are_skipped() -> None:
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=_BV("agent-1"))
    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.deny
    reason = decision.reasons[-1]
    assert reason.stage == "circuit_breaker" and reason.code == "circuit_open"
    assert "agent-1" in reason.detail and "open" in reason.detail
    # Stage 1f is terminal: policy + risk never ran.
    assert pol.calls == 0 and scorer.calls == 0
    assert [r.stage for r in decision.reasons] == ["identity", "circuit_breaker"]


def test_open_breaker_deny_is_audited_and_versioned() -> None:
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=_BV("agent-1"))
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert len(audit.calls) == 1  # evidence the action was blocked
    assert decision.evidence_ref is not None
    assert decision.constitution_version == "sha256:stub-constitution"
    assert decision.policy_version == "sha256:stub-policy"
    assert decision.trust_score == 0.5


def test_tool_scoped_verdict_names_the_pair() -> None:
    pipeline, *_ = _build(verdict=_BV("agent-1|http_get", scope="tool"))
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    assert "tool breaker agent-1|http_get" in decision.reasons[-1].detail


def test_breaker_none_is_backward_compatible() -> None:
    """No `breaker` wired -> stage 1f never runs, behavior unchanged."""
    ident = FakeIdentityStage(ok=True)
    pol = SpyPolicyEngine(Outcome.allow)
    scorer = SpyScorer()
    pipeline = Pipeline(
        identity=ident, policy=pol, scorers=[scorer], audit=FakeAuditWriter()
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow
    assert not any(r.stage == "circuit_breaker" for r in decision.reasons)


def test_the_status_check_is_in_memory_and_keyed_on_agent_and_target() -> None:
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=None)
    asyncio.run(pipeline.evaluate(_action()))
    assert breaker.status_calls == [("agent-1", "http_get")]  # exactly one lookup
    assert not hasattr(breaker, "session_factory")


def test_an_open_breaker_survives_a_policy_that_would_allow() -> None:
    """The gate only ever RESTRICTS: an allowing policy is never even reached."""
    pipeline, ident, pol, scorer, audit, breaker = _build(
        verdict=_BV("agent-1"), policy=Outcome.allow
    )
    assert asyncio.run(pipeline.evaluate(_action())).outcome is Outcome.deny
    assert pol.calls == 0


# --- graduated-path recording ------------------------------------------------


def test_an_allowed_action_records_exactly_one_success() -> None:
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=None, policy=Outcome.allow)
    assert asyncio.run(pipeline.evaluate(_action())).outcome is Outcome.allow
    assert breaker.successes == [("agent-1", "http_get")]
    assert breaker.failures == []


def test_a_policy_deny_records_exactly_one_failure() -> None:
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=None, policy=Outcome.deny)
    assert asyncio.run(pipeline.evaluate(_action())).outcome is Outcome.deny
    assert breaker.failures == [("agent-1", "http_get")]
    assert breaker.successes == []


def test_a_non_allow_graduated_outcome_counts_as_a_failure() -> None:
    """Anything short of `allow` on the graduated path is a violation signal — a sandboxed or
    approval-gated action is exactly the escalating behavior a breaker should contain."""
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=None, policy=Outcome.sandbox)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.sandbox
    assert breaker.failures == [("agent-1", "http_get")]


# --- TRAP 1: the feedback loop -----------------------------------------------


def test_the_breakers_OWN_deny_records_NOTHING() -> None:
    """THE feedback-loop guard: if an `circuit_open` deny counted as a violation, an OPEN breaker
    would feed its own window forever, re-trip on every trial, and could NEVER close."""
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=_BV("agent-1"))
    for _ in range(5):
        assert asyncio.run(pipeline.evaluate(_action())).outcome is Outcome.deny
    assert breaker.signals == []


def test_a_kill_switch_short_circuit_records_NOTHING() -> None:
    """Stage 0 (operator intent) precedes the breaker and is not an agent violation signal."""

    class StubKill:
        scope = "fleet"
        reason = "incident-42"

        def status(self, agent_id: str):
            return self

    kill = StubKill()
    breaker = StubBreaker(None)
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=SpyPolicyEngine(Outcome.allow),
        scorers=[SpyScorer()],
        audit=FakeAuditWriter(),
        kill_switch=kill,
        breaker=breaker,
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.reasons[-1].code == "fleet_killed"
    assert breaker.signals == []
    # Stage 0 precedes stage 1f: the breaker was never even consulted.
    assert breaker.status_calls == []


def test_a_privilege_short_circuit_records_NOTHING() -> None:
    """Stage 1e denies before 1f; a ring refusal is not fed to the breaker either."""

    class StubPrivilege:
        class _PV:
            target, required, held = "http_get", 3, 0

        def ring_for(self, agent_id: str) -> int:
            return 0

        def check(self, agent_id: str, target: str, *, held_ring: int | None = None):
            return self._PV()

    breaker = StubBreaker(None)
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=SpyPolicyEngine(Outcome.allow),
        scorers=[SpyScorer()],
        audit=FakeAuditWriter(),
        privilege=StubPrivilege(),
        breaker=breaker,
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.reasons[-1].code == "insufficient_ring"
    assert breaker.signals == []


# --- TRAP 2: cross-agent DoS -------------------------------------------------


def test_a_FORGED_identity_records_NOTHING_against_the_claimed_agent() -> None:
    """THE cross-agent-DoS guard: `action.agent_id` is attacker-controlled until identity verifies.
    Recording pre-identity would let anyone trip a VICTIM's breaker by forging its id — a remote
    kill switch for arbitrary agents. The gate is not consulted either."""
    pipeline, ident, pol, scorer, audit, breaker = _build(verdict=None, identity_ok=False)
    decision = asyncio.run(pipeline.evaluate(_action(token="forged", agent_id="victim-agent")))
    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    assert breaker.signals == []
    assert breaker.status_calls == []


def test_a_fail_safe_records_NOTHING() -> None:
    """A control-plane failure (PIPE-05) is not an agent violation: the graduated path never
    completed, so no signal is attributable to the agent."""

    class ExplodingPolicy(SpyPolicyEngine):
        def evaluate(self, input: dict):
            raise RuntimeError("engine down")

    breaker = StubBreaker(None)
    pipeline = Pipeline(
        identity=FakeIdentityStage(ok=True),
        policy=ExplodingPolicy(Outcome.allow),
        scorers=[SpyScorer()],
        audit=FakeAuditWriter(),
        breaker=breaker,
    )
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.reasons[0].code.startswith("control_plane_failure")
    assert breaker.signals == []


# --- Task 4: the PEP reports EXECUTION failures ------------------------------


class StubReporter:
    """A structural CircuitReporter."""

    def __init__(self) -> None:
        self.failures: list[tuple[str, str]] = []

    async def record_failure(self, agent_id: str, target: str) -> None:
        self.failures.append((agent_id, target))


class AllowPipeline:
    """A minimal PipelineProtocol that always allows — the PEP path is what is under test."""

    def __init__(self, outcome: Outcome = Outcome.allow) -> None:
        self._outcome = outcome

    async def evaluate(self, action: AgentAction) -> Decision:
        return Decision(action_id=action.id, outcome=self._outcome)


def test_a_raising_handler_is_reported_as_an_execution_failure() -> None:
    reporter = StubReporter()
    action = _action()

    async def boom():
        raise RuntimeError("upstream 500")

    with pytest.raises(RuntimeError):
        asyncio.run(governed_call(AllowPipeline(), action, boom, reporter=reporter))
    assert reporter.failures == [("agent-1", "http_get")]


def test_a_successful_handler_reports_nothing_at_the_pep() -> None:
    """Success is the PDP's job (the graduated path already recorded it) — reporting here too would
    double-count and could close a breaker on one action."""
    reporter = StubReporter()

    async def ok():
        return "fine"

    assert asyncio.run(governed_call(AllowPipeline(), _action(), ok, reporter=reporter)) == "fine"
    assert reporter.failures == []


def test_a_governance_block_is_NOT_reported_as_an_execution_error() -> None:
    """No double-counting: a `deny` was ALREADY counted by the PDP's graduated-path recording, so
    the PEP must not count it a second time — that would trip every breaker twice as fast."""
    reporter = StubReporter()

    async def never_runs():
        raise AssertionError("must not run")

    with pytest.raises(GovernanceDenied):
        asyncio.run(
            governed_call(AllowPipeline(Outcome.deny), _action(), never_runs, reporter=reporter)
        )
    assert reporter.failures == []


def test_a_quarantine_is_NOT_reported_as_an_execution_error() -> None:
    """`GovernanceQuarantined` (and every other GovernanceDenied SUBCLASS) is a governance block,
    not an execution error — the except-clause must cover the whole family."""
    reporter = StubReporter()

    class StubSandbox:
        async def run(self, action: AgentAction, decision: Decision) -> SandboxResult:
            return SandboxResult(quarantined=True, run_id="run-1", detail="quarantined")

    async def never_runs():
        raise AssertionError("must not run")

    with pytest.raises(GovernanceQuarantined):
        asyncio.run(
            governed_call(
                AllowPipeline(Outcome.sandbox),
                _action(),
                never_runs,
                sandbox=StubSandbox(),
                reporter=reporter,
            )
        )
    assert reporter.failures == []


def test_reporter_none_is_backward_compatible() -> None:
    async def boom():
        raise RuntimeError("upstream 500")

    with pytest.raises(RuntimeError):
        asyncio.run(governed_call(AllowPipeline(), _action(), boom))
