"""Pipeline stage-1e privilege-ring gate (RUN-04, Slice 9b, Task 3).

A sensitive (registered) target requires a capability tier; an agent holding a lower ring is denied
BEFORE the action runs. Stage 1e sits AFTER identity — the ring is keyed on a VERIFIED agent_id, so
an unverified caller never consumes ring state — and BEFORE enrichment/policy, alongside the other
post-identity deny gates (1b delegation, 1c inter-agent auth, 1d MCP quarantine). The deny is
terminal and audited as a DECISION record carrying `privilege`/`insufficient_ring`. The lookup is an
in-memory call (no DB read on the hot path). `privilege=None` (the default) leaves behavior unchanged.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_pipeline.runner import Pipeline


# --- fakes (mirroring tests/unit/test_kill_switch_pipeline.py) ---------------


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


class _PV:
    """A structural PrivilegeVerdictProtocol (target + required + held)."""

    def __init__(self, target: str, required: int, held: int) -> None:
        self.target = target
        self.required = required
        self.held = held


class StubPrivilege:
    """A structural PrivilegeLookup: sync `check`, NEVER given a session (proving the hot-path
    check is in-memory — no DB read per action). Records the agent_id it was keyed on."""

    def __init__(self, verdict: _PV | None) -> None:
        self._verdict = verdict
        self.calls = 0
        self.seen: list[tuple[str, str]] = []

    def check(self, agent_id: str, target: str):
        self.calls += 1
        self.seen.append((agent_id, target))
        return self._verdict


def _action(token: str | None = "tok") -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="db_drop",
        payload={"url": "https://api.example.com/data"},
        identity_token=token,
    )


def _build(*, verdict: _PV | None, identity_ok: bool = True, policy: Outcome = Outcome.allow):
    ident = FakeIdentityStage(ok=identity_ok, trust_score=0.5,
                              detail="forged" if not identity_ok else "")
    pol = SpyPolicyEngine(policy)
    scorer = SpyScorer()
    audit = FakeAuditWriter()
    priv = StubPrivilege(verdict)
    pipeline = Pipeline(
        identity=ident, policy=pol, scorers=[scorer], audit=audit, privilege=priv
    )
    return pipeline, ident, pol, scorer, audit, priv


# --- tests -------------------------------------------------------------------


def test_under_privileged_agent_denied_and_later_stages_skipped() -> None:
    pipeline, ident, pol, scorer, audit, priv = _build(verdict=_PV("db_drop", 3, 0))
    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.deny
    reason = decision.reasons[-1]
    assert reason.stage == "privilege" and reason.code == "insufficient_ring"
    assert "db_drop" in reason.detail and "3" in reason.detail and "0" in reason.detail
    # Stage 1e is terminal: policy + risk never ran.
    assert pol.calls == 0 and scorer.calls == 0
    # Only identity (which must run first) and privilege contributed reasons.
    assert [r.stage for r in decision.reasons] == ["identity", "privilege"]


def test_under_privileged_deny_is_audited() -> None:
    pipeline, ident, pol, scorer, audit, priv = _build(verdict=_PV("db_drop", 3, 0))
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert len(audit.calls) == 1  # evidence the action was blocked
    assert decision.evidence_ref is not None
    # Versions are pinned (an engine seam is available at this stage, unlike stage 0).
    assert decision.constitution_version == "sha256:stub-constitution"
    assert decision.policy_version == "sha256:stub-policy"
    assert decision.trust_score == 0.5


def test_permitted_action_proceeds_normally() -> None:
    """`check` -> None (sufficient ring, or an unregistered target) = normal evaluation."""
    pipeline, ident, pol, scorer, audit, priv = _build(verdict=None)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow
    assert ident.calls == 1 and pol.calls == 1 and scorer.calls == 1
    assert {r.stage for r in decision.reasons} == {"identity", "policy", "risk", "graduated"}
    assert priv.calls == 1


def test_privilege_none_is_backward_compatible() -> None:
    """No `privilege` wired -> stage 1e never runs, behavior unchanged."""
    ident = FakeIdentityStage(ok=True)
    pol = SpyPolicyEngine(Outcome.allow)
    scorer = SpyScorer()
    audit = FakeAuditWriter()
    pipeline = Pipeline(identity=ident, policy=pol, scorers=[scorer], audit=audit)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow
    assert ident.calls == 1 and pol.calls == 1
    assert not any(r.stage == "privilege" for r in decision.reasons)


def test_forged_identity_denies_before_the_privilege_check_runs() -> None:
    """Stage 1e runs AFTER identity, so the ring is keyed on a VERIFIED agent_id: a forged token
    denies at identity and the privilege stub is NEVER called (an unverified caller can neither
    consume nor probe ring state)."""
    pipeline, ident, pol, scorer, audit, priv = _build(
        verdict=_PV("db_drop", 3, 0), identity_ok=False
    )
    decision = asyncio.run(pipeline.evaluate(_action(token="forged")))
    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    assert ident.calls == 1
    assert priv.calls == 0  # the gate never saw the unverified, attacker-claimed id


def test_check_is_keyed_on_the_verified_agent_and_the_action_target() -> None:
    pipeline, ident, pol, scorer, audit, priv = _build(verdict=_PV("db_drop", 3, 0))
    asyncio.run(pipeline.evaluate(_action()))
    assert priv.seen == [("agent-1", "db_drop")]


def test_privilege_check_is_in_memory_no_session_on_hot_path() -> None:
    """The stub exposes ONLY sync `check` and is never handed a session — the hot-path privilege
    check is an in-memory lookup, no per-action DB read."""
    pipeline, ident, pol, scorer, audit, priv = _build(verdict=_PV("db_drop", 3, 0))
    asyncio.run(pipeline.evaluate(_action()))
    assert priv.calls == 1  # exactly one in-memory lookup
    assert not hasattr(priv, "session_factory")


def test_privilege_deny_survives_a_policy_that_would_allow() -> None:
    """The gate only ever RESTRICTS: an allowing policy is never reached."""
    pipeline, ident, pol, scorer, audit, priv = _build(
        verdict=_PV("db_drop", 5, 1), policy=Outcome.allow
    )
    assert asyncio.run(pipeline.evaluate(_action())).outcome is Outcome.deny
    assert pol.calls == 0


@pytest.mark.latency
def test_privilege_denied_path_latency_in_memory() -> None:
    """Stage 1e is one in-memory dict lookup: the denied path stays fast."""
    import time

    pipeline, ident, pol, scorer, audit, priv = _build(verdict=_PV("db_drop", 3, 0))
    action = _action()
    start = time.perf_counter()
    for _ in range(200):
        asyncio.run(pipeline.evaluate(action))
    elapsed_ms = (time.perf_counter() - start) / 200 * 1000
    # Generous budget: the per-action work is identity + one in-memory lookup + a fake append.
    assert elapsed_ms < 25, f"privilege-denied latency {elapsed_ms:.3f}ms over budget"
