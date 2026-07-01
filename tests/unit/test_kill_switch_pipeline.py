"""Pipeline stage-0 kill-switch check (RUN-01/02, Task 3).

A killed agent's every SUBSEQUENT action is denied the instant the switch flips, BEFORE
any other stage runs (kill is stage 0, ahead of identity): a killed agent is denied even
with a VALID token — the strongest halt. Fleet kill denies everyone. The check is an
in-memory lookup (no DB read on the hot path) and the deny is audited (evidence_ref set).
`kill_switch=None` (the default) leaves behavior unchanged (backward compat).
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest

from agentos_contract import ActionType, AgentAction, Outcome, RiskFinding
from agentos_contract.policy_io import ConstitutionResult, MatchedPrinciple
from agentos_pipeline.runner import Pipeline


# --- fakes (mirroring tests/unit/test_pipeline.py) ---------------------------


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


class _KV:
    """A structural KillVerdict (scope + reason)."""

    def __init__(self, scope: str, reason: str) -> None:
        self.scope = scope
        self.reason = reason


class StubKillSwitch:
    """A structural KillSwitchLookup: sync `status`, NEVER given a session (proving the
    hot-path check is in-memory — no DB read per action)."""

    def __init__(self, verdict: _KV | None) -> None:
        self._verdict = verdict
        self.calls = 0

    def status(self, agent_id: str):
        self.calls += 1
        return self._verdict


def _action(token: str | None = "tok") -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": "https://api.example.com/data"},
        identity_token=token,
    )


def _build(*, kill: _KV | None, identity_ok: bool = True, policy: Outcome = Outcome.allow):
    ident = FakeIdentityStage(ok=identity_ok, trust_score=0.5,
                              detail="forged" if not identity_ok else "")
    pol = SpyPolicyEngine(policy)
    scorer = SpyScorer()
    audit = FakeAuditWriter()
    ks = StubKillSwitch(kill)
    pipeline = Pipeline(
        identity=ident, policy=pol, scorers=[scorer], audit=audit, kill_switch=ks
    )
    return pipeline, ident, pol, scorer, audit, ks


# --- tests -------------------------------------------------------------------


def test_killed_agent_denied_and_later_stages_skipped() -> None:
    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("agent", "rogue"))
    decision = asyncio.run(pipeline.evaluate(_action()))

    assert decision.outcome is Outcome.deny
    stages = [r.stage for r in decision.reasons]
    assert stages == ["killswitch"]  # ONLY the kill reason — every later stage skipped
    assert decision.reasons[0].code == "agent_killed"
    assert decision.reasons[0].detail == "rogue"
    assert ident.calls == 0 and pol.calls == 0 and scorer.calls == 0


def test_killed_agent_deny_is_audited() -> None:
    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("agent", "rogue"))
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert len(audit.calls) == 1  # evidence the action was blocked
    assert decision.evidence_ref is not None


def test_fleet_kill_denies_with_fleet_killed_code() -> None:
    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("fleet", "incident"))
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "fleet_killed"
    assert ident.calls == 0


def test_not_killed_agent_proceeds_normally() -> None:
    pipeline, ident, pol, scorer, audit, ks = _build(kill=None)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow
    assert ident.calls == 1 and pol.calls == 1 and scorer.calls == 1
    assert {r.stage for r in decision.reasons} == {"identity", "policy", "risk", "graduated"}


def test_kill_is_checked_before_identity_even_with_valid_token() -> None:
    """The strongest halt: a killed agent WITH a valid token still denies with
    `agent_killed`, NOT `identity_verified` — kill runs ahead of identity."""
    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("agent", "rogue"), identity_ok=True)
    decision = asyncio.run(pipeline.evaluate(_action(token="a-perfectly-valid-token")))
    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "agent_killed"
    assert ident.calls == 0  # identity never ran — kill is stage 0


def test_forged_token_still_caught_by_identity_when_not_killed() -> None:
    """A forged token claiming a NON-killed id falls through to identity afterward."""
    pipeline, ident, pol, scorer, audit, ks = _build(kill=None, identity_ok=False)
    decision = asyncio.run(pipeline.evaluate(_action(token="forged")))
    assert decision.outcome is Outcome.deny
    assert decision.reasons[0].code == "forged_or_unknown_identity"
    assert ident.calls == 1


def test_kill_switch_none_is_backward_compatible() -> None:
    """No kill_switch wired -> the stage-0 check never runs, behavior unchanged."""
    ident = FakeIdentityStage(ok=True)
    pol = SpyPolicyEngine(Outcome.allow)
    scorer = SpyScorer()
    audit = FakeAuditWriter()
    pipeline = Pipeline(identity=ident, policy=pol, scorers=[scorer], audit=audit)
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert decision.outcome is Outcome.allow
    assert ident.calls == 1 and pol.calls == 1


def test_kill_check_is_in_memory_no_session_on_hot_path() -> None:
    """The stub exposes ONLY sync `status` and is never handed a session — the hot-path
    kill check is an in-memory lookup, no per-action DB read."""
    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("agent", "rogue"))
    asyncio.run(pipeline.evaluate(_action()))
    assert ks.calls == 1  # exactly one in-memory lookup, no DB session involved
    assert not hasattr(ks, "session_factory")


def test_long_reason_is_truncated() -> None:
    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("agent", "x" * 1000))
    decision = asyncio.run(pipeline.evaluate(_action()))
    assert len(decision.reasons[0].detail) == 512


@pytest.mark.latency
def test_killed_path_latency_in_memory() -> None:
    """Stage-0 kill is an in-memory dict-ish lookup: the killed deny path stays fast."""
    import time

    pipeline, ident, pol, scorer, audit, ks = _build(kill=_KV("agent", "rogue"))
    action = _action()
    start = time.perf_counter()
    for _ in range(200):
        asyncio.run(pipeline.evaluate(action))
    elapsed_ms = (time.perf_counter() - start) / 200 * 1000
    # Generous budget: the per-action work is one in-memory lookup + a fake audit append.
    assert elapsed_ms < 25, f"killed-path latency {elapsed_ms:.3f}ms over budget"
