"""Shared pytest fixtures for Phase 1 (Wave-0 test infrastructure, filled Wave-5).

The `make_http_get` helper and the SQLite-backed `audit_store` seam were authored
by plan 01-01; plan 01-06 (this wave) fills the four placeholder fixtures with real
wiring: `prompt_injection_scorer`, `registered_agent_token`, `pipeline_with_principle`,
and `pipeline_without_principle`.

No-Docker deviation (CONTEXT.md D-14): the audit/e2e tests run against a
SQLite-backed Store, NOT a testcontainers Postgres. There is no `testcontainers`
or Docker import anywhere in this file.
"""

from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine

from agentos_contract import ActionType, AgentAction, Outcome
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import PolicyResult, WasmPolicyEngine
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

# The compiled OPA WASM egress floor (built by the 01-04 CI/build step).
EGRESS_WASM = "policies/build/egress.wasm"
# The single allowlisted host for the Phase-1 slice (the "benign" demo target).
ALLOWLIST = ["api.example.com"]
# The agent identity the e2e + red-team probes act as.
AGENT_ID = "test-agent"


def make_http_get(url: str, fetched_content: str = "") -> AgentAction:
    """Build an `http_get` tool-call AgentAction (the single governed tool, D-01).

    `fetched_content` carries the page body the agent would retrieve — the seam
    where the indirect-prompt-injection probe is planted in later waves.
    """
    return AgentAction(
        agent_id=AGENT_ID,
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": url, "content": fetched_content},
    )


@dataclass
class WiredPipeline:
    """A fully-wired `Pipeline` plus the registered agent's signed token.

    Tests attach `token` to the probe action (`make_http_get` builds the action
    without one) before `await pipeline.evaluate(action)`. Bundling them keeps the
    pipeline and the identity that can pass its stage-1 verification together.
    """

    pipeline: Pipeline
    token: str
    agent_id: str


class _AllowAllPolicyEngine:
    """A PolicyEngine with the egress PRINCIPLE REMOVED — the D-04 proof-of-life.

    Modeling "delete the egress principle" by recompiling the Rego with the
    allowlist rule deleted would require the OPA CLI at test time (fragile,
    non-deterministic across environments). Structurally, deleting the principle
    means the policy floor no longer gates egress on the allowlist — i.e. the floor
    always allows. This engine is that exact structural state: it satisfies the same
    `PolicyEngine` Protocol (`evaluate(input) -> PolicyResult`) and always returns
    `allow`, with NO allowlist check. Note an *empty* allowlist would NOT work — the
    Rego floor is deny-by-default, so an empty allowlist still denies (verified); the
    principle being *removed* is what flips deny->allow, and that is what this models.
    """

    def evaluate(self, input: dict) -> PolicyResult:
        return PolicyResult(
            outcome=Outcome.allow,
            code="egress_principle_removed",
            policy_id="egress.allow",
            detail="egress principle deleted (D-04 proof-of-life variant)",
        )


def _new_store():
    """Fresh function-scoped in-memory SQLite Store (D-14: no Docker)."""
    engine = create_engine("sqlite+pysqlite:///:memory:")
    create_all(engine)
    return create_session_factory(engine)


def _wire(policy_engine) -> WiredPipeline:
    """Register the agent and build a Pipeline over the given policy engine.

    Both pipeline fixtures share the SAME identity engine / store / audit writer
    wiring and differ ONLY in the policy stage (the principle present vs. removed) —
    so any deny->allow flip is attributable to the principle alone (the regression
    lock's whole point).
    """
    session_factory = _new_store()
    registry = Registry(session_factory)
    token = registry.register(AGENT_ID)  # IDN-01: persist + issue the signed token
    pipeline = Pipeline(
        identity=IdentityStage(registry.identity),
        policy=policy_engine,
        scorers=[PromptInjectionScorer()],
        audit=AuditWriter(session_factory),
    )
    return WiredPipeline(pipeline=pipeline, token=token, agent_id=AGENT_ID)


@pytest.fixture
def audit_store():
    """A fresh, function-scoped SQLite-backed Store session factory (D-14: no Docker).

    Yields a sync SQLAlchemy sessionmaker bound to an in-memory SQLite engine with the
    registry + audit schema created. The same Store the AuditWriter / Registry use.
    """
    session_factory = _new_store()
    try:
        yield session_factory
    finally:
        session_factory.kw["bind"].dispose()


@pytest.fixture
def prompt_injection_scorer() -> PromptInjectionScorer:
    """The deterministic SEC-01 PromptInjectionScorer (plan 01-03)."""
    return PromptInjectionScorer()


@pytest.fixture
def registered_agent_token() -> str:
    """A registered agent's issued, signed EdDSA identity token (IDN-01).

    Registers `test-agent` against a fresh SQLite Store and returns the signed JWT
    the SDK middleware attaches to every action.
    """
    registry = Registry(_new_store())
    return registry.register(AGENT_ID)


@pytest.fixture
def pipeline_with_principle() -> WiredPipeline:
    """The 4-stage pipeline WITH the egress-allowlist principle loaded.

    Policy stage = the real `WasmPolicyEngine(egress.wasm, allowlist=["api.example.com"])`
    deterministic OPA WASM floor. Returns the pipeline + the registered agent's token.
    """
    return _wire(WasmPolicyEngine(EGRESS_WASM, allowlist=ALLOWLIST))


@pytest.fixture
def pipeline_without_principle() -> WiredPipeline:
    """The SAME pipeline but with the egress principle REMOVED — the D-04 proof-of-life.

    Deleting the principle must flip the exfil probe deny->allow. Identical wiring to
    `pipeline_with_principle` except the policy stage is the allow-all engine (the
    structural equivalent of the deleted Rego floor rule). If the probe still denies
    here, the WITH-principle test is meaningless — so this asserting `allow` is what
    makes the regression lock bite.
    """
    return _wire(_AllowAllPolicyEngine())
