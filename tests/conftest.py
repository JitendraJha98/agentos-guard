"""Shared pytest fixtures (Wave-0 infrastructure; migrated to the compiled
constitution in Phase-3 Slice 3).

The pipeline fixtures wire the REAL `ConstitutionPolicyEngine` over WASM compiled
at session start from the test-owned constitutions (tests/fixtures/*.yaml) via the
OPA CLI (vendored exe on the Windows dev box, PATH on CI). When no OPA binary is
found anywhere, the dependent tests skip cleanly.

No-Docker deviation (CONTEXT.md D-14): the audit/e2e tests run against a
SQLite-backed Store, NOT a testcontainers Postgres. There is no `testcontainers`
or Docker import anywhere in this file.
"""

from dataclasses import dataclass
from pathlib import Path

import pytest
from sqlalchemy import create_engine

from _opa import BuiltPolicy, build_constitution_wasm, find_opa
from agentos_contract import ActionType, AgentAction
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.registry import Registry
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_pipeline.identity import IdentityStage
from agentos_pipeline.policy import ConstitutionPolicyEngine
from agentos_pipeline.risk import PromptInjectionScorer
from agentos_pipeline.runner import Pipeline

# The test-owned constitutions (Slice 3): principles 1.1/2.1/3.2/3.5, and the
# same file minus 1.1 (the REAL D-04 deleted-principle recompile).
CONSTITUTION_YAML = Path("tests/fixtures/test_constitution.yaml")
CONSTITUTION_NO_EGRESS_YAML = Path("tests/fixtures/test_constitution_no_egress.yaml")
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


def _build_constitution(tmp_path_factory, yaml_path: Path, label: str) -> BuiltPolicy:
    if find_opa() is None:
        pytest.skip("no OPA binary (vendored tools/opa/opa.exe or PATH) — cannot compile the test constitution")
    return build_constitution_wasm(yaml_path, tmp_path_factory.mktemp(label))


@pytest.fixture(scope="session")
def constitution_wasm(tmp_path_factory) -> BuiltPolicy:
    """The full test constitution, compiled ONCE per session."""
    return _build_constitution(tmp_path_factory, CONSTITUTION_YAML, "wasm_full")


@pytest.fixture(scope="session")
def constitution_wasm_no_egress(tmp_path_factory) -> BuiltPolicy:
    """The D-04 variant: the SAME constitution genuinely recompiled WITHOUT 1.1."""
    return _build_constitution(
        tmp_path_factory, CONSTITUTION_NO_EGRESS_YAML, "wasm_no_egress"
    )


def _engine(built: BuiltPolicy) -> ConstitutionPolicyEngine:
    return ConstitutionPolicyEngine(
        wasm_path=str(built.wasm_path),
        lists=built.bundle.lists,
        constitution_version=built.bundle.constitution_version,
        principles_meta=built.principles_meta,
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
def pipeline_with_principle(constitution_wasm) -> WiredPipeline:
    """The pipeline WITH the full test constitution (incl. egress principle 1.1).

    Policy stage = the real `ConstitutionPolicyEngine` over the compiled
    multi-principle WASM floor. Returns the pipeline + the registered agent's token.
    """
    return _wire(_engine(constitution_wasm))


@pytest.fixture
def pipeline_without_principle(constitution_wasm_no_egress) -> WiredPipeline:
    """The SAME pipeline, recompiled WITHOUT principle 1.1 — the D-04 proof-of-life.

    Slice 3 retired the structural allow-all stub: this is now a GENUINELY
    RECOMPILED constitution with the egress principle deleted (everything else
    identical, including the lists). Deleting the principle must flip the exfil
    probe deny->allow; if the probe still denies here, the WITH-principle test is
    meaningless — so this asserting `allow` is what makes the regression lock bite.
    """
    return _wire(_engine(constitution_wasm_no_egress))
