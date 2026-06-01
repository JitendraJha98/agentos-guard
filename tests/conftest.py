"""Shared pytest fixtures scaffold for Phase 1 (Wave-0 test infrastructure).

Built by plan 01-01; downstream plans (01-02 … 01-06) replace the placeholder
bodies with real wiring. The `make_http_get` helper and the SQLite-backed
`audit_store` seam are usable now so later unit/integration tests reuse them.

No-Docker deviation (CONTEXT.md D-14): the audit/e2e tests run against a
SQLite-backed Store, NOT a testcontainers Postgres. There is no `testcontainers`
or Docker import anywhere in this file.
"""

import pytest
from sqlalchemy import MetaData, create_engine

from agentos_contract import ActionType, AgentAction


def make_http_get(url: str, fetched_content: str = "") -> AgentAction:
    """Build an `http_get` tool-call AgentAction (the single governed tool, D-01).

    `fetched_content` carries the page body the agent would retrieve — the seam
    where the indirect-prompt-injection probe is planted in later waves.
    """
    return AgentAction(
        agent_id="test-agent",
        type=ActionType.tool_call,
        target="http_get",
        payload={"url": url, "content": fetched_content},
    )


@pytest.fixture
def audit_store():
    """A fresh, function-scoped SQLite-backed store seam (D-14: no Docker).

    Yields an in-memory SQLAlchemy SQLite engine with an empty schema created.
    Plan 01-02 replaces this body with the real `Store` (its SQLAlchemy models'
    `Base.metadata.create_all` runs against this same SQLite backend). Kept as a
    working engine now so the fixture imports and connects cleanly Wave-1.
    """
    engine = create_engine("sqlite+pysqlite:///:memory:")
    metadata = MetaData()
    metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def pipeline_with_principle():
    """The 4-stage pipeline with the egress-allowlist principle loaded.

    Provided by a later wave (plan 01-05 / 01-06)."""
    pytest.skip("provided by later wave")


@pytest.fixture
def pipeline_without_principle():
    """The pipeline with the egress-allowlist principle removed — the D-04
    proof-of-life: deleting the principle must flip the probe to allow.

    Provided by a later wave (plan 01-06)."""
    pytest.skip("provided by later wave")


@pytest.fixture
def prompt_injection_scorer():
    """The deterministic SEC-01 PromptInjectionScorer (plan 01-03)."""
    from agentos_pipeline.risk import PromptInjectionScorer

    return PromptInjectionScorer()


@pytest.fixture
def registered_agent_token():
    """A registered agent plus its issued, signed EdDSA identity token.

    Provided by a later wave (plan 01-02)."""
    pytest.skip("provided by later wave")
