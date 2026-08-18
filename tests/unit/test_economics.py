"""ECON-01 — cost attribution: what an action cost, attributed to an agent."""

from __future__ import annotations

import asyncio
import json
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason, Usage
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.economics import CostRecorder, PriceBook
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import AuditRecord, CostRecord
from agentos_sdk.usage import extract_usage


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    create_all(engine)
    return create_session_factory(engine)


def _action(agent: str = "a1", model: str = "gpt-4o") -> AgentAction:
    return AgentAction(
        agent_id=agent,
        type=ActionType.model_invocation,
        target="chat",
        payload={"model": model, "messages": [{"role": "user", "content": "hi"}]},
    )


def _decision(action: AgentAction, outcome: Outcome = Outcome.allow) -> Decision:
    return Decision(
        action_id=action.id,
        outcome=outcome,
        reasons=[
            Reason(
                stage="policy", code="constitution_principle_fired",
                principle_ref="2.1", evidence={"effect": outcome.value},
            )
        ],
    )


def test_cost_record_round_trips_with_an_unpriced_model(store) -> None:
    """The unpriced case is the DEFAULT, not an edge case: an operator who has not supplied rates
    must still get token attribution, and must not be shown a fabricated dollar figure."""
    with store() as s:
        s.add(
            CostRecord(
                action_id=uuid4(),
                agent_id="a1",
                action_type="model_invocation",
                model="some-unpriced-model",
                input_tokens=100,
                output_tokens=20,
            )
        )
        s.commit()
    with store() as s:
        row = s.scalars(select(CostRecord)).one()

    assert (row.input_tokens, row.output_tokens) == (100, 20)
    assert row.cost_micro_usd is None and row.price_book_version is None


def test_the_cost_event_kind_is_accepted_and_unknown_kinds_are_not(store) -> None:
    audit = AuditWriter(store)

    asyncio.run(
        audit.append_event("cost_recorded", {"agent": "a1", "input_tokens": 1, "output_tokens": 1})
    )

    with pytest.raises(ValueError):
        asyncio.run(audit.append_event("cost_definitely_not_a_kind", {}))


# --- usage is REPORTED, never inferred (D-7) ----------------------------------


def test_usage_is_extracted_from_a_langchain_message() -> None:
    from langchain_core.messages import AIMessage

    msg = AIMessage(
        content="ok", usage_metadata={"input_tokens": 11, "output_tokens": 4, "total_tokens": 15}
    )

    assert extract_usage(msg) == Usage(input_tokens=11, output_tokens=4, model=None)


def test_usage_is_extracted_from_an_openai_agents_usage_object() -> None:
    """Same extractor, no provider branch — the two SDKs agree on the field names."""
    pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")
    from agents.usage import Usage as AgentsUsage

    holder = type(
        "R", (), {"usage": AgentsUsage(requests=1, input_tokens=7, output_tokens=3, total_tokens=10)}
    )()

    got = extract_usage(holder)

    assert (got.input_tokens, got.output_tokens) == (7, 3)


def test_the_model_is_read_off_the_providers_own_response_metadata() -> None:
    """The model is what the provider ACTUALLY served, which is not always what was requested —
    an alias resolves to a dated snapshot, and a bill written against the requested name would
    price the wrong thing."""
    from langchain_core.messages import AIMessage

    msg = AIMessage(
        content="ok",
        usage_metadata={"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
        response_metadata={"model_name": "gpt-4o-2026-05-01"},
    )

    assert extract_usage(msg).model == "gpt-4o-2026-05-01"


def test_an_unrecognized_result_yields_None_not_zero() -> None:
    """THE property that keeps the ledger honest. Zero means 'this was free'; None means 'we do not
    know'. Collapsing them would put fabricated free actions into a budget decision and a
    compliance export."""
    assert extract_usage("just a string") is None
    assert extract_usage({"nothing": "useful"}) is None
    assert extract_usage(None) is None
    assert extract_usage(type("R", (), {"usage_metadata": {"input_tokens": "eleven"}})()) is None


# --- dollars are a CONVERSION the operator supplies ---------------------------


def test_pricing_is_exact_in_integer_micro_usd() -> None:
    book = PriceBook({"gpt-4o": (2.50, 10.00)}, version="2026-08")

    # 1000 in @ $2.50/1k + 500 out @ $10.00/1k = $2.50 + $5.00 = $7.50
    assert book.cost_micro_usd("gpt-4o", 1000, 500) == 7_500_000


def test_an_unpriced_model_costs_None_not_zero() -> None:
    book = PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08")

    assert book.cost_micro_usd("some-other-model", 1000, 500) is None
    assert book.cost_micro_usd(None, 1000, 500) is None


# --- recording: attribution + audit -------------------------------------------


def test_recording_attributes_cost_to_the_agent_and_the_action(store) -> None:
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08"))
    action = _action()

    asyncio.run(
        rec.record(action, _decision(action), Usage(input_tokens=1000, output_tokens=500, model="gpt-4o"))
    )

    with store() as s:
        row = s.scalars(select(CostRecord)).one()
    assert row.agent_id == "a1" and row.action_id == action.id
    assert row.action_type == "model_invocation"
    assert row.cost_micro_usd == 7_500_000 and row.price_book_version == "2026-08"


def test_an_unpriced_record_keeps_tokens_and_pins_no_rate_version(store) -> None:
    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="2026-08"))
    action = _action(model="mystery")

    asyncio.run(
        rec.record(action, _decision(action), Usage(input_tokens=9, output_tokens=1, model="mystery"))
    )

    with store() as s:
        row = s.scalars(select(CostRecord)).one()
    assert (row.input_tokens, row.output_tokens) == (9, 1)
    assert row.cost_micro_usd is None
    assert row.price_book_version is None, "a rate version on an unpriced row would imply a rate was applied"


def test_the_audit_body_carries_no_prompt_text(store) -> None:
    """AUD-04: identifiers and numbers only. The prompt is the thing most worth leaking and it is
    exactly what a cost event does not need."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = _action()
    action.payload["messages"] = [{"role": "user", "content": "SECRET-CANARY-TEXT"}]

    asyncio.run(
        rec.record(action, _decision(action), Usage(input_tokens=1, output_tokens=1, model="gpt-4o"))
    )

    with store() as s:
        blob = json.dumps([r.body for r in s.scalars(select(AuditRecord)).all()])
    assert "SECRET-CANARY-TEXT" not in blob


def test_totals_separate_priced_from_unpriced_actions(store) -> None:
    """A dollar total that silently covers only half the actions is a number an operator will
    misread as the whole bill."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    priced, unpriced = _action(), _action(model="mystery")

    asyncio.run(rec.record(priced, _decision(priced), Usage(1000, 500, "gpt-4o")))
    asyncio.run(rec.record(unpriced, _decision(unpriced), Usage(10, 10, "mystery")))

    t = rec.totals()[0]
    assert t["actions"] == 2 and t["priced_actions"] == 1 and t["unpriced_actions"] == 1
    assert t["input_tokens"] == 1010 and t["cost_micro_usd"] == 7_500_000


def test_per_agent_detail_lists_the_actions_behind_the_total(store) -> None:
    """The roll-up answers 'what did this agent cost'; ECON-01 also asks 'on which actions?'."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    mine, theirs = _action(agent="a1"), _action(agent="a2")

    asyncio.run(rec.record(mine, _decision(mine), Usage(1000, 500, "gpt-4o")))
    asyncio.run(rec.record(theirs, _decision(theirs), Usage(3, 4, "gpt-4o")))

    rows = rec.for_agent("a1")
    assert [r["action_id"] for r in rows] == [str(mine.id)]
    assert rows[0]["cost_micro_usd"] == 7_500_000 and rows[0]["price_book_version"] == "v"


# --- the ONE enforcement seam -------------------------------------------------


class _Pipeline:
    """A stub PDP with a fixed outcome. The PEP forms below differ only in HOW they reach
    `governed_call`, which is exactly the property these tests are about."""

    def __init__(self, outcome: Outcome = Outcome.allow) -> None:
        self._outcome = outcome

    async def evaluate(self, action):
        return _decision(action, self._outcome)


def _returns(value):
    """`run` in the shape `governed_call` wants it: a zero-arg awaitable callable."""

    async def _run():
        return value

    return _run


def _message(input_tokens: int = 1000, output_tokens: int = 500):
    from langchain_core.messages import AIMessage

    return AIMessage(
        content="ok",
        usage_metadata={
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
        response_metadata={"model_name": "gpt-4o"},
    )


def _recorder(store) -> CostRecorder:
    return CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))


def _costs(store) -> list[CostRecord]:
    with store() as s:
        return list(s.scalars(select(CostRecord)).all())


def test_an_allowed_action_is_metered_through_governed_call(store) -> None:
    from agentos_sdk.enforce import governed_call

    rec = _recorder(store)
    action = _action()

    asyncio.run(governed_call(_Pipeline(), action, _returns(_message()), meter=rec))

    assert _costs(store)[0].cost_micro_usd == 7_500_000


def test_a_DENIED_action_is_never_metered(store) -> None:
    """A blocked action ran nothing, so it cost nothing. Metering it would bill an agent for work
    the control plane prevented — and would inflate the very budget that caused the block."""
    from agentos_sdk.enforce import GovernanceDenied, governed_call

    rec = _recorder(store)
    action = _action()

    with pytest.raises(GovernanceDenied):
        asyncio.run(
            governed_call(_Pipeline(Outcome.deny), action, _returns(_message()), meter=rec)
        )

    assert _costs(store) == []


def test_a_metering_failure_does_not_break_the_agents_call(store) -> None:
    """The action already succeeded. Raising here would hand the agent a false failure AND report a
    phantom execution error to the RUN-06 breaker."""
    from agentos_sdk.enforce import governed_call

    class _Broken:
        async def record(self, action, decision, usage):
            raise RuntimeError("ledger down")

    class _Reporter:
        def __init__(self) -> None:
            self.failures = 0

        async def record_failure(self, agent_id, target):
            self.failures += 1

    msg = _message()
    reporter = _Reporter()

    result = asyncio.run(
        governed_call(
            _Pipeline(), _action(), _returns(msg), reporter=reporter, meter=_Broken()
        )
    )

    assert result is msg
    assert reporter.failures == 0, "a bookkeeping failure is not an execution failure"


def test_a_result_with_no_usage_records_nothing(store) -> None:
    """No row at all, not a zero row: the ledger must never claim an action was free because the
    provider declined to say what it used."""
    from agentos_sdk.enforce import governed_call

    rec = _recorder(store)

    asyncio.run(governed_call(_Pipeline(), _action(), _returns("plain string"), meter=rec))

    assert _costs(store) == []


# --- every PEP form attributes identically ------------------------------------


def test_the_langchain_middleware_meters_both_of_its_hooks(store) -> None:
    """The two middleware call sites are separate `governed_call` invocations, so a meter threaded
    into one and forgotten in the other is exactly the divergence this slice exists to prevent."""
    from agentos_sdk import GovernanceMiddleware

    class _Model:
        model_name = "gpt-4o"

    class _ModelRequest:
        model = _Model()
        messages = ["summarize this"]

    class _ToolRequest:
        tool_call = {"name": "http_get", "args": {"url": "https://api.example.com/x"}, "id": "1"}

    async def _handler(request):
        return _message(input_tokens=1000, output_tokens=500)

    mw = GovernanceMiddleware(_Pipeline(), "tok", meter=_recorder(store))

    asyncio.run(mw.awrap_model_call(_ModelRequest(), _handler))
    asyncio.run(mw.awrap_tool_call(_ToolRequest(), _handler))

    assert [(r.action_type, r.cost_micro_usd) for r in _costs(store)] == [
        ("model_invocation", 7_500_000),
        ("tool_call", 7_500_000),
    ]


def test_the_sdk_wrappers_meter(store) -> None:
    from agentos_sdk import governed_mcp_call

    asyncio.run(
        governed_mcp_call(
            _Pipeline(), "tok", server="s", tool="t", args="{}",
            run=_returns(_message()), meter=_recorder(store),
        )
    )

    assert _costs(store)[0].action_type == "mcp_call"


def test_the_openai_agents_adapter_meters(store) -> None:
    pytest.importorskip("agents", reason="openai-agents (the `adapters` group) is not installed")
    from agents.usage import Usage as AgentsUsage

    from agentos_sdk.adapters.openai_agents import governed_tool

    class _Result:
        usage = AgentsUsage(requests=1, input_tokens=7, output_tokens=3, total_tokens=10)

    @governed_tool(_Pipeline(), "tok", meter=_recorder(store))
    async def http_get(url: str):
        return _Result()

    asyncio.run(http_get(url="https://api.example.com/x"))

    row = _costs(store)[0]
    assert (row.action_type, row.input_tokens, row.output_tokens) == ("tool_call", 7, 3)


def test_every_pep_form_takes_the_meter_last(store) -> None:
    """`meter` is APPENDED, never inserted: these are public entry points with positional callers,
    and a parameter added in the middle silently rebinds every one of them.

    The gateway is in this list even though a relayed HTTP `Response` carries no usage the extractor
    recognizes — the seam has to be present and identically shaped there, or a deployment that later
    learns to read provider bodies would have to grow a SECOND recording path, which is the exact
    disagreement `_run_reported` exists to prevent.
    """
    import inspect

    from agentos_gateway.app import create_gateway
    from agentos_sdk import GovernanceMiddleware, governed_delegation, governed_mcp_call, governed_memory_access
    from agentos_sdk.adapters.openai_agents import governance_tool_guardrail, governed_tool
    from agentos_sdk.enforce import governed_call

    for form in (
        governed_call,
        GovernanceMiddleware.__init__,
        governed_memory_access,
        governed_mcp_call,
        governed_delegation,
        governed_tool,
        governance_tool_guardrail,
        create_gateway,
    ):
        assert list(inspect.signature(form).parameters)[-1] == "meter", form.__qualname__
