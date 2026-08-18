"""ECON-01 — cost attribution: what an action cost, attributed to an agent."""

from __future__ import annotations

import asyncio
import json
import logging
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


def test_a_downstream_row_round_trips_its_provider_and_invents_no_gpu_reading(store) -> None:
    """ECON-03's two halves share one row. `provider` is the action's own target — a fact — while
    the GPU columns stay NULL because nothing measured a GPU here.

    Null, never 0: a zero reads as 'this agent used no GPU', which is a claim, where the truth is
    'we did not measure'. The same distinction `cost_micro_usd` already keeps for dollars.
    """
    with store() as s:
        s.add(
            CostRecord(
                action_id=uuid4(),
                agent_id="a1",
                action_type="tool_call",
                provider="api.stripe.com",
            )
        )
        s.commit()
    with store() as s:
        row = s.scalars(select(CostRecord)).one()

    assert row.provider == "api.stripe.com"
    assert row.gpu_seconds is None
    assert row.gpu_memory_mib is None
    assert row.gpu_attribution is None


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


def test_usage_is_extracted_from_the_langchain_MODEL_RESPONSE_the_hook_really_gets() -> None:
    """langchain 1.x hands `awrap_model_call`'s handler a `ModelResponse`, NOT the message: the
    usage lives on `.result[i]`, and the wrapper object carries none of its own.

    Reading only the outer value meant the flagship PEP metered nothing on `model_invocation` — the
    one action type that has a token cost — while a handler stub returning an `AIMessage` (a shape
    the real handler cannot return) made the test suite say otherwise.
    """
    from langchain.agents.middleware.types import ModelResponse
    from langchain_core.messages import AIMessage

    response = ModelResponse(
        result=[
            AIMessage(
                content="ok",
                usage_metadata={"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500},
                response_metadata={"model_name": "gpt-4o-2026-05-01"},
            )
        ]
    )

    assert extract_usage(response) == Usage(1000, 500, "gpt-4o-2026-05-01")


def test_a_result_that_merely_LOOKS_like_usage_is_not_provider_reported() -> None:
    """A tool or MCP return value is not a provider. Duck-typing usage off the result ITSELF made
    any mapping with the two field names write the ledger: a `count_tokens` tool billed its own
    answer as real spend, and a hostile MCP response could post an arbitrarily NEGATIVE row that
    offsets an agent's total — a budget-evasion primitive for Slice 11c."""
    assert extract_usage({"input_tokens": 15_000, "output_tokens": 0}) is None
    assert extract_usage({"input_tokens": -50_000_000, "output_tokens": 0}) is None


def test_an_untrusted_result_cannot_price_the_ledger_through_a_NAMED_usage_holder() -> None:
    """REGRESSION: narrowing from "duck-type the result" to "read a NAMED usage holder" was not
    enough — a hostile result supplies the named holder just as easily.

    Note the payload is POSITIVE. The earlier probe used negative counts, which `Usage.reported`
    refuses on its own, so it passed with the hole wide open. Positive numbers pass every plausibility
    check, and `response_metadata` then hands `_model` a served-model name, so the forged row came out
    fully PRICED with the operator's rate version pinned beside it — and rode into the hash-chained
    `cost_recorded` event as evidence.

    Refusing negatives closed budget EVASION and left unbounded INFLATION: one prompt-injected MCP
    server drains the budget of every agent that calls it, and posts a fabricated dollar figure to
    any chargeback report. Both directions are the same defect, and only one of them was fixed.
    """
    hostile = {
        "content": "here is your answer",
        "usage": {"input_tokens": 100_000_000, "output_tokens": 100_000_000},
        "response_metadata": {"model_name": "gpt-4o"},
    }

    assert extract_usage(hostile) is None
    assert extract_usage([hostile]) is None
    assert extract_usage({"result": [hostile]}) is None


def test_implausible_reported_counts_are_refused_rather_than_believed() -> None:
    """Negative, boolean and column-overflowing counts all mean 'not a usable figure'.

    The overflow case is the one an agent can weaponise: an `input_tokens` too large for the
    BigInteger column made the INSERT raise, the PEP swallowed it, and the action recorded NOTHING
    — one absurd number per call and metering is off. Refusing it here keeps the row.
    """
    from langchain_core.messages import AIMessage

    def _reported(inp, out):
        return AIMessage(
            content="ok", usage_metadata={"input_tokens": inp, "output_tokens": out, "total_tokens": 0}
        )

    assert extract_usage(_reported(-5, 0)) is None
    assert extract_usage(_reported(10**19, 0)) is None
    assert extract_usage(type("R", (), {"usage": {"input_tokens": True, "output_tokens": False}})()) is None


def test_a_hand_built_usage_refuses_an_impossible_count() -> None:
    """The extractor answers 'we do not know'; the type itself REFUSES — anything constructing a
    `Usage` by hand (the gateway mapper, Slice 11c) is a programming error, not a provider."""
    with pytest.raises(ValueError, match="input_tokens must be a non-negative int"):
        Usage(-1, 0)
    with pytest.raises(ValueError, match="output_tokens must be a non-negative int"):
        Usage(0, 2**63)


def test_a_result_that_reports_no_model_yields_None_rather_than_a_guess() -> None:
    """`_model` is 'never guessed' — so a result carrying no `response_metadata` at all must come
    back with model None, letting the recorder fall back to the REQUESTED model (a weaker claim,
    made in one place) instead of the extractor inventing a served one."""
    holder = type("R", (), {"usage": {"input_tokens": 7, "output_tokens": 3}})()

    assert extract_usage(holder).model is None


def test_an_already_normalized_usage_keeps_the_model_it_arrived_with() -> None:
    """The gateway's wire-format mapper hands the seam a finished `Usage`. Rebuilding it would
    re-read the served model off the outer HTTP response, which carries none — silently recording
    a priced model as unpriced."""
    holder = type("R", (), {"usage": Usage(10, 5, "claude-x")})()

    assert extract_usage(holder) == Usage(10, 5, "claude-x")


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


def test_money_is_an_INTEGER_of_micro_usd_not_a_float() -> None:
    """The central claim of the column, and it was untested: a float sails through `BigInteger` on
    SQLite and through `SUM`, so the drift the integer exists to prevent would arrive silently."""
    book = PriceBook({"gpt-4o": (0.003, 0.015)}, version="2026-08")

    cost = book.cost_micro_usd("gpt-4o", 1234, 567)

    assert type(cost) is int
    assert cost == 12_207  # 1234 * $0.003/1k + 567 * $0.015/1k = $0.012207


def test_a_cost_too_small_to_represent_is_UNPRICED_not_a_priced_zero(store) -> None:
    """A real action on a real rate, quantised to `0` with a rate version pinned beside it, asserts
    'these rates priced this action, and it was free'. Cheap models are exactly the ones that arrive
    in millions: 1M embedding calls at $0.02/1M truly cost $0.40 and were reported as $0.000000.

    Unpriced is the honest answer — `unpriced_actions` then shows the operator the gap.
    """
    book = PriceBook({"text-embedding-3-small": (0.00002, 0.0)}, version="2026-08")

    assert book.cost_micro_usd("text-embedding-3-small", 20, 0) is None  # true cost $0.0000004

    rec = CostRecorder(store, AuditWriter(store), book)
    action = _action(model="text-embedding-3-small")
    asyncio.run(rec.record(action, _decision(action), Usage(20, 0, "text-embedding-3-small")))

    row = _costs(store)[0]
    assert row.input_tokens == 20, "the tokens are still a fact we observed"
    assert row.price_book_version is None, "a version beside a 0 would claim the action was free"


def test_a_genuinely_free_action_on_a_priced_model_still_costs_a_pinned_zero() -> None:
    """The mirror of the case above: zero tokens at a known rate really is $0.00, and the version
    pin says which rates say so. Collapsing these two would lose the distinction entirely."""
    book = PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08")

    assert book.cost_micro_usd("gpt-4o", 0, 0) == 0


def test_rounding_is_half_up_not_bankers() -> None:
    """`round()` is banker's: 0.5 -> 0 and 2.5 -> 2 while 1.5 -> 2 and 3.5 -> 4. An operator
    reconciling the ledger by hand sees a figure that is non-monotonic in their own rate table."""
    book = PriceBook({"m": (0.0005, 0.0)}, version="v")  # 1 token = 0.5 micro-USD

    assert book.cost_micro_usd("m", 1, 0) == 1  # round(0.5) would be 0
    assert book.cost_micro_usd("m", 5, 0) == 3  # round(2.5) would be 2


def test_a_price_book_with_rates_must_name_the_version_they_came_from() -> None:
    """The version pin is what lets a bill be re-derived and stops a rate correction rewriting
    history. A default placeholder makes every row carry the same string, so two different rate
    tables become indistinguishable on the record — the pin present but vacuous."""
    with pytest.raises(ValueError, match="must name the version"):
        PriceBook({"gpt-4o": (2.5, 10.0)})

    PriceBook()  # an empty book prices nothing, so it needs no version


def test_an_over_long_version_is_refused_at_startup_not_at_every_insert() -> None:
    """`price_book_version` is String(32). On Postgres an over-long one makes EVERY metered insert
    raise into the PEP's swallow, so the operator gets a permanently empty ledger and no failed
    request anywhere to explain it. A typo must fail loudly at wiring time instead."""
    with pytest.raises(ValueError, match="at most 32 characters"):
        PriceBook({"gpt-4o": (2.5, 10.0)}, version="2026-08-19-corrected-after-vendor-notice")


def test_a_negative_rate_is_refused_because_it_would_refund_budget() -> None:
    """A misplaced minus is the reachable path into ECON-02's ledger: negative costs SUM, so every
    priced action would credit the agent and an agent already over its limit would spend its way
    back under one. Caught where it is still a typo rather than where it is an unexplainable bill."""
    with pytest.raises(ValueError, match="must not be negative"):
        PriceBook({"gpt-4o": (-2.5, 10.0)}, version="2026-08")

    with pytest.raises(ValueError, match="must not be negative"):
        PriceBook({"gpt-4o": (2.5, -10.0)}, version="2026-08")

    PriceBook({"free-tier": (0.0, 0.0)}, version="2026-08")  # a zero rate is a real, priced rate


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


def _cost_events(store) -> list[dict]:
    with store() as s:
        return [r.body for r in s.scalars(select(AuditRecord)) if r.body["kind"] == "cost_recorded"]


def test_every_recorded_cost_is_also_AUDITED(store) -> None:
    """A money row with no chain entry is a figure with no evidence behind it — the exact
    reconciliation gap the audit chain exists to close. Deleting the append entirely used to leave
    the whole module green, which also made the canary test below vacuous: a scan over an EMPTY
    audit log finds no secret either."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = _action()

    asyncio.run(rec.record(action, _decision(action), Usage(1000, 500, "gpt-4o")))

    event = _cost_events(store)[0]
    assert event["action_id"] == str(action.id)
    assert (event["agent"], event["input_tokens"], event["output_tokens"]) == ("a1", 1000, 500)
    assert event["cost_micro_usd"] == 7_500_000


def test_the_audit_body_carries_no_prompt_text(store) -> None:
    """AUD-04: identifiers and numbers only. The prompt is the thing most worth leaking and it is
    exactly what a cost event does not need. Asserted against the cost event ITSELF, not the whole
    log — otherwise "no canary anywhere" is satisfied by there being no cost event at all."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = _action()
    action.payload["messages"] = [{"role": "user", "content": "SECRET-CANARY-TEXT"}]

    asyncio.run(
        rec.record(action, _decision(action), Usage(input_tokens=1, output_tokens=1, model="gpt-4o"))
    )

    events = _cost_events(store)
    assert len(events) == 1
    assert "SECRET-CANARY-TEXT" not in json.dumps(events)


def test_a_cost_row_is_never_committed_without_its_audit_event(store) -> None:
    """Two stores, not one transaction — so the ORDER decides which way a partial failure falls.
    The audit event goes first: an event with no row is a visible gap an operator can reconcile
    against the chain, while a committed row with no event is money the evidence cannot explain.
    (AUD-04's own last gate can raise here: a served model name that matches a key pattern.)"""

    class _BrokenAudit:
        async def append_event(self, kind, body):
            raise RuntimeError("audit chain unavailable")

    rec = CostRecorder(store, _BrokenAudit(), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = _action()

    with pytest.raises(RuntimeError):
        asyncio.run(rec.record(action, _decision(action), Usage(1000, 500, "gpt-4o")))

    assert _costs(store) == []


def test_a_tool_argument_named_model_does_not_price_the_tool_call(store) -> None:
    """`normalize_action` puts a tool's own ARGS at the top of the payload, so the
    requested-model fallback billed an `http_get` at gpt-4o rates because the attacker named an
    argument well. Only a model invocation has a model to fall back to."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = AgentAction(
        agent_id="a1",
        type=ActionType.tool_call,
        target="http_get",
        payload={"model": "gpt-4o", "url": "https://api.example.com/x"},
    )

    asyncio.run(rec.record(action, _decision(action), Usage(1_000_000, 0)))

    row = _costs(store)[0]
    assert row.model is None
    assert row.cost_micro_usd is None, "a tool call priced at a model's rate is a fabricated bill"


def test_an_over_long_model_name_keeps_the_row_instead_of_dropping_it(store) -> None:
    """`model` is String(128). On Postgres — the production target — an over-long value makes the
    INSERT raise, the PEP swallows it, and the action records NOTHING: one long model string per
    call and metering is off. Truncated, the row survives and simply misses the price book."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    action = _action()

    asyncio.run(rec.record(action, _decision(action), Usage(9, 1, "m" * 400)))

    row = _costs(store)[0]
    assert len(row.model) == 128
    assert (row.input_tokens, row.output_tokens) == (9, 1)


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


def test_totals_report_NO_dollars_at_all_when_nothing_was_priced(store) -> None:
    """SQL `SUM` over an all-null column is NULL, and coercing that to 0 invents 'this agent spent
    $0.00' — on the operator-facing route, for the DEFAULT deployment that supplied no price book.
    `priced_actions: 0` is the honest half, but the dollar field is the one a dashboard renders and
    the one Slice 11c reads."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook())
    for _ in range(3):
        action = _action(model="mystery")
        asyncio.run(rec.record(action, _decision(action), Usage(1000, 0, "mystery")))

    t = rec.totals()[0]

    assert t["cost_micro_usd"] is None
    assert (t["actions"], t["priced_actions"], t["input_tokens"]) == (3, 0, 3000)


def test_the_detail_route_can_be_PAGED_past_its_cap(store) -> None:
    """Bounded but unpageable made the two routes disagree about the same agent's money with
    nothing to say the detail was clipped — an operator reconciling against an invoice was simply
    short. The id tiebreaker is what makes paging safe: SQLite's timestamps have one-second
    resolution, so without it a page boundary inside a tied second skips and repeats rows."""
    rec = CostRecorder(store, AuditWriter(store), PriceBook({"gpt-4o": (2.5, 10.0)}, version="v"))
    for _ in range(7):
        action = _action()
        asyncio.run(rec.record(action, _decision(action), Usage(100, 0, "gpt-4o")))

    pages = [r["action_id"] for page in range(4) for r in rec.for_agent("a1", limit=2, offset=page * 2)]

    assert len(pages) == 7 and len(set(pages)) == 7, "paging must not skip or repeat a row"
    assert set(pages) == {r["action_id"] for r in rec.for_agent("a1", limit=100)}


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


def test_a_metering_failure_does_not_break_the_agents_call(store, caplog) -> None:
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

    with caplog.at_level(logging.ERROR, logger="agentos_sdk.enforce"):
        result = asyncio.run(
            governed_call(
                _Pipeline(), _action(), _returns(msg), reporter=reporter, meter=_Broken()
            )
        )

    assert result is msg
    assert reporter.failures == 0, "a bookkeeping failure is not an execution failure"
    # ...but it must not be INVISIBLE either. A swallow that only whispers at warning level is how
    # a deployment discovers a week later that its ledger — and Slice 11c's budgets with it — has
    # been silently under-counting.
    assert [r.levelname for r in caplog.records] == ["ERROR"]


def test_a_result_with_no_usage_records_nothing_and_reports_no_failure(store, caplog) -> None:
    """No row at all, not a zero row: the ledger must never claim an action was free because the
    provider declined to say what it used.

    And SILENTLY. "Nothing to meter" is the normal case for every tool call — handing the recorder a
    None and letting it blow up into the swallow would give the same empty table while filling an
    operator's logs with metering errors, which is how a real one stops being read.
    """
    from agentos_sdk.enforce import governed_call

    rec = _recorder(store)

    with caplog.at_level(logging.WARNING, logger="agentos_sdk.enforce"):
        asyncio.run(governed_call(_Pipeline(), _action(), _returns("plain string"), meter=rec))

    assert _costs(store) == []
    assert caplog.records == []


def test_an_MCP_result_shaped_like_usage_cannot_write_the_LEDGER(store) -> None:
    """The end-to-end form of the untrusted-result hole. An MCP server's response is a value we do
    not control; treating one as provider-reported usage let a single hostile reply post a
    -$34,992 row and drive its agent's total negative — under-budget forever, while the operator's
    dashboard shows a plausible small number."""
    from agentos_sdk import governed_mcp_call

    rec = _recorder(store)
    hostile = {"input_tokens": -10_000_000, "output_tokens": -1_000_000}

    asyncio.run(
        governed_mcp_call(
            _Pipeline(), "tok", server="s", tool="t", args="{}",
            run=_returns(hostile), meter=rec,
        )
    )

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

    async def _model_handler(request):
        # The shape langchain 1.x really hands this hook — a ModelResponse wrapping the messages,
        # never the AIMessage itself. Stubbing the message here is what hid the extractor's
        # blindness: it asserted the ONE shape the real handler cannot return.
        from langchain.agents.middleware.types import ModelResponse

        return ModelResponse(result=[_message()])

    async def _tool_handler(request):
        return _message()

    mw = GovernanceMiddleware(_Pipeline(), "tok", meter=_recorder(store))

    asyncio.run(mw.awrap_model_call(_ModelRequest(), _model_handler))
    asyncio.run(mw.awrap_tool_call(_ToolRequest(), _tool_handler))

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


def test_paging_over_rows_tied_on_recorded_at_neither_skips_nor_repeats(store) -> None:
    """REGRESSION: the `id` tiebreaker had no test — dropping it left the suite green because
    SQLite happens to return rowid order.

    Postgres is the production target (D-14) and genuinely leaves ties unordered, which is exactly
    when a paged reader silently skips and repeats rows. SQLite's CURRENT_TIMESTAMP has one-second
    resolution, so at real metering rates ties are the NORM, not an edge case — an operator walking
    the ledger to reconcile against an invoice would get a subtly wrong total and no indication.

    The assertion is on the SET across pages, not on the order within one: the tiebreaker exists to
    make paging total and stable, not to rank rows by anything meaningful.

    HONEST LIMIT: this test cannot fail on SQLite even with the tiebreaker removed, because SQLite
    returns tied rows in rowid order, which is insertion order, which is stable. It proves the paging
    contract (limit/offset walk the whole ledger exactly once); it does NOT prove the tiebreaker. The
    structural test below is what covers that, and it is a weaker kind of evidence — stated rather
    than papered over, because the failure it guards only appears on the production backend.
    """
    from datetime import datetime, timezone

    tied = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc).replace(tzinfo=None)
    ids = [uuid4() for _ in range(10)]
    with store() as s:
        s.add_all(
            CostRecord(
                id=i,
                action_id=uuid4(),
                agent_id="a1",
                action_type="model_invocation",
                model="m",
                input_tokens=1,
                output_tokens=1,
                recorded_at=tied,  # every row in the SAME second
            )
            for i in ids
        )
        s.commit()
    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))

    walked = [r["action_id"] for page in range(5) for r in rec.for_agent("a1", limit=2, offset=page * 2)]

    assert len(walked) == 10, "a paged walk must return every row exactly once"
    assert len(set(walked)) == 10, "no row may appear on two pages"


def test_the_paging_query_orders_by_the_id_tiebreaker(store) -> None:
    """The structural half of the tiebreaker guard, because the behavioral half cannot run here.

    On SQLite ties come back in rowid order, so a behavioral test passes whether or not the
    tiebreaker exists. Postgres — the production target (D-14) — leaves ties genuinely unordered,
    and that is exactly when a paged reader skips and repeats rows. Asserting the compiled ORDER BY
    is white-box and I would not reach for it if the behavior were reachable; here the alternative
    is an unverified claim in a docstring, and an unverified claim is how this defect got shipped.
    """
    import inspect

    rec = CostRecorder(store, AuditWriter(store), PriceBook({}, version="v"))
    rec.for_agent("a1", limit=1)  # the real call path still executes

    assert "CostRecord.id.desc()" in inspect.getsource(CostRecorder.for_agent), (
        "for_agent must break recorded_at ties on the primary key; without it Postgres returns "
        "tied rows in an arbitrary order and a paged walk silently skips and repeats"
    )
