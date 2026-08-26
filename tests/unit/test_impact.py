"""ABOM-03 — vulnerability impact analysis.

The tests that matter are the ones about what a SMALL answer means. During an incident an operator
reads "2 agents affected" and acts on it; if 198 of 200 agents were never searched, or hold no ABOM
to match against, that number is a lie told by omission. So the counts that qualify the answer are
asserted as hard as the matches themselves.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_controlplane.impact import MATCH_DIGEST, MATCH_NAME, ImpactAnalyzer
from agentos_controlplane.resources import ResourceStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.supply_chain import KnownBad


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


@pytest.fixture
def resources(store) -> ResourceStore:
    return ResourceStore(store)


@pytest.fixture
def analyzer(store, resources) -> ImpactAnalyzer:
    return ImpactAnalyzer(resources, store)


def _declare(resources, agent_id: str, tools=(), models=()):
    """Declare an ABOM through the shipped ABOM-02 path so digests are the real ones."""
    return resources.declare_abom(
        agent_id,
        declaration={"tools": list(tools), "models": list(models)},
        expected_version=None,
    )


def _digest_of(resources, agent_id: str, name: str) -> str:
    for component in resources.get_abom_components(agent_id):
        if component["name"] == name:
            return component["digest"]
    raise AssertionError(f"{name} not found in {agent_id} components")


# --- the core question ---------------------------------------------------------


def test_a_digest_finds_every_agent_on_that_build(resources, analyzer) -> None:
    _declare(resources, "a1", tools=["shared-tool"])
    _declare(resources, "a2", tools=["shared-tool"])
    _declare(resources, "a3", tools=["unrelated"])
    digest = _digest_of(resources, "a1", "shared-tool")

    result = analyzer.who_uses(digest=digest)

    assert result["affected_agents"] == ["a1", "a2"]
    assert all(m["matched_on"] == MATCH_DIGEST for m in result["matches"])


def test_a_name_finds_agents_whose_build_differs(resources, analyzer) -> None:
    """A name match is the weaker, wider net: the component is present but this may not be the
    compromised build. An operator told only about the digest would miss these."""
    _declare(resources, "a1", tools=[{"name": "widget", "version": "1.0"}])
    _declare(resources, "a2", tools=[{"name": "widget", "version": "2.0"}])

    result = analyzer.who_uses(name="widget")

    assert result["affected_agents"] == ["a1", "a2"]
    assert all(m["matched_on"] == MATCH_NAME for m in result["matches"])


def test_digest_wins_over_name_when_both_match(resources, analyzer) -> None:
    """The remediations differ: "you are on the compromised build" is a different instruction from
    "you use this component and we could not confirm which build"."""
    _declare(resources, "a1", tools=["widget"])
    digest = _digest_of(resources, "a1", "widget")

    result = analyzer.who_uses(digest=digest, name="widget")

    assert [m["matched_on"] for m in result["matches"]] == [MATCH_DIGEST]


def test_an_unaffected_fleet_returns_no_matches(resources, analyzer) -> None:
    _declare(resources, "a1", tools=["safe"])

    result = analyzer.who_uses(digest="deadbeef" * 8)

    assert result["matches"] == [] and result["affected_agents"] == []


# --- what a small answer means --------------------------------------------------


def test_agents_holding_no_components_are_COUNTED_not_treated_as_safe(resources, analyzer,
                                                                      store) -> None:
    """An agent with no ABOM has nothing to match, which is not the same as an agent that is safe.

    Counting it as unaffected would let a fleet with two declared manifests out of two hundred read
    as "only two exposed" — the exact wrong conclusion to draw during an incident.
    """
    _declare(resources, "declared", tools=["widget"])
    resources.put_abom("raw", components={"tools": ["widget"]}, expected_version=None)

    result = analyzer.who_uses(name="widget")

    assert result["affected_agents"] == ["declared"]
    assert result["agents_without_components"] == 1, "the unmatched agent must be visible"


def test_the_answer_reports_how_much_of_the_fleet_it_searched(resources, analyzer) -> None:
    """"2 affected" out of 2 searched and out of 200 are different statements."""
    for i in range(5):
        _declare(resources, f"a{i}", tools=["widget"])

    result = analyzer.who_uses(name="widget", limit=2)

    assert result["agents_searched"] == 2 and result["agents_total"] == 5
    assert result["truncated"] is True, "a partial search must say so"


def test_a_query_with_neither_digest_nor_name_is_refused(analyzer) -> None:
    """With neither, the answer is the whole fleet — an inventory, not an impact analysis. Answering
    it would let a typo read as "everything is compromised"."""
    with pytest.raises(ValueError, match="digest or a name"):
        analyzer.who_uses()


# --- the whole known-bad set ----------------------------------------------------


def test_impact_of_reads_SEC_08s_own_known_bad_set(resources, analyzer) -> None:
    """Takes the shipped KnownBad rather than a private copy, so what this reports on is what the
    pipeline is actually denying against — the two cannot disagree about what is compromised."""
    _declare(resources, "a1", tools=["backdoored"])
    _declare(resources, "a2", tools=["fine"])

    result = analyzer.impact_of(KnownBad(names={"backdoored"}))

    assert result["affected_agents"] == ["a1"]


def test_one_component_matching_both_criteria_is_ONE_finding(resources, analyzer) -> None:
    """An inflated affected-count is as misleading as a deflated one: an operator sizing an incident
    response off "4 findings" when there is one component on one agent will over-escalate."""
    _declare(resources, "a1", tools=["widget"])
    digest = _digest_of(resources, "a1", "widget")

    result = analyzer.impact_of(KnownBad(digests={digest}, names={"widget"}))

    assert len(result["matches"]) == 1
    assert result["affected_agents"] == ["a1"]


def test_an_empty_known_bad_set_returns_nothing_rather_than_everything(analyzer, resources) -> None:
    """A feed that has not loaded yet must not read as "the whole fleet is clean" OR scan it."""
    _declare(resources, "a1", tools=["widget"])

    result = analyzer.impact_of(KnownBad())

    assert result["matches"] == [] and result["agents_searched"] == 0


def test_the_finding_carries_the_provenance_abom_02_recorded(resources, analyzer) -> None:
    """`first_seen` answers "how long have we been exposed", which is the second question an operator
    asks and the one a bare agent list cannot answer."""
    _declare(resources, "a1", tools=["widget"])

    match = analyzer.who_uses(name="widget")["matches"][0]

    assert match["first_seen"] and match["version"] == 1
    assert match["kind"] == "tools"
