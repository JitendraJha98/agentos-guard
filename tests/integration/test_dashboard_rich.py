"""OBS-06 / DASH-04 — the live graph, per-agent SLOs, and attack visualization.

The failure mode specific to a dashboard slice is that a TEMPLATE quietly undoes an invariant the
data layer worked to establish. Slice 12a made a rate impossible to obtain without its sample size;
Slice 12d refused to render a verdict about liveness and kept governance blocks out of the error
count. A chart is where both of those die. So the assertions here are on the RENDERED page, not on
the collaborators that feed it.

The other property is that node names are agent-controlled, and this is the page with the kill
switch on it.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from agentos_contract import ActionType, AgentAction, Decision, Outcome, Reason
from agentos_controlplane.api import create_app
from agentos_controlplane.approvals import ApprovalStore
from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.dashboard import mount_dashboard
from agentos_controlplane.graph import AgentGraphStore
from agentos_controlplane.health import HealthStore
from agentos_controlplane.inventory import InventoryStore
from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.validation import ValidationStore

TOKEN = "test-token"
VERIFIED = [Reason(stage="identity", code="identity_verified", detail="ok")]


class _Results:
    def __init__(self, rows):
        self.results = tuple(rows)


class _Row:
    def __init__(self, attack_id, suite, outcome, blocked):
        self.attack_id, self.suite = attack_id, suite
        self.outcome, self.blocked = outcome, blocked


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
def audit(store) -> AuditWriter:
    return AuditWriter(store)


def _act(audit, agent_id="a1", outcome=Outcome.allow, target="http_get"):
    action = AgentAction(
        agent_id=agent_id,
        type=ActionType.tool_call,
        target=target,
        payload={"url": "https://api.example.com/x", "content": ""},
    )
    asyncio.run(
        audit.append(
            action, Decision(action_id=action.id, outcome=outcome, reasons=VERIFIED)
        )
    )
    return action


def _client(store, audit, *, graph=None, health=None, validation=None) -> TestClient:
    inv = InventoryStore(store)
    inv.declare("a1", tools=["http_get"])
    app = create_app(ApprovalStore(store, audit), inventory_store=inv, api_token=TOKEN)
    mount_dashboard(
        app,
        TOKEN,
        approvals=ApprovalStore(store, audit),
        inventory=inv,
        session_factory=store,
        graph=graph,
        health=health,
        validation=validation,
    )
    client = TestClient(app)
    client.post("/dashboard/login", data={"token": TOKEN}, follow_redirects=False)
    return client


@pytest.fixture
def seeded(store, audit):
    """Two allows and a deny for a1, plus one validation run with a slipped attack."""
    _act(audit, "a1")
    _act(audit, "a1")
    _act(audit, "a1", outcome=Outcome.deny)
    v = ValidationStore(store, audit)
    asyncio.run(
        v.record(
            "a1",
            "jailbreak",
            _Results([
                _Row("jb_1", "jailbreak", "deny", True),
                _Row("jb_2", "jailbreak", "allow", False),
            ]),
        )
    )
    return v


# --- the graph page (DASH-04) --------------------------------------------------


def test_the_graph_page_renders_the_live_graph(store, audit) -> None:
    _act(audit, "a1")
    graph = AgentGraphStore(store)
    graph.materialize()

    body = _client(store, audit, graph=graph).get("/dashboard/graph").text

    assert "<svg" in body
    assert "a1" in body


def test_a_hostile_agent_id_never_reaches_the_page_as_markup(store, audit) -> None:
    """Agent ids are attacker-chosen: `agent_id` on an unregistered caller is whatever that caller
    sent, and DISC-06 builds node names from audit evidence.

    The store already strips markup — `graph._agent_names` runs ids through `bounded`, whose
    allowlist charset drops `<` and `>` and appends a digest so two distinct ids cannot collide. So
    this asserts the end-to-end outcome rather than a particular mechanism: nothing an agent chose
    arrives on the operator's console as markup.
    """
    _act(audit, "<script>alert(1)</script>")
    graph = AgentGraphStore(store)
    graph.materialize()

    body = _client(store, audit, graph=graph).get("/dashboard/graph").text

    assert "<script>alert(1)</script>" not in body
    assert "alert(1)" not in body


def test_the_page_escapes_markup_even_if_a_name_ever_carries_it(store, audit) -> None:
    """The page's OWN defense, tested independently of the store's.

    The sanitizer above is upstream and could be relaxed, re-scoped, or bypassed by a future writer
    — component names come from caller-supplied manifests, not only from agent ids. This is the
    screen with the kill switch on it, so it must not inherit its safety from a guarantee made two
    modules away. Renders the template directly with a name no store would currently produce.
    """
    from fastapi.templating import Jinja2Templates
    from pathlib import Path

    import agentos_controlplane.dashboard as dash

    templates = Jinja2Templates(
        directory=str(Path(dash.__file__).parent / "templates")
    )
    hostile = '<script>alert(1)</script>'
    rendered = templates.get_template("graph.html").render(
        view={
            "nodes": [{"kind": "tool", "label": hostile, "x": 1, "y": 2}],
            "edges": [], "total_nodes": 1, "truncated": False, "width": 10, "height": 10,
        }
    )

    assert hostile not in rendered
    assert "&lt;script&gt;" in rendered


def test_the_layout_is_deterministic_across_loads(store, audit) -> None:
    """An operator comparing two refreshes must be able to tell a topology change from a reshuffle.
    A layout that moves on its own makes the page unreadable exactly when something is changing."""
    for name in ("a1", "a2", "a3"):
        _act(audit, name)
    graph = AgentGraphStore(store)
    graph.materialize()
    client = _client(store, audit, graph=graph)

    assert client.get("/dashboard/graph").text == client.get("/dashboard/graph").text


def test_no_edge_is_drawn_to_a_node_this_page_did_not_place(store, audit) -> None:
    """A line to a node that is not on the page is a dangling edge — the same structural error the
    DISC-06 re-review fixed in the API view, which a page-level budget reintroduces.

    Seeds past the page's own 60-node budget on purpose. Below it nothing is ever dropped, so the
    guard is unreachable and the test would pass with it deleted — which is exactly what happened
    on the first version of this test.
    """
    import agentos_controlplane.dashboard as dash

    for i in range(dash._GRAPH_NODES + 20):
        _act(audit, f"agent-{i:03d}")
    graph = AgentGraphStore(store)
    graph.materialize()

    body = _client(store, audit, graph=graph).get("/dashboard/graph").text

    # every rendered <line> carries coordinates that a <circle> also carries
    import re

    circles = set(re.findall(r'<circle cx="([-\d.]+)" cy="([-\d.]+)"', body))
    for x1, y1, x2, y2 in re.findall(
        r'<line x1="([-\d.]+)" y1="([-\d.]+)" x2="([-\d.]+)" y2="([-\d.]+)"', body
    ):
        assert (x1, y1) in circles and (x2, y2) in circles
    # ...and the page SAYS it is showing a subset. A silently capped graph reads as the whole
    # topology, which on this page means an operator concludes a component has no callers.
    assert "truncated" in body.lower()


# --- the health page (OBS-06) --------------------------------------------------


def test_the_health_page_shows_blocked_separately_from_failed(store, audit, seeded) -> None:
    """Slice 12d's central property, asserted where it is easiest to lose. A governance block is the
    system working; folding it into an error count makes the best-governed agent look like the
    sickest, and the fix an operator reaches for is to loosen the guard.
    The fixture is 2 allows and 1 deny: 3 actions, 2 executed, 1 blocked, and nothing measured an
    execution failure. So a page that folded the block into the failure rate renders 33.3% (1 of 3
    actions) — that exact number is asserted absent, because a value the data cannot produce proves
    nothing. The first version of this test asserted "75.0%" and passed against the mutant.
    """
    body = _client(store, audit, health=HealthStore(store)).get("/dashboard/health").text

    assert "blocked" in body.lower() and "governance" in body.lower()
    assert "33.3%" not in body, "a governance block must not be rendered as an execution failure"
    assert "50.0%" not in body, "nor as a share of executed actions"


def test_the_health_page_renders_no_liveness_verdict(store, audit, seeded) -> None:
    """An idle agent and a stopped one are identical in the log. A red dot beside a healthy nightly
    job is the assertion the data layer refused to make."""
    body = _client(store, audit, health=HealthStore(store)).get("/dashboard/health").text

    assert "last seen" in body.lower()
    for verdict in (">healthy<", ">unhealthy<", ">down<", ">dead<", ">offline<"):
        assert verdict not in body.lower()


def test_an_unmeasured_failure_rate_does_not_render_as_zero_percent(store, audit, seeded) -> None:
    """`execution_failures` is None when nothing measured it. Rendering that as 0% would claim
    everything that ran, ran fine — the absent-vs-zero rule reaching the screen."""
    body = _client(store, audit, health=HealthStore(store)).get("/dashboard/health").text

    assert "n/a" in body.lower() or "not measured" in body.lower()


# --- the attacks page (OBS-06) -------------------------------------------------


def test_the_attack_page_shows_the_rate_WITH_its_sample(store, audit, seeded) -> None:
    """Slice 12a's whole design is that a rate never travels without its `n`, and a chart is where
    that discipline dies. 1-of-2 and 250-of-500 are both "50%" and are not the same claim."""
    body = _client(store, audit, validation=seeded).get("/dashboard/attacks").text

    assert "50.0%" in body
    assert "1 slipped / 2 attacks" in body
    assert "runs" in body.lower()


def test_an_empty_history_reads_as_no_data_not_as_a_perfect_score(store, audit) -> None:
    """0% is the claim "every attack was blocked". No runs is not that claim."""
    body = _client(
        store, audit, validation=ValidationStore(store, audit)
    ).get("/dashboard/attacks").text

    assert "no validation runs yet" in body.lower()
    assert "0.0%" not in body


# --- wiring --------------------------------------------------------------------


def test_the_pages_are_gated(store, audit, seeded) -> None:
    """Session-gated like every other dashboard page: who is contained, how well a guard is holding,
    and who talks to whom are each a map of where a fleet is weakest."""
    inv = InventoryStore(store)
    app = create_app(ApprovalStore(store, audit), inventory_store=inv, api_token=TOKEN)
    mount_dashboard(
        app, TOKEN, inventory=inv, session_factory=store,
        graph=AgentGraphStore(store), health=HealthStore(store), validation=seeded,
    )
    anon = TestClient(app)

    for path in ("/dashboard/graph", "/dashboard/health", "/dashboard/attacks"):
        assert anon.get(path, follow_redirects=False).status_code == 303, path


def test_an_unwired_page_404s_and_the_existing_pages_still_work(store, audit, seeded) -> None:
    client = _client(store, audit)

    assert client.get("/dashboard/graph").status_code == 404
    assert client.get("/dashboard/health").status_code == 404
    assert client.get("/dashboard/attacks").status_code == 404
    assert client.get("/dashboard").status_code == 200


def test_the_nav_links_every_new_page(store, audit, seeded) -> None:
    body = _client(store, audit, health=HealthStore(store)).get("/dashboard").text

    for path in ("/dashboard/graph", "/dashboard/health", "/dashboard/attacks"):
        assert path in body


def test_the_console_pulls_no_third_party_script(store, audit, seeded) -> None:
    """The operator console is the screen with the kill switch on it. A script fetched from a CDN
    is an unreviewed third party with script access to it, changeable by someone who is not us and
    re-fetched on every load — in a product that ships supply-chain detectors."""
    body = _client(store, audit, health=HealthStore(store)).get("/dashboard").text

    assert "unpkg.com" not in body
    assert "//cdn" not in body
    assert "<script src=\"http" not in body
