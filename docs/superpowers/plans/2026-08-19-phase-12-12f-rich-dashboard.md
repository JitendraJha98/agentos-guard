# Phase 12 · Slice 12f — Rich Operator Dashboard (OBS-06, DASH-04) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with `-m "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"`. TDD per task, one
> commit each. Gates green at every commit. Run the WHOLE suite before committing.
> **This slice depends on 12a (attack trend), 12d (health) and Phase 10's `AgentGraphStore`.**

**Goal (OBS-06, DASH-04):** Add to the existing dashboard: the **live agent graph**, **per-agent
SLOs/violations**, and **attack visualization**.

**Why one slice for two requirements.** OBS-06 ("per-agent SLO and violation dashboards with attack
visualization") and DASH-04 ("the dashboard adds the live agent graph, per-agent SLOs/violations, and
attack visualization") describe the same screen from two requirement families. Splitting them would
produce two half-dashboards that each satisfy half of both.

**Architecture:** Three new server-rendered Jinja pages on the existing cookie-gated dashboard router,
reading from collaborators that already exist. Inline SVG for the graph. **No frontend framework, no
CDN, no client-side charting library** (spec D-9).

**Tech Stack:** Jinja2 + inline SVG. No new dependency, no migration.

## Why no CDN, concretely

This is the operator console: the screen with the kill switch on it. A `<script src="https://…">` there
is an unreviewed third party with script access to the most privileged page in the product, fetched
fresh on every load, changeable by someone who is not us. This project ships supply-chain detectors
(SEC-07/08) and an ABOM; pulling a runtime dependency off a CDN onto the governance console is the
thing those exist to catch.

### A pre-existing finding to raise, not to fix silently

`templates/base.html:5` already loads htmx from `unpkg.com` — and **no template uses it**: there is
not one `hx-` attribute anywhere in `templates/`. It is a dead CDN dependency on the privileged
screen.

Per the repo's rules, pre-existing issues get **mentioned, not deleted as a drive-by**. But this slice
edits `base.html` (the nav gains three links), so the line is directly in scope, and it is dead. The
implementer should:

1. Verify the claim independently (`grep -rn "hx-" packages/controlplane/src/agentos_controlplane/templates/`).
2. If it is genuinely unused, **remove the line in its own commit**, with a message stating that it
   was unused and why a CDN script on the governance console is worth removing rather than keeping.
   A separate commit makes it trivially revertible if an operator disagrees.
3. If any template does use it, **do not** remove it — vendor it locally under a `static/` directory
   served by the app instead, and say so.

## File structure
- Modify `.../dashboard.py` — three routes.
- Modify `templates/base.html` — nav links (+ the htmx decision above).
- Create `templates/graph.html`, `templates/health.html`, `templates/attacks.html`.
- Modify `.../api.py` / `mount_dashboard` — thread the three collaborators through.
- Tests: `tests/integration/test_dashboard_rich.py`.

---

### Task 1: the live agent graph page (DASH-04)

**Files:** modify `.../dashboard.py`; create `templates/graph.html`; test.

Route `GET /dashboard/graph` renders `AgentGraphStore.view()` as **inline SVG**: nodes laid out
deterministically (sort by `(kind, name)`, place on a circle or a grid computed in Python), edges as
lines. Deterministic layout matters — a graph that reshuffles on every refresh is unreadable, and an
operator comparing two loads cannot tell a layout change from a topology change.

The view is already **bounded and closed** (Phase 10's re-review fix: every edge's endpoints are
present). Render `truncated`/counts if the view reports them — the no-silent-caps rule applies to a
screen exactly as it applies to an API.

**Escape everything.** Node names come from agent-controlled identifiers. Jinja autoescaping covers
HTML, but SVG text and attribute contexts are where an unescaped `<` or `"` becomes markup. Test with
a node named `<script>alert(1)</script>` and assert it renders as text.

- [ ] **Step 1: Failing tests**

```python
def test_the_graph_page_renders_the_live_graph(client) -> None:
    ...  # 200, contains an <svg, one element per node

def test_a_hostile_node_name_is_escaped_not_executed(client, graph_with_hostile_name) -> None:
    """Node names are agent-controlled (DISC-06 builds them from audit evidence). SVG text and
    attribute contexts are where an unescaped character becomes markup on the screen that has the
    kill switch on it."""
    body = client.get("/dashboard/graph").text

    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body

def test_the_layout_is_deterministic_across_loads(client) -> None:
    """An operator comparing two refreshes must be able to tell a topology change from a reshuffle."""
    assert client.get("/dashboard/graph").text == client.get("/dashboard/graph").text

def test_the_graph_page_is_gated(client_no_session) -> None:
    ...  # redirect to login, not a 200
```

- [ ] **Steps 2–5:** implement, verify, commit
  `feat(controlplane): live agent-graph dashboard page, server-rendered SVG (DASH-04)`.

---

### Task 2: per-agent SLO / violation page (OBS-06)

Route `GET /dashboard/health` renders 12d's `HealthStore.fleet()`.

**Carry 12d's honesty onto the screen, where it is easiest to lose.** `last_seen_at` renders as a
timestamp with no colour-coded verdict — a red dot next to an idle nightly agent is the assertion 12d
refused to make in its data. The failure rate renders **with its denominator** (`3 / 240 executed`),
and blocked actions render in their own column labelled as governance, never folded into an error
count. A test asserts the rendered page shows the denominator, because a template is exactly where a
carefully-qualified number gets reduced to a percentage.

- [ ] **Failing tests:** the page shows an agent, its `last_seen_at`, the rate **with** counts, and
  blocked-vs-failed in separate columns; a null rate renders as something other than `0%`; gated.
- [ ] Commit `feat(controlplane): per-agent SLO and violation dashboard page (OBS-06)`.

---

### Task 3: attack visualization + nav + full gate

Route `GET /dashboard/attacks` renders 12a's `ValidationStore.trend()`.

**The sample size renders too.** 12a's whole design is that a rate never travels without its `n`; a
chart is where that discipline dies. Each row/bar shows `runs` and `total` beside the rate, and a
test asserts it. A sparkline is inline SVG or a plain table — either is fine, a CDN charting library
is not (D-9).

Add the three nav links to `base.html`, and make the htmx decision from the header above.

- [ ] **Failing tests:** the page shows the trend with `n`; suites are not averaged together; an
  empty history renders as "no validation runs yet" rather than `0%` (that is 12a's absent-vs-zero
  rule reaching the screen); gated; and `base.html` links all three pages.
- [ ] **Then the FULL gate** on the WHOLE suite + `-m floor_invariant`, `-m regression_lock`,
  `-m latency`, coverage, alembic single head.
- [ ] Commit `feat(controlplane): attack-trend dashboard page + nav (OBS-06, DASH-04)`.

## Self-review

DASH-04's three additions are each a page backed by a real collaborator: the live graph from Phase
10's bounded, closed `view()`, per-agent SLOs from 12d, and attack trends from 12a. OBS-06 is the same
screen from the observability side, which is why one slice serves both.

The failure mode specific to this slice is that a template quietly undoes an invariant the data layer
worked to establish. Two tests exist purely for that: the rendered health page must show the
denominator beside the failure rate, and the rendered attack page must show `n` beside the rate — the
disciplines 12d and 12a enforce in their return shapes, asserted again where they are easiest to drop.
Absence stays absence on screen too: an empty trend reads "no validation runs yet", not `0%`.

Node names are agent-controlled, so the graph page is tested against a hostile name in SVG context —
the operator console is the page with the kill switch on it, and it is the last place an injected
script should land. Nothing here is client-side: no framework, no CDN, and a dead unpkg script tag
that predates this slice is raised for removal in its own revertible commit rather than deleted
quietly or left because it was already there.
