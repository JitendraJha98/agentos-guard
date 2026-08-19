# Phase 13 · Slice 13a — Constitution Amendments & Ratification (POL-10) — Implementation Plan

**Goal (POL-10):** Agents (or a future self-play trainer) **propose** Constitution amendments; a
**human ratifies**; the Constitution is versioned like a legal document — the prior text survives and
each version records the authority that produced it.

**Architecture:** An `Amendment` row with `proposed → ratified | rejected | withdrawn`, mirroring the
Phase-3 approval idiom rather than inventing a second review surface. Ratification is the only
transition that touches the constitution, and it goes through the **existing** `ResourceStore.apply`
path so a ratified amendment is compiled and versioned exactly like any other constitution write.

## What already exists, and therefore what this slice does NOT rebuild

`ConstitutionResource` is already append-only: `version` is unique, `source` holds the authored
document verbatim, and compile-on-write inserts a new row rather than editing one. So "the old text
survives" (spec D-2) is already structurally true, and POL-08 already pins `constitution_version` on
every `Decision`.

What is missing is **provenance** — which amendment produced a version, ratified by whom, when — and
a **history read** that presents it. This slice adds those and the lifecycle in front of them. It
does not build a parallel versioning system; doing so would create a second source of truth about
what the constitution said, and the disagreement would surface during an audit.

## File structure
- Modify `.../store/models.py` — `Amendment`.
- Create `.../store/migrations/versions/0029_amendment.py` (down_revision `0028_redteam_runs`).
- Modify `.../audit.py` — `EVENT_KINDS += "amendment_proposed"`, `"amendment_resolved"`.
- Create `.../agentos_controlplane/amendments.py` — `AmendmentStore`.
- Modify `.../api.py` — gated propose/list/resolve routes.
- Tests: `tests/unit/test_amendments.py`, `tests/integration/test_amendments_api.py`,
  plus a case in `tests/integration/test_migrations.py`.

---

### Task 1: `Amendment` table + migration 0029 + event kinds

```python
class Amendment(Base):
    """POL-10 — a proposed change to the Constitution, and its human ratification.

    An amendment is a proposal ABOUT THE RULES, so it may never bypass them: `proposed_by` may be an
    agent, `ratified_by` may only be a human operator, and a row in `proposed` has no effect on any
    decision. That is the POL-13 shape — the interpreter may recommend a temporary exception but
    never grant one — applied to the document itself.

    `source` is the FULL proposed constitution, not a diff. A diff would have to be applied to
    whatever the constitution said at ratification time, which may not be what it said at proposal
    time; storing the whole document means what a human ratifies is exactly what takes effect.
    """

    __tablename__ = "amendment"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    proposed_by: Mapped[str] = mapped_column(String(255), nullable=False)   # agent id or operator
    source: Mapped[dict] = mapped_column(JSON, nullable=False)              # the whole proposed doc
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    ratified_by: Mapped[str | None] = mapped_column(String(128), nullable=True)  # human only
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The constitution version this amendment PRODUCED. Null until ratified — and this column is the
    # provenance the requirement's "versioned like a legal document" asks for: a version with no
    # amendment behind it was an operator's direct write, which is a different act.
    constitution_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    proposed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
```

Event kinds, in `audit.py`'s comment style:
```python
        # POL-10 (Slice 13a): the Constitution's own change log. Short identifiers only — the
        # proposed text lives in the amendment row, not in the chain.
        "amendment_proposed",
        "amendment_resolved",
```

Migration `0029_amendment.py`, plus a case in `tests/integration/test_migrations.py` asserting
upgrade/downgrade/re-upgrade and a single head `0029_amendment`.

- [ ] Failing test: round-trip an `Amendment`, assert `status == "proposed"` and both nullable
  resolution columns are None; assert both event kinds are accepted and an unknown kind raises.
- [ ] Implement. Run → passes, single head.
- [ ] Commit `feat(controlplane): amendment table + event kinds + migration 0029 (POL-10)`.

---

### Task 2: `AmendmentStore` — propose, ratify, reject

```python
"""POL-10 — the Constitution as an amendable governing document.

A CONSTITUTION THAT CANNOT BE AMENDED IS EDITED INSTEAD. Operators change the rules either way; the
question is whether the change leaves a record of who asked, who agreed, and what it replaced. This
module makes the change a first-class, audited act rather than a resource write nobody can
reconstruct later.

WHO MAY DO WHAT. An agent may PROPOSE — that is the point of POL-10's "agents or the self-play
trainer". Only a human may RATIFY. This is the POL-13 rule applied to the document itself: the
interpreter may recommend a temporary exception and never grant one, and by the same reasoning a
system that could ratify its own amendments could rewrite the rules it is governed by.

A PROPOSAL IS INERT. Nothing reads `amendment` on the decision path. A pending proposal changes no
outcome, and the test suite asserts that by evaluating an action against one — because the whole
value of a ratification step is that the un-ratified state means nothing.
"""
```

`AmendmentStore(session_factory, audit, resources=None)`:

- **`propose(title, rationale, proposed_by, source) -> UUID`** — validates the proposed document
  compiles *before* storing it. An amendment that cannot compile is not a proposal a human should be
  asked to review; refusing at proposal time puts the error in front of the proposer, who can fix it,
  rather than in front of the ratifier, who cannot. Audited as `amendment_proposed` with the title
  and proposer, never the document.
- **`ratify(amendment_id, ratified_by, note=None) -> str`** — the ONLY transition that touches the
  constitution. Applies `source` through the existing `ResourceStore.apply` (so compile-on-write,
  versioning and the policy row all behave identically to any other write), records the resulting
  `constitution_version` on the amendment, and audits `amendment_resolved`. Returns the new version.
- **`reject(amendment_id, resolved_by, note=None)`** / **`withdraw(amendment_id, by)`** — terminal,
  audited, and non-constitutional.
- **`list_amendments(status=None, limit=200)`**, **`get(amendment_id)`**.

Transitions are guarded: a resolved amendment cannot be re-resolved (raises `AlreadyResolvedError`,
reusing the approvals exception rather than adding a second one), and `ratified_by` is required and
non-empty — an amendment with no ratifier named is not human-ratified, whatever the status column
says.

- [ ] Failing tests:

```python
def test_a_pending_amendment_changes_no_decision(store, audit, wired_pipeline) -> None:
    """THE property of this slice. A proposal that took effect before ratification would make the
    review step decorative, and an agent could rewrite the rules it is governed by simply by asking."""
    before = asyncio.run(wired_pipeline.evaluate(_action()))
    AmendmentStore(store, audit, resources).propose(
        "allow everything", "because", "agent-1", _permissive_constitution()
    )
    after = asyncio.run(wired_pipeline.evaluate(_action()))

    assert after.outcome is before.outcome
    assert after.constitution_version == before.constitution_version


def test_ratifying_produces_a_new_constitution_version(store, audit, resources) -> None:
    ...  # returns a version, records it on the amendment, status becomes "ratified"


def test_the_previous_constitution_text_survives_ratification(store, audit, resources) -> None:
    """"Versioned like a legal document" is mostly about what does NOT happen: the old text stays
    readable. POL-08 pins constitution_version on every Decision, so an audited decision is only
    explicable while the text that evaluated it still exists."""


def test_an_amendment_that_does_not_compile_is_refused_at_PROPOSAL(store, audit, resources) -> None:
    """The error belongs in front of the proposer, who can fix it — not the ratifier, who cannot."""
    with pytest.raises(ConstitutionError):
        AmendmentStore(store, audit, resources).propose("bad", "r", "agent-1", {"nonsense": True})


def test_ratification_requires_a_named_human(store, audit, resources) -> None:
    """An amendment with no ratifier named is not human-ratified, whatever the status column says."""
    with pytest.raises(ValueError):
        store_.ratify(aid, ratified_by="")


def test_a_resolved_amendment_cannot_be_resolved_again(store, audit, resources) -> None:
    ...  # second ratify/reject raises AlreadyResolvedError


def test_the_audit_body_carries_no_proposed_document(store, audit, resources) -> None:
    """Short identifiers only. The proposed text can be arbitrarily large and is already stored in
    its own row; putting it in the hash chain would bloat every verification pass."""


def test_a_rejected_amendment_touches_no_constitution_version(store, audit, resources) -> None:
```

- [ ] Implement. Run → passes.
- [ ] Commit `feat(controlplane): amendment lifecycle — agents propose, humans ratify (POL-10)`.

---

### Task 3: gated API + history read + full gate

Append `amendments: "AmendmentStore | None" = None` LAST to `build_inventory_router` and
`create_app`, matching every collaborator since DISC-03.

```python
    @router.get("/amendments")
    def list_amendments(status: str | None = None) -> list[dict]: ...

    @router.post("/amendments")
    def propose_amendment(body: ProposeAmendmentIn) -> dict:
        """POL-10 — propose a change to the Constitution. Gated but AGENT-usable: proposing is the
        half of POL-10 an agent is meant to do. Ratifying is not."""

    @router.post("/amendments/{amendment_id}/ratify")
    async def ratify_amendment(amendment_id: UUID, body: RatifyIn) -> dict:
        """POL-10 — the human half. `ratified_by` is required, and this is the only route in the
        product that changes what the Constitution says."""

    @router.get("/constitution/history")
    def constitution_history() -> list[dict]:
        """POL-10 — what the Constitution has said, when, and on whose authority.

        A version with no amendment behind it was an operator's direct write, which is a different
        act from a ratified amendment and is shown as such rather than blank."""
```

`ProposeAmendmentIn`/`RatifyIn` are `extra="forbid"` Pydantic models with bounded `title` (255),
`rationale` (4096) and `ratified_by` (128) — the same boundedness every operator-input model in
`api.py` already has.

- [ ] Failing tests: propose → 200 with an id; list shows it as `proposed`; ratify → 200 with the new
  version; history shows the version with its amendment id and ratifier; a version written directly
  shows `amendment: null`; 401 without a token; 404 when unwired while `/inventory` still 200; an
  over-long title → 422.
- [ ] Implement. Run → passes.
- [ ] **Full gate on the WHOLE suite** + `-m floor_invariant`, `-m regression_lock`, `-m latency`,
  coverage, alembic single head.
- [ ] Commit `feat(controlplane): gated amendment + constitution-history API (POL-10)`.

## Self-review

POL-10 names three things and each is real: agents propose (an agent id is a valid `proposed_by`, and
the propose route is agent-usable), humans ratify (`ratified_by` required and non-empty, enforced at
the store rather than only at the route), and the Constitution is versioned like a legal document —
which this slice achieves mostly by *not* rebuilding versioning that already exists, and instead
adding the provenance and history that make an existing version chain readable as a record of
authority.

The property that makes the ratification step meaningful is asserted directly: a pending amendment
changes no decision. Without that test the review step is decorative, and an agent could rewrite the
rules governing it by proposing them.

Compilation is checked at proposal, so a broken amendment fails in front of the person who can fix
it. The audit chain carries identifiers only — the proposed document already has a row, and putting
it in the chain would bloat every verification pass for no gain.
