# Phase 11 · Slice 11f — One-Click Evidence Export (CMP-06) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. Nothing here touches the per-action path.

**Goal (CMP-06):** One call produces an evidence bundle **per framework and time range** — and the
recipient can verify it while holding neither our database nor our trust.

**Architecture:** This is where 11a and 11e meet. The bundle carries the framework's mapping
(11e), the derived evidence for the range (11e), the in-range audit records, **and their Merkle
inclusion proofs plus the anchored root** (11a). That last clause is the point of the whole phase:
partial disclosure means the auditor gets the records they are entitled to, verifies each one against
an externally anchored root, and learns nothing about the records they were not given. A bundle
manifest digest lets them detect a bundle edited after export.

**Tech Stack:** the existing `compliance.py` + `merkle.py`, FastAPI, stdlib `json`/`hashlib`, pytest.

> First commit in this slice: `docs(phase-11): Slice 11f plan` for this file, then the tasks below.

## File structure
- Modify `.../agentos_controlplane/compliance.py` — `export_evidence_bundle()` + `bundle_digest()`
  + the CLI subcommand.
- Modify `.../api.py` — the gated export route.
- Tests: `tests/unit/test_evidence_bundle.py`, `tests/integration/test_evidence_export_api.py`.

---

### Task 1: `export_evidence_bundle(framework, start, end)`

**Files:** modify `.../compliance.py`; test `tests/unit/test_evidence_bundle.py`.

```python
FRAMEWORKS = ("owasp_agentic_2026", "nist_ai_rmf", "eu_ai_act", "soc2")

# A bundle is handed to an outside party, so its size must be bounded by something other than how
# busy the fleet was. An unbounded export of a year of audit records is a memory event on our side
# and an unusable artifact on theirs; truncation is reported in the manifest so a recipient always
# knows they are holding a subset.
_MAX_RECORDS = 5000


def export_evidence_bundle(
    framework: str,
    session_factory,
    *,
    start=None,
    end=None,
    sealer=None,
    public_key_pem=None,
) -> dict:
    """CMP-06 — a per-framework, per-time-range evidence bundle, verifiable standalone.

    WHY THE PROOFS TRAVEL WITH IT. Without them a bundle is an extract: a list of records the
    recipient must take on our word, indistinguishable from one we edited. With an inclusion proof
    per record and an externally anchored root, the recipient recomputes each record's path and
    verifies it themselves. That is the difference between disclosure and assertion, and it is what
    makes 'evidence' the right word for this artifact.

    WHY IT IS PARTIAL BY CONSTRUCTION. Only the in-range records travel. The rest of the log is
    represented by sibling HASHES inside the proofs, which reveal nothing about their contents —
    so an auditor entitled to Q3 does not receive Q2 as the price of verifying Q3.
    """
```

The returned shape:

```python
    {
      "framework": framework,
      "range": {"start": ..., "end": ...},          # ISO-8601 or null for unbounded
      "mapping": {...},                              # the framework's slice of the 11e mapping
      "derived_evidence": {...},                     # SOC 2 counts / EU article evidence for the range
      "records": [                                   # in-range audit records, already AUD-04 redacted
        {"seq": .., "record_hash": .., "body": {...}, "signature": .., "signing_key_id": ..,
         "inclusion": {"index": .., "proof": [...], "root": .., "epoch": .., "anchored": bool} | None},
      ],
      "verification": {
        "chain_verifies": bool,                      # AUD-05 over the whole chain
        "records_in_range": int,
        "records_included": int,                     # how many carried a proof
        "records_unsealed": int,                     # in-range but not yet in a sealed epoch
        "truncated": bool,
        "how_to_verify": "…",                        # the exact steps, in the bundle itself
      },
      "manifest_digest": "…",                        # sha256 over the canonical bundle, minus this key
      "disclaimer": "…",                             # the 11e non-conformity statement, carried through
    }
```

**Unsealed records are reported, never hidden.** A record appended after the last seal has no proof
yet. Dropping it would silently shrink the evidence; including it with `inclusion: null` and a
`records_unsealed` count tells the recipient exactly what they can and cannot verify. That honesty is
cheap here and expensive to retrofit after someone has relied on the bundle.

```python
def bundle_digest(bundle: dict) -> str:
    """sha256 over the canonical JSON of the bundle with `manifest_digest` removed.

    Detects a bundle edited after export. It does NOT authenticate the exporter — anyone can
    recompute a digest over altered content. Authentication comes from the per-record signatures and
    the anchored root, which is why both travel inside.
    """
```

- [ ] **Step 1: Write the failing tests**

```python
def test_every_included_record_verifies_against_the_root_in_the_bundle(bundle) -> None:
    """The claim CMP-06 makes: verifiable STANDALONE. Nothing in this test touches the database."""
    from agentos_controlplane.merkle import verify_inclusion

    included = [r for r in bundle["records"] if r["inclusion"]]
    assert included, "the fixture must seal at least one epoch or this test proves nothing"
    for r in included:
        inc = r["inclusion"]
        assert verify_inclusion(r["record_hash"], inc["index"], inc["proof"], inc["root"])


def test_the_bundle_contains_only_the_requested_range(store, sealer) -> None:
    """A range that silently leaks neighbouring records is both a privacy failure and a correctness
    one: the auditor receives records they were not entitled to, and the operator cannot say what
    they disclosed."""
    early, late = _two_windows(store)
    bundle = export_evidence_bundle("soc2", store, start=late.start, sealer=sealer)
    seqs = {r["seq"] for r in bundle["records"]}
    assert seqs and seqs.isdisjoint(early.seqs)


def test_unsealed_records_are_reported_not_dropped(store, sealer) -> None:
    """Silently omitting them would shrink the evidence without saying so."""
    _append_after_seal(store)
    bundle = export_evidence_bundle("soc2", store, sealer=sealer)
    assert bundle["verification"]["records_unsealed"] >= 1
    assert any(r["inclusion"] is None for r in bundle["records"])


def test_the_manifest_digest_detects_an_edited_bundle(bundle) -> None:
    from agentos_controlplane.compliance import bundle_digest

    assert bundle_digest(bundle) == bundle["manifest_digest"]
    tampered = dict(bundle)
    tampered["records"] = bundle["records"][:-1]
    assert bundle_digest(tampered) != bundle["manifest_digest"]


def test_a_tampered_record_fails_its_own_proof(bundle) -> None:
    """The property that makes the bundle evidence rather than an extract."""
    from agentos_controlplane.merkle import verify_inclusion

    r = next(r for r in bundle["records"] if r["inclusion"])
    inc = r["inclusion"]
    assert not verify_inclusion("ff" * 32, inc["index"], inc["proof"], inc["root"])


def test_each_framework_exports_only_its_own_mapping(store, sealer) -> None:
    for fw in FRAMEWORKS:
        b = export_evidence_bundle(fw, store, sealer=sealer)
        assert b["framework"] == fw and b["mapping"], fw
    with pytest.raises(ValueError):
        export_evidence_bundle("not-a-framework", store)


def test_a_large_range_is_bounded_and_says_so(store, sealer) -> None:
    """An unbounded export is a memory event on our side and an unusable artifact on theirs. The
    recipient must be told they hold a subset."""
    _append_many(store, _MAX_RECORDS + 10)
    b = export_evidence_bundle("soc2", store, sealer=sealer)
    assert b["verification"]["truncated"] is True
    assert len(b["records"]) <= _MAX_RECORDS


def test_the_bundle_carries_the_non_conformity_disclaimer(bundle) -> None:
    """It travels OUTSIDE our hands. The disclaimer must ride with it, not live in our docs."""
    assert "not a conformity assessment" in json.dumps(bundle).lower()
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes.**
- [ ] **Step 5: Commit** `feat(controlplane): per-framework, per-range evidence bundle with inclusion proofs (CMP-06)`.

---

### Task 2: the "one click" — CLI + gated API route + full gate

**Files:** modify `.../compliance.py` (`_main`), `.../api.py`; test
`tests/integration/test_evidence_export_api.py`.

CLI — extend the existing `python -m agentos_controlplane.compliance` entry point rather than adding
a second script:

```
--framework {owasp_agentic_2026,nist_ai_rmf,eu_ai_act,soc2}   export a per-framework bundle
--start / --end ISO-8601                                       the time range
--out PATH                                                     write the bundle (default: stdout)
```

API — on the gated router:

```python
    @router.get("/compliance/export/{framework}")
    def export_bundle(framework: str, start: str | None = None, end: str | None = None) -> dict:
        """CMP-06 — one-click evidence bundle. Gated: an evidence bundle is a curated disclosure of
        who did what, and deciding who receives it is the operator's call, not a URL's."""
        if session_factory is None:
            raise HTTPException(status_code=404, detail="evidence export is not wired")
        try:
            return export_evidence_bundle(
                framework, session_factory, start=_parse_dt(start), end=_parse_dt(end), sealer=sealer
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
```

`_parse_dt` accepts ISO-8601 or None and raises `ValueError` on anything else — a malformed range
must be a 422, never a silently-unbounded export. **This is worth a test of its own:** an operator
who typos a date and receives the entire log instead of a quarter has over-disclosed, and the
mistake is invisible to them.

- [ ] **Step 1: Write the failing tests**

```python
def test_the_export_route_returns_a_verifiable_bundle(client) -> None:
    from agentos_controlplane.merkle import verify_inclusion

    b = client.get("/compliance/export/soc2").json()
    r = next(r for r in b["records"] if r["inclusion"])
    assert verify_inclusion(r["record_hash"], r["inclusion"]["index"], r["inclusion"]["proof"], r["inclusion"]["root"])


def test_the_export_route_is_gated(client_no_token) -> None:
    assert client_no_token.get("/compliance/export/soc2").status_code == 401


def test_an_unknown_framework_is_422_not_an_empty_bundle(client) -> None:
    """An empty bundle for a typo'd framework reads as 'no evidence exists' — the wrong conclusion
    from a wrong URL."""
    assert client.get("/compliance/export/nope").status_code == 422


def test_a_malformed_date_is_refused_rather_than_ignored(client) -> None:
    """Ignoring an unparseable start date silently exports the ENTIRE log. The operator asked for a
    quarter, over-disclosed a year, and has no way to notice."""
    assert client.get("/compliance/export/soc2?start=last-tuesday").status_code == 422


def test_the_cli_writes_a_bundle_that_verifies(tmp_path, seeded_db) -> None:
    from agentos_controlplane.compliance import _main

    out = tmp_path / "bundle.json"
    assert _main(["--db", str(seeded_db), "--framework", "soc2", "--out", str(out)]) == 0
    b = json.loads(out.read_text(encoding="utf-8"))
    assert b["framework"] == "soc2" and b["manifest_digest"]
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.**
- [ ] **Step 4: Run → passes**, then the FULL gate: `pytest -q`, `-m floor_invariant`,
  `-m regression_lock`, `-m latency`, the coverage check, the alembic single-head check.
- [ ] **Step 5: Commit** `feat(controlplane): one-click compliance export — CLI + gated API (CMP-06)`.

## Self-review

CMP-06 asks for one-click export **per framework and time range**, and both dimensions are real: four
frameworks each export their own mapping, an unknown one is a 422 rather than an empty bundle that
would read as "no evidence exists", and the range genuinely filters — with a test proving a bundle
for one window is disjoint from another, because a range that silently leaks neighbouring records is
simultaneously a privacy failure and a correctness one.

The bundle is verifiable **standalone**: the inclusion-proof test touches no database, and a tampered
record fails its own proof. That is what makes the artifact evidence rather than an extract, and it
is the payoff for the Merkle work in 11a.

Three honesty properties are enforced by test rather than intention: unsealed records are reported
with `inclusion: null` and a count instead of being silently dropped; a large range is truncated with
`truncated: true` so a recipient always knows they hold a subset; and a malformed date is a 422,
because the alternative — an ignored bound and a full-log export — is an over-disclosure the operator
cannot see. The 11e non-conformity disclaimer travels inside the bundle, since the bundle is the part
that leaves our hands.

The manifest digest's limit is stated where it lives: it detects post-export edits, it does not
authenticate the exporter. Authentication comes from the per-record signatures and the anchored root,
which is why both travel in the bundle.
