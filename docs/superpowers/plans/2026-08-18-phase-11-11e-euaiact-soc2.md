# Phase 11 · Slice 11e — EU AI Act Mapping & SOC 2 Evidence (CMP-04, CMP-05) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> + `regression_lock` green at every commit. Nothing in this slice touches the per-action path.

**Goal (CMP-04, CMP-05):** Produce a **full EU AI Act mapping** (risk classification, logging, human
oversight) and **SOC 2 control evidence** (access, change, monitoring) derived from the audit log.

**Architecture:** Extends `compliance.py` — no new module. The mapping is deliberately one place: a
second mapping file is a second thing to forget to update, and a stale compliance claim is worse than
no claim. Phase 6 shipped a minimal Art. 12 / Art. 26 pointer; this slice widens it to the article
set a high-risk deployment actually faces, adds the operator-declared risk classification, and adds a
SOC 2 layer that **derives** evidence by counting real audit events in a time range rather than
asserting controls exist.

## The rule that governs every string in this slice (spec D-8)

**We emit evidence, never a conformity claim.** "Here are the controls bearing on Art. 14 and the
records behind them" — never "this system is Art. 14 compliant." Conformity is a determination made
by a notified body, an auditor, or the deployer's own counsel; a tool that pre-empts it is
manufacturing false assurance about legal exposure.

**Risk classification is operator-declared, never inferred.** Whether a deployment is high-risk under
Art. 6 / Annex III depends on its *use case* — the same agent is high-risk in a hiring pipeline and
minimal-risk summarizing meeting notes. Guessing it and being wrong causes real harm in both
directions: a false "high-risk" burdens a customer with obligations they do not have, and a false
"minimal" tells them to skip obligations they do. So the classification is a declared field we echo
back, with its source labelled.

## Verify before you write (do not trust this plan's citations)

The article and criterion numbers below are the implementer's starting point, **not** an authority.
Confirm each against a primary source before it ships in a compliance artifact; drop anything you
cannot confirm rather than approximating it. A wrong article number in a bundle handed to a regulator
is precisely the failure mode this whole slice exists to avoid.

- EU AI Act = Regulation (EU) 2024/1689. Articles referenced: 5 (prohibited practices), 6 + Annex III
  (high-risk classification), 9 (risk management), 10 (data governance), 11 + Annex IV (technical
  documentation), 12 (record-keeping), 13 (transparency to deployers), 14 (human oversight), 15
  (accuracy, robustness, cybersecurity), 26 (deployer obligations), 72 (post-market monitoring), 73
  (serious incident reporting).
- SOC 2 = AICPA Trust Services Criteria. Points referenced: CC6.1/6.2/6.3 (logical access),
  CC7.2/7.3/7.4 (monitoring, event evaluation, incident response), CC8.1 (change management).

> First commit in this slice: `docs(phase-11): Slice 11e plan` for this file, then the tasks below.

## File structure
- Modify `.../agentos_controlplane/compliance.py` — widened `EU_AI_ACT`, `SOC2_CRITERIA`, the
  per-mapping article/criterion fields, `derive_soc2_evidence()`, `risk_classification` plumbing.
- Modify `.../store/models.py` + migration `0027_agent_risk_classification.py` — the declared field.
- Tests: `tests/unit/test_compliance_mapping.py` (extend the existing coverage test),
  `tests/unit/test_soc2_evidence.py`.

---

### Task 1: the operator-declared risk classification

**Files:** modify `.../store/models.py`; create `0027_agent_risk_classification.py`
(down_revision `0026_cost_provider_gpu`); test `tests/unit/test_compliance_mapping.py`.

Add to the existing `Agent` model:

```python
    # CMP-04 — the EU AI Act risk class the OPERATOR declares for this agent's use case.
    # Never inferred. The same agent is high-risk in a hiring pipeline and minimal-risk summarizing
    # meeting notes; the difference lives in the deployment, not in anything we can observe. A wrong
    # guess harms in both directions — burdening a deployer with obligations they do not have, or
    # telling them to skip ones they do. NULL means UNDECLARED, which the export reports as
    # undeclared rather than defaulting to a class.
    risk_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
```

Accepted values (validated at the API/setter, not by a DB constraint — same discipline as
`ApprovalRequest.status`): `prohibited`, `high_risk`, `limited_risk`, `minimal_risk`.

- [ ] **Step 1: Failing test**

```python
def test_an_undeclared_agent_is_reported_as_undeclared_not_defaulted(store) -> None:
    """Defaulting a legal classification is the single most harmful thing this module could do.
    'We do not know' must survive all the way to the export."""
    _register(store, "a1")
    bundle = export_compliance_evidence(store)
    assert bundle["eu_ai_act"]["risk_classifications"]["a1"] == "undeclared"


def test_a_declared_classification_is_echoed_with_its_source(store) -> None:
    _register(store, "a2", risk_classification="high_risk")
    entry = export_compliance_evidence(store)["eu_ai_act"]["risk_classifications"]["a2"]
    assert entry == "high_risk"
```

- [ ] **Step 2: Run → fails.** **Step 3: Add the column + migration + export plumbing.**
- [ ] **Step 4: Run → passes;** alembic single head `['0027_agent_risk_classification']`.
- [ ] **Step 5: Commit** `feat(controlplane): operator-declared EU AI Act risk classification (CMP-04)`.

---

### Task 2: the widened EU AI Act mapping (CMP-04)

**Files:** modify `.../compliance.py`; test `tests/unit/test_compliance_mapping.py`.

Replace the two-entry `EU_AI_ACT` dict with the full set, each entry naming what the article is about
in the Act's own terms. Then extend every `ControlMapping.eu_ai_act` tuple so each shipped control
points at the articles it actually bears on. Examples of the intended attribution (the implementer
completes the set for all controls, and the coverage test enforces completeness):

| Article | What we can evidence | Controls |
|---|---|---|
| Art. 9 risk management | graduated response + risk scoring + red-team gate | graduated outcomes, detectors, TEST-* gates |
| Art. 10 data governance | PII/secret guardrails + fail-closed redaction | `PiiScorer`, `SecretLeakScorer`, AUD-04 |
| Art. 11 technical documentation | ABOM + constitution + policy versions | ABOM-01/02, POL-08 version pinning |
| Art. 12 record-keeping | hash chain + signatures + Merkle inclusion proofs | AUD-01/03/04/08, **AUD-06 (new)** |
| Art. 13 transparency | explainable reasons + remediation on every decision | `Decision.reasons`, POL remediation |
| Art. 14 human oversight | approval, review, exception, kill switch | POL-07/13/14, RUN-01/02 |
| Art. 15 robustness/cybersecurity | the detector surface + circuit breakers + containment | SEC-*, RUN-03..07 |
| Art. 26 deployer obligations | oversight assignment + log retention + monitoring | approvals, audit retention, reconcilers |
| Art. 72 post-market monitoring | shadow/rogue detection + continuous verification | DISC-04/05, AUD-05 verifier |

**Article 5 is a deliberate non-claim.** Prohibited practices are about *what the system is used
for*, not about controls; the mapping must say we evidence nothing toward it rather than inventing a
control. Write that as an explicit entry with an empty control list and a note, because a silently
missing article reads as an oversight, while an explicit empty one is a statement.

Add a bundle section:

```python
        "eu_ai_act": {
            "articles": by_eu,                       # article -> {name, controls}
            "risk_classifications": classifications, # agent -> declared class | "undeclared"
            "disclaimer": (
                "Evidence toward the obligations these articles create. This is NOT a conformity "
                "assessment and NOT a claim of compliance: classification under Art. 6/Annex III "
                "and conformity under Art. 43 are determinations for the deployer, their counsel, "
                "or a notified body."
            ),
        },
```

- [ ] **Step 1: Write the failing tests**

```python
def test_every_shipped_control_maps_to_at_least_one_framework() -> None:
    """The existing coverage lock, still holding after the widening — a live control mapped to
    nothing is a control an auditor will ask about and we cannot evidence."""
    for m in CONTROL_MAPPINGS:
        assert m.owasp or m.nist_rmf or m.eu_ai_act, m.control


def test_every_live_detector_control_is_mapped() -> None:
    mapped = {m.control for m in CONTROL_MAPPINGS}
    assert LIVE_DETECTOR_CONTROLS <= mapped


def test_each_article_we_list_has_evidence_or_says_it_has_none() -> None:
    """A silently empty article reads as an oversight; an explicitly empty one is a statement. Art.
    5 (prohibited practices) is about USE, not controls, and must say so rather than borrow a
    control that does not bear on it."""
    bundle = export_compliance_evidence()
    arts = bundle["eu_ai_act"]["articles"]
    assert arts["Art.5"]["controls"] == []
    assert "prohibited" in arts["Art.5"]["name"].lower()
    for art, entry in arts.items():
        if art != "Art.5":
            assert entry["controls"], f"{art} claims coverage with no control behind it"


def test_the_bundle_never_claims_conformity() -> None:
    """D-8, asserted mechanically. The single largest reputational risk in this phase is emitting
    something a customer forwards to a regulator as a certificate."""
    import json

    blob = json.dumps(export_compliance_evidence()).lower()
    for forbidden in ("is compliant", "certified", "conformity assessment passed", "guarantees compliance"):
        assert forbidden not in blob
    assert "not a conformity assessment" in blob


def test_merkle_evidence_is_cited_under_record_keeping() -> None:
    """AUD-06 landed in 11a; Art. 12 is where it earns its keep."""
    arts = export_compliance_evidence()["eu_ai_act"]["articles"]
    assert any("Merkle" in c or "AUD-06" in c for c in json.dumps(arts["Art.12"]).split())
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes.**
- [ ] **Step 5: Commit** `feat(controlplane): full EU AI Act article mapping with an explicit non-conformity stance (CMP-04)`.

---

### Task 3: SOC 2 evidence derived from the audit log (CMP-05)

**Files:** modify `.../compliance.py`; test `tests/unit/test_soc2_evidence.py`.

CMP-05 says **derived from the audit log** — so this counts real events in a range, it does not
assert that controls exist. The three families the requirement names map as:

```python
# AICPA Trust Services Criteria. Each criterion lists the AUDIT EVIDENCE we can actually produce —
# event kinds and decision shapes already written by the shipped pipeline. Nothing here asserts a
# control exists; the numbers come from the log or they are zero, and a zero is reported as a zero.
SOC2_CRITERIA: dict[str, dict] = {
    "CC6": {
        "name": "Logical and physical access controls",
        "evidence": "identity verification verdicts, certificate issuance/revocation, privilege-ring gates, delegation authority",
        "event_kinds": ("identity_verified", "identity_rejected", "certificate_issued", "certificate_revoked", "privilege_denied"),
    },
    "CC7": {
        "name": "System operations and monitoring",
        "evidence": "detector findings, circuit-breaker trips, kill switches, shadow/rogue findings, chain verification",
        "event_kinds": ("breaker_tripped", "kill_switch_engaged", "emergency_shutdown", "shadow_agent_seen", "rogue_finding"),
    },
    "CC8": {
        "name": "Change management",
        "evidence": "resource version bumps, constitution/policy version changes recorded on every decision",
        "event_kinds": ("resource_applied", "constitution_compiled"),
    },
}
```

> Implementer: the `event_kinds` above are ILLUSTRATIVE. Read the real `EVENT_KINDS` frozenset in
> `audit.py` and use only kinds that genuinely exist. A criterion citing an event kind the system
> never writes will silently report zero forever and look like a control that never fires — the most
> misleading possible output. Add a test that every kind named here is in `EVENT_KINDS`.

```python
def derive_soc2_evidence(session_factory, start=None, end=None) -> dict:
    """CMP-05 — count the audit evidence backing each criterion over a time range.

    Derived, not asserted: every number comes from the log. A zero means the log contains no such
    event in this window, which is itself evidence — of a quiet period, or of a control that never
    fired, and an auditor is entitled to tell those apart from the range and the totals.
    """
```

Returns, per criterion: `{name, evidence, event_kinds, counts: {kind: n}, total, range: {start, end}}`.
Decision-derived counts (outcomes like `require_approval`, `deny`) come from decision records, which
carry no `kind` — count them by `body["outcome"]`.

- [ ] **Step 1: Write the failing tests**

```python
def test_every_cited_event_kind_actually_exists(store) -> None:
    """A criterion citing a kind the system never writes reports zero forever and reads as a control
    that never fired — the most misleading output this module could produce."""
    from agentos_controlplane.audit import EVENT_KINDS

    for crit in SOC2_CRITERIA.values():
        for kind in crit["event_kinds"]:
            assert kind in EVENT_KINDS, kind


@pytest.mark.asyncio
async def test_evidence_counts_come_from_the_log_not_from_assertions(store) -> None:
    audit = AuditWriter(store)
    await _seed_kill_switch_event(audit)
    ev = derive_soc2_evidence(store)
    assert ev["CC7"]["total"] >= 1


def test_an_empty_log_reports_zeros_rather_than_omitting_the_criterion(store) -> None:
    """A missing criterion reads as 'not applicable'; a zero reads as 'no events in this window'.
    Only one of those is true, and an auditor needs to see which."""
    ev = derive_soc2_evidence(store)
    assert set(ev) == set(SOC2_CRITERIA)
    assert all(c["total"] == 0 for c in ev.values())


@pytest.mark.asyncio
async def test_the_time_range_actually_filters(store) -> None:
    """A range that silently ignores its bounds would let an auditor believe a quiet quarter was
    quiet when the events simply fell outside the query."""
    from datetime import datetime, timedelta, timezone

    audit = AuditWriter(store)
    await _seed_kill_switch_event(audit)
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert derive_soc2_evidence(store, start=future)["CC7"]["total"] == 0
    assert derive_soc2_evidence(store)["CC7"]["total"] >= 1
```

- [ ] **Step 2: Run → fails.** **Step 3: Implement.** **Step 4: Run → passes** + full gate.
- [ ] **Step 5: Commit** `feat(controlplane): SOC 2 evidence derived from the audit log (CMP-05)`.

## Self-review

CMP-04 names three things and each has a home: **risk classification** (operator-declared, echoed,
`undeclared` when absent — with a test proving it is never defaulted), **logging** (Art. 12, now
citing AUD-06's inclusion proofs), and **human oversight** (Art. 14, mapped to the approval / review
/ exception / kill-switch controls that actually ship). CMP-05 names access, change and monitoring;
CC6 / CC8 / CC7 cover them, and the counts are derived from the log rather than asserted.

The governing risk in this slice is not a crash, it is a false claim. Three tests exist purely to
hold that line: the bundle is scanned for conformity language and must carry the explicit
non-conformity disclaimer; every article we list must have a control behind it or say plainly that it
has none (Art. 5); and every event kind a criterion cites must exist in `EVENT_KINDS`, so no
criterion can report a permanent zero that reads as a control which never fires.

Nothing here touches the per-action path, and the widened mapping is additive — Phase 6's minimal
Art. 12 / Art. 26 claim remains true, with more articles around it.
