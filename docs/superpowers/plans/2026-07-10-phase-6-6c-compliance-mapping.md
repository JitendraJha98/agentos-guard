# Phase 6 · Slice 6c — Compliance Mapping + Evidence Export (CMP-01/02/03) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Commits end
> with a second `-m "Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"`. Tests:
> `./.venv/Scripts/python.exe -m pytest`. TDD per task, one commit each. Gates `floor_invariant`
> (430) + `regression_lock` (10) + `latency` (4) green at every commit.

**Goal (CMP-01/02/03):** Map each shipped detector/policy/effect/audit-capability to **OWASP Top 10
for Agentic Applications (2026)** + **NIST AI RMF** functions, and point **EU AI Act Art. 12
(record-keeping) / Art. 26 (human oversight)** claims at concrete evidence — exportable in one call.

**Architecture:** A static `compliance.py` registry in `agentos_controlplane` (dependency-light — only
strings, no pipeline import) maps each control to `{owasp, nist_rmf, eu_ai_act, evidence}`. A coverage
TEST (which may import everything) asserts every live detector class + graduated outcome + P0
audit/approval capability has a mapping and every referenced framework code is valid — so a future
control added without a mapping fails CI. `export_compliance_evidence(session_factory=None)` emits the
framework sections + control table + evidence pointers (live audit-chain counts + verifier status when
a store is supplied), with a `python -m agentos_controlplane.compliance` CLI.

**Tech Stack:** stdlib + Pydantic/dataclasses, the existing `audit_verify` (for evidence), pytest.

> First commit in this slice: `docs(phase-6): Slice 6c plan` for this file, then the tasks below.

## Framework taxonomy (authoritative — verified 2026-07-10)
- **OWASP Top 10 for Agentic Applications (2026)** — ASI01 Agent Goal Hijack · ASI02 Tool Misuse &
  Exploitation · ASI03 Agent Identity & Privilege Abuse · ASI04 Agentic Supply Chain Compromise ·
  ASI05 Unexpected Code Execution · ASI06 Memory & Context Poisoning · ASI07 Insecure Inter-Agent
  Communication · ASI08 Cascading Agent Failures · ASI09 Human-Agent Trust Exploitation · ASI10 Rogue
  Agents.
- **NIST AI RMF 1.0** functions — GOVERN, MAP, MEASURE, MANAGE.
- **EU AI Act** — Art. 12 (record-keeping / automatic logging), Art. 26 (deployer obligations,
  incl. human oversight).

## File structure
- Create `packages/controlplane/src/agentos_controlplane/compliance.py` — framework constants,
  `ControlMapping`, `CONTROL_MAPPINGS`, `export_compliance_evidence`, `_main` (CLI).
- Tests: `tests/unit/test_compliance_mapping.py`, `tests/integration/test_compliance_export.py`.

---

### Task 1: framework constants + control-mapping registry + coverage

**Files:**
- Create: `packages/controlplane/src/agentos_controlplane/compliance.py`
- Test: `tests/unit/test_compliance_mapping.py`

```python
"""CMP-01/02/03 — map shipped controls to OWASP Agentic Top 10 (2026) + NIST AI RMF, and point
EU AI Act Art. 12 / Art. 26 claims at concrete evidence. Dependency-light: this module holds only
strings + the export logic (no pipeline import); the coverage TEST enforces that every live control
is mapped. Taxonomy verified 2026-07-10 (OWASP Top 10 for Agentic Applications, 2026 / NIST AI RMF 1.0)."""
from __future__ import annotations

from dataclasses import dataclass, field

# OWASP Top 10 for Agentic Applications (2026)
OWASP_AGENTIC = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse & Exploitation",
    "ASI03": "Agent Identity & Privilege Abuse",
    "ASI04": "Agentic Supply Chain Compromise",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Agent Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}
NIST_RMF = {"GOVERN", "MAP", "MEASURE", "MANAGE"}
EU_AI_ACT = {"Art.12": "Record-keeping / automatic logging", "Art.26": "Deployer obligations & human oversight"}


@dataclass(frozen=True)
class ControlMapping:
    control: str          # stable key
    name: str             # human name
    owasp: tuple[str, ...]        # ASI codes
    nist_rmf: tuple[str, ...]     # RMF functions
    eu_ai_act: tuple[str, ...]    # article ids ("" allowed when not a launch claim)
    evidence: str         # what concrete artifact backs it


# Each shipped control (detector / graduated outcome family / audit-or-approval capability) -> frameworks.
CONTROL_MAPPINGS: tuple[ControlMapping, ...] = (
    ControlMapping("PromptInjectionScorer", "SEC-01 prompt-injection detector",
                   ("ASI01",), ("MEASURE",), ("Art.12",), "risk findings on the Decision + audit record"),
    ControlMapping("PiiScorer", "SEC-02 PII guardrail",
                   ("ASI02",), ("MEASURE", "MANAGE"), ("Art.12",), "risk findings + fail-closed redaction (AUD-04)"),
    ControlMapping("UnsafeContentScorer", "SEC-02 unsafe-content guardrail",
                   ("ASI01",), ("MEASURE",), ("Art.12",), "risk findings on the Decision"),
    ControlMapping("FormatViolationScorer", "SEC-02 format/schema guardrail",
                   ("ASI02",), ("MEASURE",), ("Art.12",), "risk findings on the Decision"),
    ControlMapping("IntentScorer", "SEC-12 intent-class tags",
                   ("ASI01",), ("MAP", "MEASURE"), ("Art.12",), "Decision.inferred_intent + audit record"),
    ControlMapping("SequenceCorrelator", "SEC-13 sequence/lineage intent",
                   ("ASI01", "ASI02"), ("MEASURE",), ("Art.12",), "sequence reasons + parent_action_id lineage"),
    ControlMapping("constitution_policy_floor", "POL-01/03 deterministic constitution floor",
                   ("ASI02", "ASI10"), ("GOVERN", "MANAGE"), ("Art.12",), "policy/constitution version on every Decision"),
    ControlMapping("graduated_response", "POL-06 graduated outcomes",
                   ("ASI02", "ASI09"), ("MANAGE",), (), "the outcome + reasons on every Decision"),
    ControlMapping("approvals", "POL-07 require_approval workflow",
                   ("ASI09",), ("MANAGE",), ("Art.26",), "ApprovalRequest records + resolutions (audited)"),
    ControlMapping("temporary_exception", "POL-13 human-ratified time-boxed allow",
                   ("ASI09",), ("MANAGE",), ("Art.26",), "temporary_exception records (human-granted)"),
    ControlMapping("governance_review", "POL-14 async non-blocking review",
                   ("ASI09",), ("MANAGE",), ("Art.26",), "GovernanceReview records"),
    ControlMapping("kill_switch", "RUN-01/02 operator kill switch",
                   ("ASI08", "ASI10"), ("MANAGE",), ("Art.26",), "kill_switch state + audited toggles"),
    ControlMapping("identity_engine", "IDN-01/02 signed identity + verification",
                   ("ASI03",), ("GOVERN",), (), "EdDSA token verification; forged -> deny (audited)"),
    ControlMapping("interception_coverage", "INT-06 no-silent-gaps coverage",
                   ("ASI10",), ("MEASURE",), (), "coverage registry + bypass-attempt fail-closed"),
    ControlMapping("audit_chain", "AUD-01/02/03 hash-chained decision records + provenance",
                   ("ASI08", "ASI10"), ("GOVERN", "MEASURE"), ("Art.12",), "append-only hash chain; action->decision->principles->outcome + versions"),
    ControlMapping("audit_signatures", "AUD-08 per-record EdDSA signatures",
                   ("ASI03",), ("GOVERN",), ("Art.12",), "detached signature per record (verify_record_signature)"),
    ControlMapping("audit_verifier", "AUD-05 CI chain verifier + checkpoint anchoring",
                   ("ASI08",), ("MEASURE",), ("Art.12",), "audit_verify re-derivation + RFC-3161 checkpoints"),
    ControlMapping("redaction", "AUD-04 fail-closed redaction + secret scan",
                   ("ASI02", "ASI06"), ("MANAGE",), ("Art.12",), "redacted payload; no write if redaction fails"),
)

# Detector CLASS NAMES that MUST be mapped (the coverage test imports the classes and checks these).
LIVE_DETECTOR_CONTROLS = frozenset({
    "PromptInjectionScorer", "PiiScorer", "UnsafeContentScorer", "FormatViolationScorer",
    "IntentScorer", "SequenceCorrelator",
})
```

**Steps (TDD):**
- [ ] Test (`test_compliance_mapping.py`): (a) every `ControlMapping.owasp` code is in
  `OWASP_AGENTIC`, every `nist_rmf` in `NIST_RMF`, every `eu_ai_act` in `EU_AI_ACT` (no typo'd
  codes). (b) control keys are unique. (c) COVERAGE: import the live scorer classes
  (`from agentos_pipeline.risk import ...` — PromptInjectionScorer/PiiScorer/UnsafeContentScorer/
  FormatViolationScorer/IntentScorer, and the SequenceCorrelator) and assert each class `__name__`
  is a mapped control (proves no shipped detector is unmapped); assert `LIVE_DETECTOR_CONTROLS`
  equals the set of those class names (catches a new detector). (d) every graduated `Outcome` family
  and the P0 audit/approval capability keys used below are present. Run → fails.
- [ ] Implement `compliance.py` (registry + constants). Run → passes.
- [ ] Commit `feat(controlplane): compliance control->framework mapping registry + coverage (CMP-01/02)`.

---

### Task 2: `export_compliance_evidence` + CLI (CMP-03)

**Files:**
- Modify: `packages/controlplane/src/agentos_controlplane/compliance.py`
- Test: `tests/integration/test_compliance_export.py`

```python
def export_compliance_evidence(session_factory=None, public_key_pem=None) -> dict:
    """CMP-03 — a one-call evidence bundle: the control->framework mapping grouped by framework, plus
    pointers to the CONCRETE evidence backing EU Art. 12 (record-keeping) / Art. 26 (human oversight)
    claims. When a store is supplied, include LIVE evidence: audit-record count, checkpoint count, and
    whether the chain currently verifies (AUD-05) — the record-keeping proof itself."""
    controls = [
        {"control": m.control, "name": m.name, "owasp": list(m.owasp),
         "nist_rmf": list(m.nist_rmf), "eu_ai_act": list(m.eu_ai_act), "evidence": m.evidence}
        for m in CONTROL_MAPPINGS
    ]
    by_owasp = {code: {"name": name, "controls": [m.control for m in CONTROL_MAPPINGS if code in m.owasp]}
                for code, name in OWASP_AGENTIC.items()}
    by_nist = {fn: [m.control for m in CONTROL_MAPPINGS if fn in m.nist_rmf] for fn in sorted(NIST_RMF)}
    by_eu = {art: {"name": name, "controls": [m.control for m in CONTROL_MAPPINGS if art in m.eu_ai_act]}
             for art, name in EU_AI_ACT.items()}
    bundle = {
        "frameworks": {"owasp_agentic_2026": by_owasp, "nist_ai_rmf": by_nist, "eu_ai_act": by_eu},
        "controls": controls,
        "evidence": {
            "eu_art12_record_keeping": "hash-chained, per-record-signed, fail-closed-redacted audit log (AUD-01/03/04/08)",
            "eu_art26_human_oversight": "require_approval + temporary_exception + governance_review + kill switch (POL-07/13/14, RUN-01/02)",
        },
    }
    if session_factory is not None:
        from sqlalchemy import func, select
        from agentos_controlplane.audit_verify import verify_chain
        from agentos_controlplane.store.models import AuditRecord, ChainCheckpoint
        with session_factory() as s:
            bundle["evidence"]["audit_records"] = s.scalar(select(func.count()).select_from(AuditRecord))
            bundle["evidence"]["checkpoints"] = s.scalar(select(func.count()).select_from(ChainCheckpoint))
        result = verify_chain(session_factory, public_key_pem=public_key_pem)
        bundle["evidence"]["chain_verifies"] = result.ok
    return bundle


def _main(argv=None) -> int:
    import argparse, json
    from sqlalchemy import create_engine
    from agentos_controlplane.store.engine import create_session_factory
    p = argparse.ArgumentParser(prog="agentos_controlplane.compliance",
                                description="Export the compliance evidence bundle (CMP-03).")
    p.add_argument("--db", help="SQLite path / SQLAlchemy URL to include live audit evidence")
    p.add_argument("--pubkey", help="control-plane public-key PEM (enables chain signature verify)")
    args = p.parse_args(argv)
    sf = None
    if args.db:
        url = args.db if "://" in args.db else f"sqlite+pysqlite:///{args.db}"
        sf = create_session_factory(create_engine(url))
    pub = open(args.pubkey, encoding="utf-8").read() if args.pubkey else None
    print(json.dumps(export_compliance_evidence(sf, public_key_pem=pub), indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
```

**Steps (TDD):**
- [ ] Test (`test_compliance_export.py`): `bundle = export_compliance_evidence()` — assert it has
  `frameworks.owasp_agentic_2026` (10 ASI keys), `frameworks.nist_ai_rmf` (4 functions),
  `frameworks.eu_ai_act` (Art.12 + Art.26 each listing >=1 control), a `controls` list, and the two
  `evidence` claim pointers. Then with a live store: append a couple of real decisions via
  `AuditWriter` (signed, over a shared SQLite store), call
  `export_compliance_evidence(sf, public_key_pem=<control-plane pub pem>)`, assert
  `evidence.audit_records >= 2` and `evidence.chain_verifies is True`. Run the CLI via
  `_main(["--db", <path>])` (or subprocess) → prints valid JSON, exit 0. Run → fails.
- [ ] Implement the export + CLI. Run → passes.
- [ ] Commit `feat(controlplane): compliance evidence export + CLI, live audit-chain proof (CMP-03)`.

---

### Task 3: full gate
- [ ] `pytest -q` green; `-m floor_invariant` 430; `-m regression_lock` 10; `-m latency` 4 (compliance
  is off the hot path — no pipeline/latency impact).
- [ ] Commit only if incidental fixes were needed.

## Self-review
CMP-01: every shipped detector + policy/effect + audit capability maps to OWASP Agentic Top-10 (2026)
ASI codes (coverage test DISCOVERS the live detector classes from their modules so an unmapped future detector fails CI).
CMP-02: each maps to NIST RMF GOVERN/MAP/MEASURE/MANAGE. CMP-03: EU Art. 12 (record-keeping) / Art. 26
(human oversight) claims point at concrete evidence — the hash-chained/signed/redacted audit log and
the approval/exception/review/kill controls — and the export includes LIVE proof (record count +
`chain_verifies`) when a store is supplied, with a one-call CLI. Dependency-light module (no pipeline
import); taxonomy verified against the 2026 OWASP Agentic list + NIST AI RMF 1.0. Off the hot path;
gates green.
