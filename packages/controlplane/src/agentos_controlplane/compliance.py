"""CMP-01/02/03 — map shipped controls to OWASP Agentic Top 10 (2026) + NIST AI RMF, and point
EU AI Act Art. 12 / Art. 26 claims at concrete evidence. Dependency-light: this module holds only
strings + the export logic (no pipeline import); the coverage TEST enforces that every live control
is mapped. Taxonomy verified 2026-07-10 (OWASP Top 10 for Agentic Applications, 2026 / NIST AI RMF 1.0)."""
from __future__ import annotations

from dataclasses import dataclass

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
EU_AI_ACT = {
    "Art.12": "Record-keeping / automatic logging",
    "Art.26": "Deployer obligations & human oversight",
}

# CMP-04 — the risk tiers an OPERATOR may declare for a deployment (Art. 6 / Annex III).
# Never inferred. Which tier applies depends on the USE CASE, not on anything a runtime can observe:
# the same agent is high-risk in a hiring pipeline and minimal-risk summarizing meeting notes. A
# wrong guess harms in both directions — it burdens a deployer with obligations they do not have, or
# tells them to skip ones they do. Absent = UNDECLARED, which the export reports as undeclared.
RISK_CLASSIFICATIONS = frozenset({"prohibited", "high_risk", "limited_risk", "minimal_risk"})
UNDECLARED = "undeclared"

# D-8, in one string. It travels INSIDE the eu_ai_act section rather than beside it, so the articles
# cannot be lifted out of the bundle and forwarded without it. Art. 6 / Annex III (classification)
# and Art. 43 (conformity assessment) are cited because they are the two determinations this tool
# must not pre-empt — both belong to the deployer, their counsel, or a notified body.
EU_AI_ACT_DISCLAIMER = (
    "Evidence bearing on the obligations these articles create. This is NOT a conformity "
    "assessment and NOT a claim of compliance: classification under Art. 6 and Annex III, and "
    "conformity under Art. 43, are determinations for the deployer, their counsel, or a notified "
    "body — never for this tool."
)
RISK_CLASSIFICATION_SOURCE = (
    "operator-declared, never inferred; 'undeclared' means no operator has declared one for this "
    "agent's deployment, not that it is low risk"
)


@dataclass(frozen=True)
class ControlMapping:
    control: str  # stable key
    name: str  # human name
    owasp: tuple[str, ...]  # ASI codes
    nist_rmf: tuple[str, ...]  # RMF functions
    eu_ai_act: tuple[str, ...]  # article ids ("" allowed when not a launch claim)
    evidence: str  # what concrete artifact backs it


# Each shipped control (detector / graduated outcome family / audit-or-approval capability) -> frameworks.
CONTROL_MAPPINGS: tuple[ControlMapping, ...] = (
    ControlMapping(
        "PromptInjectionScorer",
        "SEC-01 prompt-injection detector",
        ("ASI01",),
        ("MEASURE",),
        ("Art.12",),
        "risk findings on the Decision + audit record",
    ),
    ControlMapping(
        "PiiScorer",
        "SEC-02 PII guardrail",
        ("ASI02",),
        ("MEASURE", "MANAGE"),
        ("Art.12",),
        "risk findings + fail-closed redaction (AUD-04)",
    ),
    ControlMapping(
        "UnsafeContentScorer",
        "SEC-02 unsafe-content guardrail",
        ("ASI01",),
        ("MEASURE",),
        ("Art.12",),
        "risk findings on the Decision",
    ),
    ControlMapping(
        "FormatViolationScorer",
        "SEC-02 format/schema guardrail",
        ("ASI02",),
        ("MEASURE",),
        ("Art.12",),
        "risk findings on the Decision",
    ),
    ControlMapping(
        "IntentScorer",
        "SEC-12 intent-class tags",
        ("ASI01",),
        ("MAP", "MEASURE"),
        ("Art.12",),
        "Decision.inferred_intent + audit record",
    ),
    ControlMapping(
        "SequenceCorrelator",
        "SEC-13 sequence/lineage intent",
        ("ASI01", "ASI02"),
        ("MEASURE",),
        ("Art.12",),
        "sequence reasons + parent_action_id lineage",
    ),
    ControlMapping(
        "constitution_policy_floor",
        "POL-01/03 deterministic constitution floor",
        ("ASI02", "ASI10"),
        ("GOVERN", "MANAGE"),
        ("Art.12",),
        "policy/constitution version on every Decision",
    ),
    ControlMapping(
        "graduated_response",
        "POL-06 graduated outcomes",
        ("ASI02", "ASI09"),
        ("MANAGE",),
        (),
        "the outcome + reasons on every Decision",
    ),
    ControlMapping(
        "approvals",
        "POL-07 require_approval workflow",
        ("ASI09",),
        ("MANAGE",),
        ("Art.26",),
        "ApprovalRequest records + resolutions (audited)",
    ),
    ControlMapping(
        "temporary_exception",
        "POL-13 human-ratified time-boxed allow",
        ("ASI09",),
        ("MANAGE",),
        ("Art.26",),
        "temporary_exception records (human-granted)",
    ),
    ControlMapping(
        "governance_review",
        "POL-14 async non-blocking review",
        ("ASI09",),
        ("MANAGE",),
        ("Art.26",),
        "GovernanceReview records",
    ),
    ControlMapping(
        "kill_switch",
        "RUN-01/02 operator kill switch",
        ("ASI08", "ASI10"),
        ("MANAGE",),
        ("Art.26",),
        "kill_switch state + audited toggles",
    ),
    ControlMapping(
        "identity_engine",
        "IDN-01/02 signed identity + verification",
        ("ASI03",),
        ("GOVERN",),
        (),
        "EdDSA token verification; forged -> deny (audited)",
    ),
    ControlMapping(
        "interception_coverage",
        "INT-06 no-silent-gaps coverage",
        ("ASI10",),
        ("MEASURE",),
        (),
        "coverage registry + bypass-attempt fail-closed",
    ),
    ControlMapping(
        "audit_chain",
        "AUD-01/02/03 hash-chained decision records + provenance",
        ("ASI08", "ASI10"),
        ("GOVERN", "MEASURE"),
        ("Art.12",),
        "append-only hash chain; action->decision->principles->outcome + versions",
    ),
    ControlMapping(
        "audit_signatures",
        "AUD-08 per-record EdDSA signatures",
        ("ASI03",),
        ("GOVERN",),
        ("Art.12",),
        "detached signature per record (verify_record_signature)",
    ),
    ControlMapping(
        "audit_verifier",
        "AUD-05 CI chain verifier + checkpoint anchoring",
        ("ASI08",),
        ("MEASURE",),
        ("Art.12",),
        "audit_verify re-derivation + RFC-3161 checkpoints",
    ),
    ControlMapping(
        "redaction",
        "AUD-04 fail-closed redaction + secret scan",
        ("ASI02", "ASI06"),
        ("MANAGE",),
        ("Art.12",),
        "redacted payload; no write if redaction fails",
    ),
)

# Detector CLASS NAMES that MUST be mapped. The coverage test DISCOVERS the live detector classes
# from their modules and asserts this set equals exactly them, so an unmapped new detector fails CI.
LIVE_DETECTOR_CONTROLS = frozenset(
    {
        "PromptInjectionScorer",
        "PiiScorer",
        "UnsafeContentScorer",
        "FormatViolationScorer",
        "IntentScorer",
        "SequenceCorrelator",
    }
)


def export_compliance_evidence(session_factory=None, public_key_pem=None) -> dict:
    """CMP-03 — a one-call evidence bundle: the control->framework mapping grouped by framework, plus
    pointers to the CONCRETE evidence backing EU Art. 12 (record-keeping) / Art. 26 (human oversight)
    claims. When a store is supplied, include LIVE evidence: audit-record count, checkpoint count, and
    whether the chain currently verifies (AUD-05) — the record-keeping proof itself."""
    controls = [
        {
            "control": m.control,
            "name": m.name,
            "owasp": list(m.owasp),
            "nist_rmf": list(m.nist_rmf),
            "eu_ai_act": list(m.eu_ai_act),
            "evidence": m.evidence,
        }
        for m in CONTROL_MAPPINGS
    ]
    by_owasp = {
        code: {"name": name, "controls": [m.control for m in CONTROL_MAPPINGS if code in m.owasp]}
        for code, name in OWASP_AGENTIC.items()
    }
    by_nist = {
        fn: [m.control for m in CONTROL_MAPPINGS if fn in m.nist_rmf] for fn in sorted(NIST_RMF)
    }
    by_eu = {
        art: {"name": name, "controls": [m.control for m in CONTROL_MAPPINGS if art in m.eu_ai_act]}
        for art, name in EU_AI_ACT.items()
    }
    eu_section: dict = {"articles": by_eu, "disclaimer": EU_AI_ACT_DISCLAIMER}
    bundle = {
        "frameworks": {"owasp_agentic_2026": by_owasp, "nist_ai_rmf": by_nist, "eu_ai_act": by_eu},
        "eu_ai_act": eu_section,
        "controls": controls,
        "evidence": {
            "eu_art12_record_keeping": "hash-chained, per-record-signed, fail-closed-redacted audit log (AUD-01/03/04/08)",
            "eu_art26_human_oversight": "require_approval + temporary_exception + governance_review + kill switch (POL-07/13/14, RUN-01/02)",
        },
    }
    if session_factory is not None:
        from sqlalchemy import func, select

        from agentos_controlplane.audit_verify import verify_chain
        from agentos_controlplane.store.models import Agent, AuditRecord, ChainCheckpoint

        with session_factory() as s:
            bundle["evidence"]["audit_records"] = s.scalar(select(func.count()).select_from(AuditRecord))
            bundle["evidence"]["checkpoints"] = s.scalar(select(func.count()).select_from(ChainCheckpoint))
            # CMP-04. Added ONLY with a registry to read: an empty `risk_classifications: {}` would
            # read as "this fleet has no agents", which is a claim about a fleet we cannot see.
            eu_section["risk_classifications"] = {
                agent_id: classification or UNDECLARED
                for agent_id, classification in s.execute(
                    select(Agent.agent_id, Agent.risk_classification).order_by(Agent.agent_id)
                ).all()
            }
            eu_section["risk_classification_source"] = RISK_CLASSIFICATION_SOURCE
        result = verify_chain(session_factory, public_key_pem=public_key_pem)
        bundle["evidence"]["chain_verifies"] = result.ok
    return bundle


def _main(argv=None) -> int:
    import argparse
    import json

    from sqlalchemy import create_engine

    from agentos_controlplane.store.engine import create_session_factory

    p = argparse.ArgumentParser(
        prog="agentos_controlplane.compliance",
        description="Export the compliance evidence bundle (CMP-03).",
    )
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
