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

# Detector CLASS NAMES that MUST be mapped (the coverage test imports the classes and checks these).
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
