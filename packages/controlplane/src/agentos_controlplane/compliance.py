"""CMP-01/02/03/04/05 — map shipped controls to OWASP Agentic Top 10 (2026), NIST AI RMF, the EU AI
Act article set a high-risk deployment actually faces, and the SOC 2 Trust Services Criteria.
Dependency-light: this module holds only strings + the export logic (no pipeline import); the
coverage TEST enforces that every live control is mapped. Taxonomy verified 2026-07-10 (OWASP Top 10
for Agentic Applications, 2026 / NIST AI RMF 1.0).

EVERY STRING BELOW IS EVIDENCE, NEVER A CONFORMITY CLAIM (spec D-8). "Here are the controls bearing
on Art. 14 and the records behind them" — never "this system is Art. 14 compliant". Conformity is a
determination made by a notified body, an auditor, or the deployer's own counsel; a tool that
pre-empts it manufactures false assurance about someone else's legal exposure. The mapping lives in
ONE module on purpose: a second mapping file is a second thing to forget to update, and a stale
compliance claim is worse than no claim."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

# Rows per round trip while streaming the audit log for SOC 2 counts — memory bound, not a result
# bound (the count itself is never clipped).
_SCAN_CHUNK = 1000

# CMP-06 — the frameworks an evidence bundle can be exported for. An unknown name is refused rather
# than answered with an empty bundle, which would read as "no evidence exists" (the wrong conclusion
# drawn from a wrong URL).
FRAMEWORKS = ("owasp_agentic_2026", "nist_ai_rmf", "eu_ai_act", "soc2")

# A bundle is handed to an outside party, so its size must be bounded by something other than how
# busy the fleet was. An unbounded export of a year of audit records is a memory event on our side
# and an unusable artifact on theirs; truncation is reported in the manifest, so a recipient always
# knows they hold a subset and how big a one.
_MAX_RECORDS = 5000

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
# EU AI Act = Regulation (EU) 2024/1689. Headings quoted as the Act words them rather than
# paraphrased — a paraphrase in a bundle handed to a regulator is where a mapping starts describing
# obligations that do not exist. PROVENANCE, stated exactly, because overstating what we checked is
# the same failure as overstating what we evidence: verified verbatim on 2026-08-19, Art. 5-15
# against the CONSOLIDATED text on EUR-Lex (eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng),
# and Art. 26 / 43 / 50 / 72 against two independent reproductions of the Official Journal text
# (ai-act-law.eu, artificialintelligenceact.eu) because the EUR-Lex renderer truncates mid-recital
# before reaching them. Anything that could not be confirmed is ABSENT rather than approximated:
# Art. 73 (serious incident reporting) is omitted because notifying a market surveillance authority
# is an act this control plane does not perform, and listing it would imply we evidence something
# toward it.
EU_AI_ACT = {
    "Art.5": "Prohibited AI practices",
    "Art.6": "Classification rules for high-risk AI systems",
    "Art.9": "Risk management system",
    "Art.10": "Data and data governance",
    "Art.11": "Technical documentation",
    "Art.12": "Record-keeping",
    "Art.13": "Transparency and provision of information to deployers",
    "Art.14": "Human oversight",
    "Art.15": "Accuracy, robustness and cybersecurity",
    "Art.26": "Obligations of deployers of high-risk AI systems",
    "Art.72": (
        "Post-market monitoring by providers and post-market monitoring plan for high-risk AI "
        "systems"
    ),
}

# The articles we LIST but evidence NOTHING toward, and why. Listing them empty is deliberate: a
# silently missing article reads as an oversight, an explicitly empty one is a statement, and both
# of these are articles where inventing a control would be exactly the overreach D-8 forbids.
EU_ARTICLE_NOTES = {
    "Art.5": (
        "No control here bears on this article. Prohibited practices are about what a system is "
        "USED for — the purpose a deployer puts it to — not about controls a runtime can "
        "implement. Pointing a shipped control at Art. 5 would be a claim about a deployment "
        "nothing here can observe."
    ),
    "Art.6": (
        "No control here bears on this article. Classification is a legal determination about a "
        "deployment's use case; it is operator-declared (see risk_classifications) and never "
        "inferred from anything this control plane measures."
    ),
}

# CMP-04 — the risk tiers an OPERATOR may declare. Never inferred.
#
# PROVENANCE, precisely, because attributing to the Regulation a vocabulary it does not use is the
# same overreach as claiming conformity: ONLY `high_risk` names a determination the Act's OPERATIVE
# text defines (Art. 6 + Annex III, which produce exactly one answer — high-risk or not). The other
# three are the European Commission's own explanatory labels for the Act's risk-based approach
# ("Unacceptable risk / High risk / Transparency risk / Minimal or no risk", verified 2026-08-19 at
# digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai): `unacceptable_risk` for the
# practices Art. 5 prohibits, `transparency_risk` for the systems Art. 50 attaches disclosure
# obligations to, `minimal_risk` for everything else. Neither "limited risk" nor "minimal risk"
# appears in the operative text at all, and "limited risk" is not even the Commission's current
# term — which is why it is not one of these values.
#
# Which tier applies depends on the USE CASE, not on anything a runtime can observe: the same agent
# is high-risk in a hiring pipeline and minimal-risk summarizing meeting notes. A wrong guess harms
# in both directions — it burdens a deployer with obligations they do not have, or tells them to
# skip ones they do. Absent = UNDECLARED, which the export reports as undeclared.
RISK_CLASSIFICATIONS = frozenset(
    {"unacceptable_risk", "high_risk", "transparency_risk", "minimal_risk"}
)
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
    "agent, not that it is low risk. ONE declaration per registered agent, not per deployment — an "
    "agent serving two use cases can hold only one, and which tier applies depends on the use "
    "case. Only 'high_risk' names a determination the Act's operative text defines (Art. 6 + Annex "
    "III); the other tiers follow the European Commission's explanatory risk-level framing."
)
# A classification is a standing statement, not an event, so it has no place in the range — and
# saying so stops a reader from taking it as the tier that was in force during the window.
RISK_CLASSIFICATION_AS_OF = (
    "Read at export time — the tiers declared NOW, not the tiers in force during the exported "
    "range. A classification is a standing operator statement about a use case rather than an "
    "event in the window, and back-dating it would invent a history no record supports."
)

# Said once and used by every range-scoped output. The window is the ONE dimension scoping an
# auditor-facing artifact that is not itself tamper-evident, and two copies of that caveat are two
# things to forget to keep true.
RANGE_NOTE = (
    "Both bounds inclusive. Filtered on audit_record.created_at — the server clock at insert, "
    "which the record hash and the AUD-08 signature do NOT cover (the chain's own ordering is "
    "`seq`), so the window is administrative metadata rather than tamper-evident. Inclusive only "
    "to that column's storage granularity: on SQLite it is one second, so a record written in the "
    "same second as an exact-second `start` falls outside the window."
)


# SOC 2 = AICPA Trust Services Criteria (TSP section 100, 2017 criteria). Family names and point
# references verified 2026-08-19 against the TSP section 100 text itself. Only points the cited
# records actually bear on are listed: CC6.2 (registering and authorizing users before issuing
# credentials) is deliberately absent because agent enrollment and certificate issuance are not
# written as audit EVENTS, and citing a point nothing here evidences is the same failure as citing
# an event kind nothing writes.
#
# Each criterion names the AUDIT EVIDENCE we can actually produce: event kinds and decision outcomes
# already written by the shipped pipeline. NOTHING HERE ASSERTS A CONTROL EXISTS — the numbers come
# from the log or they are zero, and a zero is reported as a zero.
#
# A record may back more than one criterion (a privilege-ring assignment is both an access
# authorization and a configuration change), so the per-criterion totals are not a partition of the
# log and do not sum to it.
#
# Within a listed family, only the POINTS the shipped records bear on are cited; the rest are
# absent for the same reason CC6.2 is. Points we can see an argument for but have not verified
# against the AICPA text stay out — approximating a criterion reference in an auditor-facing
# artifact is exactly the failure D-8 exists to prevent.

# D-8 for the SOC 2 half. A SOC 2 report is an attestation ISSUED BY an independent licensed CPA
# firm; this output reproduces AICPA family headings and point references next to counts, which is
# the shape of a control-effectiveness table out of such a report. Forwarded without this it is
# indistinguishable from attested evidence — so it travels INSIDE each criterion (the function
# returns a bare {CC6:..., CC7:..., CC8:...} map with no wrapper level to hang it from), never
# beside them.
SOC2_DISCLAIMER = (
    "Audit-log evidence bearing on these criteria. This is NOT a SOC 2 report and NOT an opinion "
    "on the design or operating effectiveness of any control: a SOC 2 examination is performed and "
    "reported by an independent licensed CPA firm, never by the system under examination. A single "
    "record may back more than one criterion, so these totals overlap and do not partition the log."
)
# Silence about what is NOT covered is the same failure EU_ARTICLE_NOTES exists to refuse, applied
# to the other framework: three families out of nine read as "SOC 2 evidence" unless we say so.
SOC2_SCOPE = (
    "Scope: the CC6, CC7 and CC8 common criteria only, and within them only the points the shipped "
    "audit records actually bear on. The other common-criteria series (CC1-CC5, CC9) and the "
    "Availability, Confidentiality, Processing Integrity and Privacy categories are OUT of scope "
    "here — not evidenced and not asserted, and their absence says nothing about them either way."
)

# CMP-06's D-8 statement. The CMP-03 bundle can rely on ours being the hands it stays in; an
# evidence bundle is built to LEAVE, so what it is not has to ride inside it.
EVIDENCE_BUNDLE_DISCLAIMER = (
    "Evidence exported from an audit log. This is NOT a conformity assessment, NOT a "
    "certification, and NOT an opinion on the design or operating effectiveness of any control: "
    "each of those is a determination for a notified body, an independent auditor, or the "
    "deployer's own counsel — never for the system under examination. The proofs here show that "
    "the included records are IN the sealed epochs whose roots travel with them; no root can show "
    "that nothing was withheld before it was sealed."
)

# Stated for the two frameworks that are taxonomies rather than obligations. `{}` would read as "no
# evidence exists" — the same false silence an empty EU article entry would be.
_NO_DERIVED_AGGREGATE = (
    "No aggregate is derived from the audit log for this framework: {framework} classifies "
    "CONTROLS, and no field in an audit record maps onto its categories as a count. The evidence "
    "here is the mapping plus the in-range records travelling with this bundle, each with its own "
    "inclusion proof."
)

# The verification steps, INSIDE the artifact. A recipient who has to ask us how to check a bundle
# is already trusting us for the part the bundle exists to remove.
HOW_TO_VERIFY = (
    "1. Recompute the manifest digest: sha256 over the canonical JSON (sorted keys, no whitespace, "
    "ensure_ascii) of this bundle with the `manifest_digest` key removed, then compare. This "
    "detects a bundle edited after export. It DOES NOT AUTHENTICATE THE EXPORTER — anyone can "
    "alter the content and recompute a digest over the result. Steps 2 and 3 are where authority "
    "comes from.",
    "2. For every entry in `records` whose `inclusion` is not null, build "
    '{"record": entry["record"], "index": entry["inclusion"]["index"], '
    '"proof": entry["inclusion"]["proof"], '
    '"epoch": epochs[str(entry["inclusion"]["epoch"])]} and pass it to '
    "agentos_controlplane.merkle.verify_bundle(payload, public_key_pem=..., tsa_root_pem=...); "
    "require `.ok`. Use verify_bundle, NOT verify_inclusion: the tree check alone binds a "
    "record_hash, so on its own it proves only that this file agrees with itself.",
    "3. Require `.anchor_verified` too. Without it nothing outside this file vouches for an "
    "epoch's `root` or `leaf_count`, and a fabricated epoch over a fabricated tree verifies exactly "
    "as a genuine one does.",
    "4. Read `records_unsealed` and `truncated` before drawing conclusions from the record list. An "
    "unsealed record carries no proof because it was appended after the last epoch was sealed; a "
    "truncated bundle is a subset of `records_in_range`, oldest first. Both are stated rather than "
    "implied so that what you hold is never mistaken for everything there was.",
    "5. `chain_verifies` is our own AUD-05 pass over the WHOLE chain at export time, run on our "
    "data — context, not a substitute for steps 2 and 3. Read `chain_signatures_checked` beside "
    "it: without a public key that pass re-derives the hash linkage and verifies NO signature, so "
    "a zero there means `chain_verifies: true` says nothing about who wrote the records.",
    "6. Know the limit of all of it: an inclusion proof shows a record IS in the sealed epoch. It "
    "cannot show the epoch is COMPLETE — no root can testify that nothing was withheld before "
    "sealing. Completeness needs independent witnesses observing roots, which this bundle neither "
    "provides nor claims.",
)

SOC2_CRITERIA: dict[str, dict] = {
    "CC6": {
        "name": "Logical and Physical Access Controls",
        "criteria": ("CC6.1", "CC6.3"),
        "evidence": (
            "privilege-ring assignments, human authorization rulings, time-boxed exceptions, "
            "multi-party consensus, and the per-action decisions that REFUSED or HELD an action — "
            "`deny` and `require_approval`, and only those two. The other gating outcomes are "
            "already counted here as their own lifecycle events (`require_consensus` as "
            "consensus_resolved, `temporary_exception` as exception_granted) or belong to CC7 "
            "containment (`sandbox` as sandbox_executed), and counting the decision as well would "
            "double-count one act of access control. `governance_review` is not counted at all: it "
            "lets the action proceed and opens an asynchronous review, so it refused nothing."
        ),
        "event_kinds": (
            "privilege_ring_set",
            "approval_resolved",
            "approval_timed_out",
            "exception_granted",
            "consensus_resolved",
        ),
        "outcomes": ("deny", "require_approval"),
    },
    "CC7": {
        "name": "System Operations",
        "criteria": ("CC7.2", "CC7.4"),
        "evidence": (
            "anomaly detections (shadow/rogue agents, resource-budget breaches) and the "
            "containment actions taken in response (sandboxing, breakers, kill switches, "
            "fleet-wide emergency stop and its explicit resume)"
        ),
        "event_kinds": (
            "shadow_agent_detected",
            "rogue_agent_detected",
            "resource_limit_exceeded",
            "sandbox_executed",
            "circuit_tripped",
            "circuit_reset",
            "kill_switch_set",
            "kill_switch_cleared",
            "emergency_shutdown",
            "emergency_resume",
        ),
        "outcomes": (),
    },
    "CC8": {
        "name": "Change Management",
        "criteria": ("CC8.1",),
        "evidence": (
            "operator changes to enforcement configuration — privilege-ring assignments and "
            "resource budgets — each audited with the operator who made it"
        ),
        "event_kinds": ("privilege_ring_set", "resource_limit_set"),
        "outcomes": (),
    },
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
        ("Art.9", "Art.12", "Art.15"),
        "risk findings on the Decision + audit record",
    ),
    ControlMapping(
        "PiiScorer",
        "SEC-02 PII guardrail",
        ("ASI02",),
        ("MEASURE", "MANAGE"),
        ("Art.10", "Art.12"),
        "risk findings + fail-closed redaction (AUD-04)",
    ),
    ControlMapping(
        "UnsafeContentScorer",
        "SEC-02 unsafe-content guardrail",
        ("ASI01",),
        ("MEASURE",),
        ("Art.9", "Art.12", "Art.15"),
        "risk findings on the Decision",
    ),
    ControlMapping(
        "FormatViolationScorer",
        "SEC-02 format/schema guardrail",
        ("ASI02",),
        ("MEASURE",),
        ("Art.12", "Art.15"),
        "risk findings on the Decision",
    ),
    ControlMapping(
        "IntentScorer",
        "SEC-12 intent-class tags",
        ("ASI01",),
        ("MAP", "MEASURE"),
        ("Art.9", "Art.12"),
        "Decision.inferred_intent + audit record",
    ),
    ControlMapping(
        "SequenceCorrelator",
        "SEC-13 sequence/lineage intent",
        ("ASI01", "ASI02"),
        ("MEASURE",),
        ("Art.9", "Art.12"),
        "sequence reasons + parent_action_id lineage",
    ),
    ControlMapping(
        "constitution_policy_floor",
        "POL-01/03 deterministic constitution floor",
        ("ASI02", "ASI10"),
        ("GOVERN", "MANAGE"),
        ("Art.9", "Art.11", "Art.12"),
        "policy/constitution version pinned on every Decision",
    ),
    ControlMapping(
        "graduated_response",
        "POL-06 graduated outcomes",
        ("ASI02", "ASI09"),
        ("MANAGE",),
        ("Art.9", "Art.13"),
        "the outcome + explainable reasons (principle refs, evidence) + remediation on every Decision",
    ),
    ControlMapping(
        "approvals",
        "POL-07 require_approval workflow",
        ("ASI09",),
        ("MANAGE",),
        ("Art.14", "Art.26"),
        "ApprovalRequest records + resolutions (audited)",
    ),
    ControlMapping(
        "temporary_exception",
        "POL-13 human-ratified time-boxed allow",
        ("ASI09",),
        ("MANAGE",),
        ("Art.14", "Art.26"),
        "temporary_exception records (human-granted)",
    ),
    ControlMapping(
        "governance_review",
        "POL-14 async non-blocking review",
        ("ASI09",),
        ("MANAGE",),
        ("Art.14", "Art.26"),
        "GovernanceReview records",
    ),
    ControlMapping(
        "kill_switch",
        "RUN-01/02 operator kill switch",
        ("ASI08", "ASI10"),
        ("MANAGE",),
        ("Art.14", "Art.26"),
        "kill_switch state + audited toggles",
    ),
    ControlMapping(
        "identity_engine",
        "IDN-01/02 signed identity + verification",
        ("ASI03",),
        ("GOVERN",),
        ("Art.15",),
        "EdDSA token verification; forged -> deny (audited)",
    ),
    ControlMapping(
        "interception_coverage",
        "INT-06 no-silent-gaps coverage",
        ("ASI10",),
        ("MEASURE",),
        ("Art.12", "Art.15"),
        "coverage registry + bypass-attempt fail-closed",
    ),
    ControlMapping(
        "audit_chain",
        "AUD-01/02/03 hash-chained decision records + provenance",
        ("ASI08", "ASI10"),
        ("GOVERN", "MEASURE"),
        ("Art.12", "Art.26"),
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
        ("Art.12", "Art.26", "Art.72"),
        "audit_verify re-derivation + RFC-3161 checkpoints",
    ),
    ControlMapping(
        "redaction",
        "AUD-04 fail-closed redaction + secret scan",
        ("ASI02", "ASI06"),
        ("MANAGE",),
        ("Art.10", "Art.12"),
        "redacted payload; no write if redaction fails",
    ),
    # --- Phase-8 guardrail detectors. Live in `enrich()` but never re-exported from
    # `agentos_pipeline.risk.__all__`, which is why the CMP-01/02 coverage lock discovers the
    # scorers enrichment actually RUNS rather than only the ones the package advertises.
    ControlMapping(
        "SecretLeakScorer",
        "SEC-05 secret & credential detector",
        ("ASI03",),
        ("MEASURE", "MANAGE"),
        ("Art.10", "Art.12", "Art.15"),
        "risk findings carrying pattern ids only (never the secret) + the AUD-04 body gate",
    ),
    ControlMapping(
        "ExfiltrationScorer",
        "SEC-04 data-exfiltration detector",
        ("ASI02",),
        ("MEASURE",),
        ("Art.10", "Art.12", "Art.15"),
        "risk findings on the sensitive-data + outbound-destination conjunction",
    ),
    ControlMapping(
        "CodeExecutionScorer",
        "SEC-11 unsafe code-execution detector",
        ("ASI05",),
        ("MEASURE",),
        ("Art.12", "Art.15"),
        "risk findings on the Decision",
    ),
    ControlMapping(
        "MemoryPoisoningScorer",
        "SEC-09 memory-poisoning detector",
        ("ASI06",),
        ("MEASURE",),
        ("Art.12", "Art.15"),
        "risk findings on the Decision",
    ),
    ControlMapping(
        "merkle_evidence",
        "AUD-06 Merkle inclusion proofs + anchored epoch roots",
        ("ASI08", "ASI10"),
        ("GOVERN", "MEASURE"),
        ("Art.12",),
        "RFC-6962 inclusion proof per record, checkable against an RFC-3161-anchored epoch root "
        "without disclosing any other record. Proves INCLUSION, not completeness",
    ),
    ControlMapping(
        "abom",
        "ABOM-01/02 agent bill of materials with per-component provenance",
        ("ASI04",),
        ("GOVERN", "MAP"),
        ("Art.11",),
        "per-component digest, source and version + the window each definition was in force",
    ),
    ControlMapping(
        "sandbox",
        "RUN-03 quarantined sandbox execution",
        ("ASI05",),
        ("MANAGE",),
        ("Art.15",),
        "sandbox_run rows + sandbox_executed audit events",
    ),
    ControlMapping(
        "privilege_rings",
        "RUN-04 privilege rings / least privilege",
        ("ASI03",),
        ("GOVERN", "MANAGE"),
        ("Art.15", "Art.26"),
        "privilege_ring_set events + the per-action ring deny on the Decision",
    ),
    ControlMapping(
        "resource_governor",
        "RUN-05 per-execution resource budgets",
        ("ASI08",),
        ("MANAGE",),
        ("Art.15",),
        "resource_limit_set + resource_limit_exceeded events",
    ),
    ControlMapping(
        "circuit_breaker",
        "RUN-06 automatic circuit breakers",
        ("ASI08",),
        ("MANAGE",),
        ("Art.15",),
        "circuit_tripped / circuit_reset events + breaker state",
    ),
    ControlMapping(
        "emergency_shutdown",
        "RUN-07 fleet-wide emergency stop + explicit resume",
        ("ASI08", "ASI10"),
        ("MANAGE",),
        ("Art.14", "Art.26"),
        "emergency_shutdown / emergency_resume events + the incident row",
    ),
    ControlMapping(
        "consensus",
        "POL-09 multi-party consensus on high-stakes actions",
        ("ASI09",),
        ("GOVERN", "MANAGE"),
        ("Art.14",),
        "consensus_vote per voter + the consensus_resolved round record",
    ),
    ControlMapping(
        "shadow_detection",
        "DISC-04 shadow (unregistered) agent detection",
        ("ASI10",),
        ("MEASURE",),
        ("Art.72",),
        "shadow_agent_detected events (bounded, sanitized claimed id + digest)",
    ),
    ControlMapping(
        "rogue_detection",
        "DISC-05 undeclared-component (rogue) detection",
        ("ASI04", "ASI10"),
        ("MEASURE",),
        ("Art.72",),
        "rogue_agent_detected events — ADVISORY: an undeclared component is an observation an "
        "operator adjudicates, not a decision, because a manifest can simply be stale",
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
        "SecretLeakScorer",
        "ExfiltrationScorer",
        "CodeExecutionScorer",
        "MemoryPoisoningScorer",
    }
)


def _as_utc_naive(moment: datetime | None) -> datetime | None:
    """A range bound in the form the audit column stores.

    `audit_record.created_at` is filled by the server's `now()` and read back UTC-naive on the
    SQLite backend, so an aware bound is CONVERTED to UTC (never truncated — a caller in UTC+14
    asking for "yesterday" must not have its offset dropped) and a naive bound is taken as already
    UTC. Reading a naive bound as local time would shift every operator's window by their own
    offset and silently change the counts an auditor reads."""
    if moment is None or moment.tzinfo is None:
        return moment
    return moment.astimezone(timezone.utc).replace(tzinfo=None)


def _window(start: datetime | None, end: datetime | None) -> dict:
    """The range as an artifact echoes it: the bounds it was given, and what they are scoped on."""
    return {
        "start": start.isoformat() if start is not None else None,
        "end": end.isoformat() if end is not None else None,
        "note": RANGE_NOTE,
    }


def parse_time_bound(text: str | None) -> datetime | None:
    """An ISO-8601 range bound, or None for unbounded. Anything else RAISES.

    Ignoring a bound we cannot parse is the expensive failure: the operator asked for a quarter,
    the export silently drops the bound, and they disclose the entire log with nothing in the
    artifact saying so. Only `None` means unbounded — an empty string is a bound someone typed and
    got wrong, so it is refused rather than read as absence.
    """
    if text is None:
        return None
    try:
        return datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"not an ISO-8601 date/time: {text!r}") from exc


def derive_soc2_evidence(session_factory, start=None, end=None) -> dict:
    """CMP-05 — count the audit evidence backing each Trust Services criterion over a time range.

    DERIVED, NOT ASSERTED: every number comes from the log. A zero means the log contains no such
    record in this window, which is itself evidence — of a quiet period, or of a control that never
    fired — and an auditor is entitled to tell those apart from the range and the totals. So every
    criterion is returned even when all its counts are zero: omitting it would read as "not
    applicable", which is a different claim.

    Two kinds of record are counted. Lifecycle EVENTS carry a `kind`; per-action DECISIONS carry an
    `outcome` and no kind, and are the access-control evidence with by far the most volume. The
    presence of `kind` is the discriminator, so an event body that happens to mention an outcome is
    still counted as the event it is.

    The scan is deliberately UNBOUNDED over the range. Every other bulk read in this codebase is
    capped, because a clipped page is still a usable page — here a clipped count is a WRONG count,
    reported to someone who cannot see that it was clipped. `yield_per` keeps the memory bounded
    instead — passed as an EXECUTION OPTION, not as `Result.yield_per()`, because only the option
    also sets `stream_results`; called on an already-materialized result it sets a buffer size
    after psycopg2 has client-side-buffered every `body` in the log, which is not a memory bound at
    all on the production backend.

    BOTH BOUNDS ARE INCLUSIVE, to the storage granularity of `audit_record.created_at`. On SQLite
    that column is TEXT at one-second resolution while a bound binds with microseconds, so a record
    written in the same second as an exact-second `start` sorts BELOW it and falls outside the
    window; the emitted `range` says so, because an auditor's period almost always starts on a
    whole second.
    """
    from sqlalchemy import select

    from agentos_controlplane.store.models import AuditRecord

    counts = {
        name: dict.fromkeys(criterion["event_kinds"] + criterion["outcomes"], 0)
        for name, criterion in SOC2_CRITERIA.items()
    }
    by_kind: dict[str, list[str]] = {}
    by_outcome: dict[str, list[str]] = {}
    for name, criterion in SOC2_CRITERIA.items():
        for kind in criterion["event_kinds"]:
            by_kind.setdefault(kind, []).append(name)
        for outcome in criterion["outcomes"]:
            by_outcome.setdefault(outcome, []).append(name)

    stmt = select(AuditRecord.body)
    if start is not None:
        stmt = stmt.where(AuditRecord.created_at >= _as_utc_naive(start))
    if end is not None:
        stmt = stmt.where(AuditRecord.created_at <= _as_utc_naive(end))
    with session_factory() as s:
        for (body,) in s.execute(stmt, execution_options={"yield_per": _SCAN_CHUNK}):
            body = body or {}
            key = body.get("kind")
            criteria = by_kind.get(key) if key is not None else None
            if key is None:
                key = body.get("outcome")
                criteria = by_outcome.get(key) if key is not None else None
            for name in criteria or ():
                counts[name][key] += 1

    # The one dimension scoping an auditor-facing count is the one field in the record that is NOT
    # tamper-evident. Saying so here is cheaper than an auditor assuming otherwise.
    window = _window(start, end)
    return {
        name: {
            "name": criterion["name"],
            "criteria": list(criterion["criteria"]),
            "evidence": criterion["evidence"],
            "event_kinds": list(criterion["event_kinds"]),
            "outcomes": list(criterion["outcomes"]),
            "counts": counts[name],
            "total": sum(counts[name].values()),
            "range": window,
            "disclaimer": SOC2_DISCLAIMER,
            "scope": SOC2_SCOPE,
        }
        for name, criterion in SOC2_CRITERIA.items()
    }


def _eu_article_entry(article: str, name: str) -> dict:
    """One article's entry: its heading, the controls bearing on it, and — when there are none —
    the note saying so.

    An article with no controls and no note is the failure this shape exists to prevent: a heading
    with nothing under it reads as an oversight, and an auditor cannot tell "we forgot" from "there
    is genuinely nothing to show". Every article therefore ends up in exactly one of two states,
    and both of them are statements."""
    entry = {
        "name": name,
        "controls": [m.control for m in CONTROL_MAPPINGS if article in m.eu_ai_act],
    }
    note = EU_ARTICLE_NOTES.get(article)
    if note is not None:
        entry["note"] = note
    return entry


def _owasp_section() -> dict:
    return {
        code: {"name": name, "controls": [m.control for m in CONTROL_MAPPINGS if code in m.owasp]}
        for code, name in OWASP_AGENTIC.items()
    }


def _nist_section() -> dict:
    return {fn: [m.control for m in CONTROL_MAPPINGS if fn in m.nist_rmf] for fn in sorted(NIST_RMF)}


def _eu_section() -> dict:
    """The article map with its disclaimer INSIDE it — built here once so the CMP-03 bundle and a
    CMP-06 export cannot ship two versions of the same article set."""
    return {
        "articles": {art: _eu_article_entry(art, name) for art, name in EU_AI_ACT.items()},
        # Article-keyed pointers live INSIDE the disclaimed section, not beside it under a generic
        # `evidence` key: an "Art. 12 / Art. 14" claim lifted out of the bundle is the same
        # lift-and-forward exposure as the article map itself.
        "evidence_pointers": {
            "eu_art12_record_keeping": "hash-chained, per-record-signed, fail-closed-redacted audit log (AUD-01/03/04/08) + Merkle inclusion proofs against anchored epoch roots (AUD-06)",
            # Art. 14 is "Human oversight"; Art. 26 is "Obligations of deployers of high-risk AI
            # systems". These four controls are the oversight mechanisms, so the key names Art. 14
            # — pointing an auditor at the wrong article for the obligation named is precisely the
            # citation error a compliance bundle must not carry.
            "eu_art14_human_oversight": "require_approval + temporary_exception + governance_review + kill switch (POL-07/13/14, RUN-01/02)",
        },
        "disclaimer": EU_AI_ACT_DISCLAIMER,
    }


def _soc2_section() -> dict:
    """The criteria table WITHOUT counts — the mapping half of what `derive_soc2_evidence` returns.

    Disclaimer and scope travel inside each criterion for the same reason they do there: the map has
    no wrapper level, so a single criterion lifted out still says what it is not."""
    return {
        name: {
            "name": criterion["name"],
            "criteria": list(criterion["criteria"]),
            "evidence": criterion["evidence"],
            "event_kinds": list(criterion["event_kinds"]),
            "outcomes": list(criterion["outcomes"]),
            "disclaimer": SOC2_DISCLAIMER,
            "scope": SOC2_SCOPE,
        }
        for name, criterion in SOC2_CRITERIA.items()
    }


def _risk_classifications(session_factory) -> dict:
    """The operator-declared tiers, refused rather than echoed when one is unrecognised.

    LAST GATE, fail-closed — the same discipline as the AUD-04 body scan. The column is a plain
    string on every backend and `Registry.declare_risk_classification` gates only the path that goes
    through it; a value written around it (a future API route, a direct UPDATE, a migration) would
    otherwise be echoed verbatim into a regulator-facing bundle as if it were a recognised tier.
    Refusing to emit the bundle is the honest failure: silently rewriting the value to "undeclared"
    would replace one false statement with a different one — "no operator declared a class for this
    agent".
    """
    from sqlalchemy import select

    from agentos_controlplane.store.models import Agent

    with session_factory() as s:
        declared = s.execute(
            select(Agent.agent_id, Agent.risk_classification).order_by(Agent.agent_id)
        ).all()
    for agent_id, classification in declared:
        if classification is not None and classification not in RISK_CLASSIFICATIONS:
            raise ValueError(
                f"agent {agent_id!r} carries an unrecognised EU AI Act risk classification "
                f"{classification!r}; expected one of {sorted(RISK_CLASSIFICATIONS)} or "
                "NULL (undeclared). Refusing to emit a compliance bundle containing it."
            )
    return {agent_id: classification or UNDECLARED for agent_id, classification in declared}


def export_compliance_evidence(session_factory=None, public_key_pem=None) -> dict:
    """CMP-03/04 — a one-call evidence bundle: the control->framework mapping grouped by framework,
    the EU AI Act article set with the controls bearing on each (and an explicit note where nothing
    does), and pointers to the CONCRETE records behind Art. 12 and Art. 14. When a store is
    supplied, include LIVE evidence: audit-record count, checkpoint count, whether the chain
    currently verifies (AUD-05) — the record-keeping proof itself — and the operator-declared risk
    classification of every registered agent.

    EVIDENCE, NOT A CONFORMITY CLAIM (D-8). Every article reference in this bundle — keyed OR
    tagged, in a key or in a list value — lives under `eu_ai_act`, which carries its disclaimer
    inside itself rather than beside itself. So no sub-object a consumer would plausibly lift
    contains an article reference at all, and the article map cannot be extracted and forwarded
    without the statement of what it is not.

    That sentence used to name `frameworks` and `evidence` and quietly omit `controls`, which
    carried sixty article tags and no disclaimer — four times the article density of the disclaimed
    section, in the exact shape a customer pastes into an audit response. The guarantee is now the
    blunt one and the test enforces it bluntly: no "Art." anywhere outside the disclaimed section."""
    controls = [
        {
            "control": m.control,
            "name": m.name,
            "owasp": list(m.owasp),
            "nist_rmf": list(m.nist_rmf),
            # No `eu_ai_act` here, deliberately. A control->article table with an evidence column IS
            # the compliance-mapping deliverable, and undisclaimed it reads as a self-assessment of
            # conformity. Nothing is lost: `by_eu` is built from these same tuples, so the
            # article->control direction is fully preserved where the disclaimer travels, and
            # control->article is its inverse.
            "evidence": m.evidence,
        }
        for m in CONTROL_MAPPINGS
    ]
    eu_section = _eu_section()
    # `frameworks` deliberately holds only the two taxonomies with no legal weight. The article map
    # appears ONCE, under `eu_ai_act`, so there is no path to it that does not also carry the
    # disclaimer — a second copy here is the obvious sub-object to lift for a "framework coverage"
    # view, and it would forward article->control mappings to a regulator saying nothing about what
    # they are not.
    bundle = {
        "frameworks": {"owasp_agentic_2026": _owasp_section(), "nist_ai_rmf": _nist_section()},
        "eu_ai_act": eu_section,
        "controls": controls,
    }
    if session_factory is not None:
        # Same reasoning as `risk_classifications` below: with no store we know nothing about any
        # fleet, and an empty `evidence: {}` is a claim rather than a silence.
        bundle["evidence"] = {}
        from sqlalchemy import func, select

        from agentos_controlplane.audit_verify import verify_chain
        from agentos_controlplane.store.models import AuditRecord, ChainCheckpoint

        with session_factory() as s:
            bundle["evidence"]["audit_records"] = s.scalar(select(func.count()).select_from(AuditRecord))
            bundle["evidence"]["checkpoints"] = s.scalar(select(func.count()).select_from(ChainCheckpoint))
        # CMP-04. Added ONLY with a registry to read: an empty `risk_classifications: {}` would
        # read as "this fleet has no agents", which is a claim about a fleet we cannot see.
        eu_section["risk_classifications"] = _risk_classifications(session_factory)
        eu_section["risk_classification_source"] = RISK_CLASSIFICATION_SOURCE
        result = verify_chain(session_factory, public_key_pem=public_key_pem)
        bundle["evidence"]["chain_verifies"] = result.ok
    return bundle


def _framework_mapping(framework: str) -> dict:
    """The framework's OWN slice of the mapping and nothing else.

    A bundle that shipped all four would tell a SOC 2 auditor what we map to the EU AI Act, which is
    disclosure they did not ask for and cannot use."""
    if framework == "owasp_agentic_2026":
        return _owasp_section()
    if framework == "nist_ai_rmf":
        return _nist_section()
    if framework == "eu_ai_act":
        return _eu_section()
    return _soc2_section()


def _framework_evidence(framework: str, session_factory, start, end) -> dict:
    """What the audit log DERIVES for this framework over this range.

    SOC 2 gets the criterion counts (CMP-05) and the EU AI Act gets the operator-declared risk
    tiers (CMP-04). The two taxonomies get an explicit note rather than `{}`, for the reason the
    empty EU articles carry one: a silent empty object reads as "no evidence exists", which is a
    different statement from "nothing here aggregates into counts" and a false one."""
    if framework == "soc2":
        return derive_soc2_evidence(session_factory, start, end)
    if framework == "eu_ai_act":
        return {
            "risk_classifications": _risk_classifications(session_factory),
            "risk_classification_source": RISK_CLASSIFICATION_SOURCE,
            "as_of": RISK_CLASSIFICATION_AS_OF,
            "disclaimer": EU_AI_ACT_DISCLAIMER,
        }
    return {"note": _NO_DERIVED_AGGREGATE.format(framework=framework)}


def verifiable_record(bundle: dict, entry: dict) -> dict:
    """Assemble the `merkle.verify_bundle` payload for ONE exported record.

    The epoch roots live ONCE under `bundle["epochs"]` instead of beside every record: an RFC-3161
    token is kilobytes, and copying it next to each of 5000 records turns an evidence bundle into
    tens of megabytes of one repeated string. The join is this function so a recipient never has to
    infer it, and `verification.how_to_verify` states it in prose for anyone not running Python.

    Callers check `entry["inclusion"] is not None` first — an unsealed record has no proof to
    verify, which is what `records_unsealed` counts.
    """
    inclusion = entry["inclusion"]
    return {
        "record": entry["record"],
        "index": inclusion["index"],
        "proof": inclusion["proof"],
        "epoch": bundle["epochs"][str(inclusion["epoch"])],
    }


def bundle_digest(bundle: dict) -> str:
    """sha256 over the canonical JSON of `bundle` with `manifest_digest` removed.

    WHAT IT DETECTS: a bundle edited after export — a record dropped, a count rewritten, a range
    widened. WHAT IT DOES NOT DO: authenticate the exporter. Anyone can alter the content and
    recompute a digest over the result, so a matching digest says only that the artifact is
    internally whole. Authentication comes from the per-record AUD-08 signatures and the externally
    anchored epoch root — which is exactly why both travel INSIDE the bundle rather than being
    summarized by it.
    """
    from agentos_controlplane.audit import canonical_json

    return hashlib.sha256(
        canonical_json({k: v for k, v in bundle.items() if k != "manifest_digest"})
    ).hexdigest()


def export_evidence_bundle(
    framework: str,
    session_factory,
    *,
    start: datetime | None = None,
    end: datetime | None = None,
    public_key_pem=None,
) -> dict:
    """CMP-06 — a per-framework, per-time-range evidence bundle, verifiable standalone.

    WHY THE PROOFS TRAVEL WITH IT. Without them a bundle is an extract: a list of records the
    recipient must take on our word, indistinguishable from one we edited. With an inclusion proof
    per record and an externally anchored root, the recipient recomputes each record's path and
    checks it themselves. That is the difference between disclosure and assertion, and it is what
    makes "evidence" the right word for this artifact.

    WHY IT IS PARTIAL BY CONSTRUCTION. Only the in-range records travel. The rest of the log is
    represented by sibling HASHES inside the proofs, which reveal nothing about their contents — so
    an auditor entitled to Q3 does not receive Q2 as the price of verifying Q3.

    NOTHING IS SILENTLY DROPPED. A record appended after the last seal carries `inclusion: null` and
    is counted in `records_unsealed`; a range larger than the cap is truncated oldest-first with
    `truncated: true` beside the true `records_in_range`. Both would be cheaper to omit and
    expensive to retrofit after someone relied on the bundle.

    NO SEALER ARGUMENT, deliberately: the epochs are read from the same store as the records, so an
    export needs exactly one collaborator and cannot be handed a sealer pointed at a different
    database than the records it proves.
    """
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework!r}; expected one of {list(FRAMEWORKS)}")

    from bisect import bisect_left, bisect_right

    from sqlalchemy import func, select

    from agentos_controlplane.audit_verify import verify_chain
    from agentos_controlplane.merkle import (
        MerkleIntegrityError,
        inclusion_proofs,
        verify_bundle,
    )
    from agentos_controlplane.store.models import AuditRecord, MerkleRoot

    lo, hi = _as_utc_naive(start), _as_utc_naive(end)
    bounds = []
    if lo is not None:
        bounds.append(AuditRecord.created_at >= lo)
    if hi is not None:
        bounds.append(AuditRecord.created_at <= hi)

    epochs: dict[str, dict] = {}
    records: list[dict] = []
    with session_factory() as s:
        in_range = s.scalar(select(func.count()).select_from(AuditRecord).where(*bounds)) or 0
        # Oldest first, so a truncated bundle is a contiguous PREFIX of the window rather than an
        # arbitrary sample the recipient cannot describe.
        rows = s.execute(
            select(
                AuditRecord.seq,
                AuditRecord.record_hash,
                AuditRecord.prev_hash,
                AuditRecord.body,
                AuditRecord.signature,
                AuditRecord.signing_key_id,
            )
            .where(*bounds)
            .order_by(AuditRecord.seq.asc())
            .limit(_MAX_RECORDS)
        ).all()
        seqs = [r.seq for r in rows]
        covering: dict[int, int] = {}
        proofs: dict[int, list] = {}
        if seqs:
            sealed = s.scalars(
                select(MerkleRoot)
                .where(MerkleRoot.seq_start <= seqs[-1], MerkleRoot.seq_end >= seqs[0])
                .order_by(MerkleRoot.epoch.asc())
            ).all()
            # Ascending epoch order + `setdefault`: overlapping rows are reachable by DB write, and
            # which epoch answers must not depend on the engine's row order (as in `disclose`).
            members: dict[int, list[int]] = {}
            for ep in sealed:
                for seq in seqs[bisect_left(seqs, ep.seq_start) : bisect_right(seqs, ep.seq_end)]:
                    if covering.setdefault(seq, ep.epoch) == ep.epoch:
                        members.setdefault(ep.epoch, []).append(seq)
            for ep in sealed:
                if ep.epoch not in members:
                    continue
                # Columns, not entities — one string per leaf, never the bodies of the records we
                # are NOT disclosing.
                leaves = list(
                    s.scalars(
                        select(AuditRecord.record_hash)
                        .where(AuditRecord.seq >= ep.seq_start, AuditRecord.seq <= ep.seq_end)
                        .order_by(AuditRecord.seq.asc())
                    ).all()
                )
                if len(leaves) != ep.leaf_count:
                    raise MerkleIntegrityError(
                        f"epoch {ep.epoch} covers {len(leaves)} of its stated {ep.leaf_count} "
                        "records — records were deleted from under a sealed root"
                    )
                indices = [seq - ep.seq_start for seq in members[ep.epoch]]
                paths = inclusion_proofs(leaves, indices)
                for seq, index in zip(members[ep.epoch], indices):
                    # Lists, not tuples: the artifact is JSON, and a proof that changes shape on the
                    # round trip is a proof the recipient's digest disagrees with.
                    proofs[seq] = [index, [list(step) for step in paths[index]]]
                epochs[str(ep.epoch)] = {
                    "epoch": ep.epoch,
                    "seq_start": ep.seq_start,
                    "seq_end": ep.seq_end,
                    "root": ep.root,
                    "leaf_count": ep.leaf_count,
                    "anchor_kind": ep.anchor_kind,
                    "anchor_proof": ep.proof.hex() if ep.proof is not None else None,
                    "tsa_url": ep.tsa_url,
                    "anchored": ep.proof is not None,
                }
        for r in rows:
            inclusion = None
            if r.seq in proofs:
                index, path = proofs[r.seq]
                inclusion = {"index": index, "proof": path, "epoch": covering[r.seq]}
            records.append(
                {
                    # The seq is NOT hoisted beside `record`. A copy outside the hashed body is a
                    # number nothing authenticates, and a recipient filtering on it could be shown
                    # one seq while verifying another.
                    "record": {
                        "seq": r.seq,
                        "record_hash": r.record_hash,
                        "prev_hash": r.prev_hash,
                        "body": r.body,
                        "signature": r.signature,
                        "signing_key_id": r.signing_key_id,
                    },
                    "inclusion": inclusion,
                }
            )

    included = [e for e in records if e["inclusion"] is not None]
    # `ok` alone would over-report: with no public key the pass re-derives the hash linkage and
    # verifies NO signature, and `chain_verifies: true` beside nothing else reads as "signatures
    # checked". The count is what the pass actually did, so a zero is legible as a zero.
    chain = verify_chain(session_factory, public_key_pem=public_key_pem)
    bundle = {
        "framework": framework,
        "range": _window(start, end),
        "mapping": _framework_mapping(framework),
        "derived_evidence": _framework_evidence(framework, session_factory, start, end),
        "epochs": epochs,
        "records": records,
        "verification": {
            "chain_verifies": chain.ok,
            "chain_signatures_checked": chain.signatures_checked,
            "records_in_range": in_range,
            "records_exported": len(records),
            "records_included": len(included),
            "records_unsealed": len(records) - len(included),
            "records_anchored": sum(
                1 for e in included if epochs[str(e["inclusion"]["epoch"])]["anchored"]
            ),
            "truncated": in_range > len(records),
            "how_to_verify": list(HOW_TO_VERIFY),
        },
        "disclaimer": EVIDENCE_BUNDLE_DISCLAIMER,
    }
    # Verified BEFORE it leaves, the same posture as `MerkleSealer.disclose`: a record edited or
    # deleted from under a sealed root produces a success-shaped bundle the recipient cannot verify,
    # and to an auditor an unverifiable proof reads as tampering rather than as our bug.
    for entry in included:
        result = verify_bundle(verifiable_record(bundle, entry), public_key_pem=public_key_pem)
        if not result.ok:
            raise MerkleIntegrityError(
                f"refusing to export seq {entry['record']['seq']}: {result.reason}"
            )
    bundle["manifest_digest"] = bundle_digest(bundle)
    return bundle


def _main(argv=None) -> int:
    import argparse
    import json

    from sqlalchemy import create_engine

    from agentos_controlplane.store.engine import create_session_factory

    p = argparse.ArgumentParser(
        prog="agentos_controlplane.compliance",
        description="Export the compliance evidence bundle (CMP-03) or a CMP-06 evidence bundle.",
    )
    p.add_argument("--db", help="SQLite path / SQLAlchemy URL to include live audit evidence")
    p.add_argument("--pubkey", help="control-plane public-key PEM (enables chain signature verify)")
    p.add_argument("--framework", choices=FRAMEWORKS, help="CMP-06: export this framework's bundle")
    p.add_argument("--start", help="CMP-06 range start, ISO-8601")
    p.add_argument("--end", help="CMP-06 range end, ISO-8601")
    p.add_argument("--out", help="CMP-06: write the bundle here (default: stdout)")
    args = p.parse_args(argv)
    sf = None
    if args.db:
        url = args.db if "://" in args.db else f"sqlite+pysqlite:///{args.db}"
        sf = create_session_factory(create_engine(url))
    pub = open(args.pubkey, encoding="utf-8").read() if args.pubkey else None
    if args.framework is None:
        # Refused, not ignored: a range silently dropped because the wrong subcommand was implied is
        # the same over-disclosure as a range silently dropped because the date would not parse.
        if args.start or args.end or args.out:
            p.error("--start/--end/--out apply to a --framework export only")
        print(json.dumps(export_compliance_evidence(sf, public_key_pem=pub), indent=2, default=str))
        return 0
    if sf is None:
        p.error("--framework needs --db: a bundle without the records it is evidence FROM is not evidence")
    try:
        bundle = export_evidence_bundle(
            args.framework,
            sf,
            start=parse_time_bound(args.start),
            end=parse_time_bound(args.end),
            public_key_pem=pub,
        )
    except ValueError as exc:
        p.error(str(exc))
    text = json.dumps(bundle, indent=2)
    if args.out:
        from pathlib import Path

        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
