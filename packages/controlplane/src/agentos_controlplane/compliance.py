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

from dataclasses import dataclass
from datetime import datetime, timezone

# Rows per round trip while streaming the audit log for SOC 2 counts — memory bound, not a result
# bound (the count itself is never clipped).
_SCAN_CHUNK = 1000

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

    window = {
        "start": start.isoformat() if start is not None else None,
        "end": end.isoformat() if end is not None else None,
        # The one dimension scoping an auditor-facing count is the one field in the record that is
        # NOT tamper-evident. Saying so here is cheaper than an auditor assuming otherwise.
        "note": (
            "Both bounds inclusive. Filtered on audit_record.created_at — the server clock at "
            "insert, which the record hash and the AUD-08 signature do NOT cover (the chain's own "
            "ordering is `seq`), so the window is administrative metadata rather than "
            "tamper-evident. Inclusive only to that column's storage granularity: on SQLite it is "
            "one second, so a record written in the same second as an exact-second `start` falls "
            "outside the window."
        ),
    }
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


def export_compliance_evidence(session_factory=None, public_key_pem=None) -> dict:
    """CMP-03/04 — a one-call evidence bundle: the control->framework mapping grouped by framework,
    the EU AI Act article set with the controls bearing on each (and an explicit note where nothing
    does), and pointers to the CONCRETE records behind Art. 12 and Art. 14. When a store is
    supplied, include LIVE evidence: audit-record count, checkpoint count, whether the chain
    currently verifies (AUD-05) — the record-keeping proof itself — and the operator-declared risk
    classification of every registered agent.

    EVIDENCE, NOT A CONFORMITY CLAIM (D-8). Everything article-keyed lives under `eu_ai_act`, which
    carries its disclaimer inside itself rather than beside itself — so no sub-object a consumer
    would plausibly lift (`frameworks`, `evidence`) contains an article reference at all, and the
    article map cannot be extracted and forwarded without the statement of what it is not."""
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
        art: _eu_article_entry(art, name) for art, name in EU_AI_ACT.items()
    }
    eu_section: dict = {
        "articles": by_eu,
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
    # `frameworks` deliberately holds only the two taxonomies with no legal weight. The article map
    # appears ONCE, under `eu_ai_act`, so there is no path to it that does not also carry the
    # disclaimer — a second copy here is the obvious sub-object to lift for a "framework coverage"
    # view, and it would forward article->control mappings to a regulator saying nothing about what
    # they are not.
    bundle = {
        "frameworks": {"owasp_agentic_2026": by_owasp, "nist_ai_rmf": by_nist},
        "eu_ai_act": eu_section,
        "controls": controls,
    }
    if session_factory is not None:
        # Same reasoning as `risk_classifications` below: with no store we know nothing about any
        # fleet, and an empty `evidence: {}` is a claim rather than a silence.
        bundle["evidence"] = {}
        from sqlalchemy import func, select

        from agentos_controlplane.audit_verify import verify_chain
        from agentos_controlplane.store.models import Agent, AuditRecord, ChainCheckpoint

        with session_factory() as s:
            bundle["evidence"]["audit_records"] = s.scalar(select(func.count()).select_from(AuditRecord))
            bundle["evidence"]["checkpoints"] = s.scalar(select(func.count()).select_from(ChainCheckpoint))
            # CMP-04. Added ONLY with a registry to read: an empty `risk_classifications: {}` would
            # read as "this fleet has no agents", which is a claim about a fleet we cannot see.
            declared = s.execute(
                select(Agent.agent_id, Agent.risk_classification).order_by(Agent.agent_id)
            ).all()
            # LAST GATE, fail-closed — the same discipline as the AUD-04 body scan. The column is a
            # plain string on every backend and `Registry.declare_risk_classification` gates only
            # the path that goes through it; a value written around it (a future API route, a
            # direct UPDATE, a migration) would otherwise be echoed verbatim into a
            # regulator-facing bundle as if it were a recognised tier. Refusing to emit the bundle
            # is the honest failure: silently rewriting the value to "undeclared" would replace one
            # false statement with a different one — "no operator declared a class for this agent".
            for agent_id, classification in declared:
                if classification is not None and classification not in RISK_CLASSIFICATIONS:
                    raise ValueError(
                        f"agent {agent_id!r} carries an unrecognised EU AI Act risk classification "
                        f"{classification!r}; expected one of {sorted(RISK_CLASSIFICATIONS)} or "
                        "NULL (undeclared). Refusing to emit a compliance bundle containing it."
                    )
            eu_section["risk_classifications"] = {
                agent_id: classification or UNDECLARED for agent_id, classification in declared
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
