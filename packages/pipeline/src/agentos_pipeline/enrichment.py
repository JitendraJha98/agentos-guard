"""Deterministic pre-policy enrichment (SEC-12, D6). Pure CPU, sub-ms, stateless.

Runs as pipeline stage 2 (identity -> ENRICHMENT -> policy -> risk -> graduated):
its outputs are first-class policy-input fields (D4), so principles can condition
on `intent.class` and the guardrail flags. Intent classes are a small closed
vocabulary; matching is exact/prefix on the normalized target (lower/strip) +
the memory operation — NO regex, NO models.

The guardrail flags are REAL since Slice 4 (SEC-02): the PII / unsafe-content /
format-violation scorers run ONCE here (pre-policy, pure CPU, deterministic).
`Enrichment` carries both the derived boolean flags (the policy-input fields
principle 3.2 conditions on) and the typed findings themselves, which stage 4
merges into the risk score via the aggregator's `extra_findings` — the scorers
are never re-run.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentos_contract import ActionType, AgentAction, RiskFinding


@dataclass(frozen=True)
class Enrichment:
    intent_class: str | None
    guardrails: dict[str, bool]                        # real detectors (SEC-02)
    guardrail_findings: tuple[RiskFinding, ...] = ()   # merged into stage-4 risk


# The tagger's full output vocabulary — what principle authors may condition on.
# Note: 2.1's DATA_EXFILTRATION is principle-referenced but not yet tagger-emitted
# (Slice 4 may extend this set).
INTENT_CLASSES = frozenset({"DATA_DESTRUCTION", "RESOURCE_RENAME"})

_DESTRUCTION_EXACT = frozenset({"rm", "drop", "delete", "truncate"})
# No "remove_": it false-positives (remove_formatting / remove_duplicates).
_DESTRUCTION_PREFIX = ("drop_", "delete_", "truncate_")
_RENAME_EXACT = frozenset({"mv", "rename", "move"})
_RENAME_PREFIX = ("rename_", "move_", "mv_")


def tag_intent(action: AgentAction) -> str | None:
    """Tag the action's coarse intent class (SEC-12) — or None when untagged."""
    if (
        action.type is ActionType.memory_access
        and str(action.payload.get("operation", "")).lower() == "delete"
    ):
        return "DATA_DESTRUCTION"
    t = action.target.strip().lower()
    if t in _DESTRUCTION_EXACT or t.startswith(_DESTRUCTION_PREFIX):
        return "DATA_DESTRUCTION"
    if t in _RENAME_EXACT or t.startswith(_RENAME_PREFIX):
        return "RESOURCE_RENAME"
    return None


# Imported BELOW tag_intent deliberately: `agentos_pipeline.risk.__init__` pulls
# in IntentScorer, which imports tag_intent from THIS module — so the scorer
# imports must run after tag_intent exists for either entry point of the cycle
# to resolve.
from agentos_pipeline.risk.format_check import FormatViolationScorer  # noqa: E402
from agentos_pipeline.risk.pii import PiiScorer  # noqa: E402
from agentos_pipeline.risk.unsafe_content import UnsafeContentScorer  # noqa: E402

# Stateless, patterns compiled once as class attributes — instantiate ONCE.
_GUARDRAIL_SCORERS = (PiiScorer(), UnsafeContentScorer(), FormatViolationScorer())

_FLAG_BY_CATEGORY = {"pii": "pii", "unsafe_content": "unsafe", "format_violation": "format"}


def enrich(action: AgentAction) -> Enrichment:
    """Build the full enrichment document the policy-input builder consumes (D4)."""
    findings = tuple(s.score(action) for s in _GUARDRAIL_SCORERS)
    flags = {"pii": False, "unsafe": False, "format": False}
    for finding in findings:
        if finding.matched:
            flags[_FLAG_BY_CATEGORY[finding.category]] = True
    return Enrichment(
        intent_class=tag_intent(action),
        guardrails=flags,
        guardrail_findings=findings,
    )
