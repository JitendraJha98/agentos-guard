"""Deterministic pre-policy enrichment (SEC-12, D6). Pure CPU, sub-ms, stateless.

Runs as pipeline stage 2 (identity -> ENRICHMENT -> policy -> risk -> graduated):
its outputs are first-class policy-input fields (D4), so principles can condition
on `intent.class` and the guardrail flags. Intent classes are a small closed
vocabulary; matching is exact/prefix on the normalized target (lower/strip) +
the memory operation — NO regex, NO models.

The guardrail flags are a SEAM in this slice: always
{pii: False, unsafe: False, format: False} — the real detectors land in Slice 4
(SEC-02). Intent tagging is real now.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentos_contract import ActionType, AgentAction


@dataclass(frozen=True)
class Enrichment:
    intent_class: str | None
    guardrails: dict[str, bool]  # real detectors land in Slice 4 (SEC-02)


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


def enrich(action: AgentAction) -> Enrichment:
    """Build the full enrichment document the policy-input builder consumes (D4)."""
    return Enrichment(
        intent_class=tag_intent(action),
        guardrails={"pii": False, "unsafe": False, "format": False},
    )
