"""build_policy_input — the versioned D4 policy-input builder (Slice 3).

This builder and `agentos_contract.policy_io.POLICY_INPUT_FIELDS` are the SAME
versioned schema (POLICY_INPUT_SCHEMA_VERSION): `when.field` in a Constitution
may reference only registry paths, and this builder emits exactly those paths
for each action type — every applicable field is ALWAYS present, with ""/False/[]
defaults, never an absent key (deliberate fail-closed semantics: an unparseable
URL yields egress.host == "", which is in no allowlist, so a not_in allowlist
principle fires -> deny, mirroring the Phase-1 _host behavior).

`sequence.matched_refs` is always [] in this slice — the Slice-7 sequence
correlator populates it.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from agentos_contract import ActionType, AgentAction
from agentos_contract.policy_io import POLICY_INPUT_SCHEMA_VERSION  # noqa: F401  (the shared schema version)

from agentos_pipeline.enrichment import Enrichment


def _host(action: AgentAction) -> str:
    """Parse the host from the `url` in the action payload.

    A missing/unparseable URL yields an empty host — which a deny-by-default
    egress principle (`egress.host not_in allowlist`) correctly DENIES. Never
    silently fail open (Pitfall 3): an unknown host is treated as
    not-allowlisted, not as allowed.
    """
    url = (action.payload or {}).get("url", "")
    return urlsplit(url).hostname or ""


def build_policy_input(
    action: AgentAction,
    enrichment: Enrichment,
    sequence_matched_refs: tuple[str, ...] = (),
) -> dict:
    """Emit the complete D4 policy-input document for one action."""
    payload = action.payload or {}
    doc: dict = {
        "type": action.type.value,
        "target": action.target,
        "intent": {"class": enrichment.intent_class or ""},
        # dict(enrichment.guardrails) already carries every derived flag — pii/unsafe/
        # format plus the Phase-8 secret/exfiltration/code_exec/memory_poison flags —
        # so a constitution principle can condition on any of them with no builder change.
        "guardrails": dict(enrichment.guardrails),
        # SEC-13: the SequenceCorrelator's matches — compiled membership rules
        # turn these refs into REAL fired principles (deterministic floor).
        "sequence": {"matched_refs": list(sequence_matched_refs)},
    }
    if action.type is ActionType.tool_call:
        doc["egress"] = {"host": _host(action)}
    elif action.type is ActionType.mcp_call:
        doc["mcp"] = {
            "server": str(payload.get("server", "")),
            "tool": str(payload.get("tool", "")),
        }
        doc["egress"] = {"host": _host(action)}
    elif action.type is ActionType.memory_access:
        doc["memory"] = {
            "operation": str(payload.get("operation", "")),
            "key": str(payload.get("key", "")),
        }
    elif action.type is ActionType.delegation:
        doc["delegation"] = {"to_agent": str(payload.get("to_agent", ""))}
    else:  # ActionType.model_invocation
        doc["model"] = {"name": str(payload.get("model", ""))}
    return doc
