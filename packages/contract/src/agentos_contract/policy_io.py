"""D4 policy I/O contract — the seam shared by the constitution compiler (Slice 2),
the policy engine/runner (Slice 3), and the interpreter trigger (Slice 5).

The INPUT registry is versioned: `when.field` in a Constitution may reference only
these dotted paths, and `build_policy_input` (Slice 3) emits exactly this shape.
OUTCOME_RESTRICTIVENESS is the single restrictiveness order (graduated._RANK
consolidates onto it in Slice 3)."""

from dataclasses import dataclass

from agentos_contract.decision import Outcome

POLICY_INPUT_SCHEMA_VERSION = 1

# field -> (python type, action types it applies to; "all" = every type)
POLICY_INPUT_FIELDS: dict[str, tuple[type, frozenset[str] | str]] = {
    "type": (str, "all"),
    "target": (str, "all"),
    "intent.class": (str, "all"),
    "guardrails.pii": (bool, "all"),
    "guardrails.unsafe": (bool, "all"),
    "guardrails.format": (bool, "all"),
    # Phase-8 detector flags — principle authors may condition on these. Each is
    # added here in lockstep with the enrich() flag that emits it (drift-locked by
    # test_builder_emits_exactly_the_registry_fields_for_every_type).
    "guardrails.secret": (bool, "all"),           # SEC-05 secret/credential leak
    "guardrails.exfiltration": (bool, "all"),     # SEC-04 sensitive data to an external host
    "guardrails.code_exec": (bool, "all"),        # SEC-11 unsafe dynamic code/command execution (ASI05)
    "guardrails.memory_poison": (bool, "all"),    # SEC-09 memory/context poisoning (ASI06)
    "sequence.matched_refs": (list, "all"),
    # ECON-02 economics fields — the FIRST numeric fields in this registry, so they are also the
    # first live consumers of the gte/lte operators the schema and compiler have carried since
    # Phase 3. Added in lockstep with the builder (drift-locked by
    # test_builder_emits_exactly_the_registry_fields_for_every_type). Scoped "all" because a
    # runaway agent burns its budget through tool and MCP calls as readily as through the model.
    "cost.spend_usd": (float, "all"),          # spend inside the agent's window; 0.0 if unbudgeted
    "cost.budget_used_ratio": (float, "all"),  # 0.0 when NO budget is configured (not a breach)
    "egress.host": (str, frozenset({"tool_call", "mcp_call"})),
    "memory.operation": (str, frozenset({"memory_access"})),
    "memory.key": (str, frozenset({"memory_access"})),
    "mcp.server": (str, frozenset({"mcp_call"})),
    "mcp.tool": (str, frozenset({"mcp_call"})),
    "delegation.to_agent": (str, frozenset({"delegation"})),
    "model.name": (str, frozenset({"model_invocation"})),
}

# Single source of restrictiveness (ties: governance_review/temporary_exception both
# "proceed with oversight"). deny is maximal; allow minimal.
OUTCOME_RESTRICTIVENESS: dict[Outcome, int] = {
    Outcome.allow: 0,
    Outcome.warn: 1,
    Outcome.governance_review: 2,
    Outcome.temporary_exception: 2,
    Outcome.sandbox: 3,
    Outcome.require_consensus: 4,
    Outcome.require_approval: 5,
    Outcome.deny: 6,
}

# POL-13: temporary_exception is human-ratified only — never authorable as an effect.
AUTHORABLE_EFFECTS: frozenset[str] = frozenset(
    o.value for o in Outcome if o is not Outcome.temporary_exception
)


@dataclass(frozen=True)
class MatchedPrinciple:
    """One fired principle from the deterministic floor (provenance for Reason)."""
    principle_ref: str
    effect: str
    evidence: dict | None = None


@dataclass(frozen=True)
class ConstitutionResult:
    """The policy-result v2 contract — the structured verdict of the compiled constitution."""
    matched: tuple[MatchedPrinciple, ...]
    no_match: bool


def select_floor(matched: list[MatchedPrinciple] | tuple[MatchedPrinciple, ...]) -> Outcome | None:
    """Deny-overrides-allow: the most restrictive matched effect is the floor.
    Returns None on no match — that floor is the per-action-class posture (PIPE-05)."""
    if not matched:
        return None
    return max((Outcome(m.effect) for m in matched), key=OUTCOME_RESTRICTIVENESS.__getitem__)
