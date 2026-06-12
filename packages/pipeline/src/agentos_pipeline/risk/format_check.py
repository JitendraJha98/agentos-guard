"""FormatViolationScorer — the SEC-02 inline, deterministic format guardrail.

It implements the RiskScorer Protocol (agentos_contract) and returns a typed
RiskFinding (category "format_violation"). Unlike the text scorers it walks the
payload STRUCTURE (values + nesting), not a joined text surface — a structural
anomaly (NUL bytes, megabyte values, pathological nesting) is a malformed-input
signal regardless of content.

INVARIANTS (tested):
  - inline=True, pure CPU, bounded; no catastrophic backtracking. NO model, NO
    network, NO LLM on the hot path (P0-killer Pitfall 1). stdlib only; the walk
    is ITERATIVE (a hostile deeply-nested payload cannot blow the recursion
    limit) and inspects dict KEYS as well as values (keys are attacker-controlled
    strings too).
  - Per-string inspection is capped at 32 KiB (the shared deterministic budget):
    a string longer than the cap is ALREADY an `oversized_value` finding, so
    scanning its tail for control chars adds nothing.
  - matched holds pattern IDs only ("control_chars", "oversized_value",
    "excessive_nesting") — never raw payload.
  - Advisory only: 0.2 when matched — below the 0.4 sandbox band by design
    (format anomalies corroborate; they never gate alone).
"""

import re

from agentos_contract import AgentAction, RiskFinding

_FORMAT_RISK = 0.2          # advisory: < sandbox_at (0.4) by design
_MAX_VALUE_LEN = 32_768     # single string value longer than this is anomalous
_MAX_DEPTH = 8              # dict/list nesting deeper than this is anomalous

# C0 control characters EXCLUDING the legitimate whitespace \t \n \r — a single
# precompiled character class (C-level scan, ~20x faster than a per-char Python
# loop on wide payloads; trivially backtracking-free).
_FORBIDDEN_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class FormatViolationScorer:
    """Slice-4 inline detector: structural payload anomalies, no model, no I/O."""

    name = "format.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        matched: list[str] = []
        control_chars = oversized = too_deep = False

        # Iterative walk (no recursion — hostile nesting depth is the very thing
        # being detected). Each stack entry is (node, depth); the payload dict
        # itself is depth 1.
        stack: list[tuple[object, int]] = [(action.payload or {}, 1)]
        while stack:
            node, depth = stack.pop()
            if depth > _MAX_DEPTH:
                too_deep = True
                continue  # deep enough — no need to walk further down this branch
            if isinstance(node, dict):
                # Keys are attacker-controlled strings too ({"bad\x00key": ...}).
                stack.extend((key, depth + 1) for key in node.keys())
                stack.extend((child, depth + 1) for child in node.values())
            elif isinstance(node, (list, tuple)):
                stack.extend((child, depth + 1) for child in node)
            elif isinstance(node, str):
                if len(node) > _MAX_VALUE_LEN:
                    oversized = True
                elif not control_chars and _FORBIDDEN_CONTROL_RE.search(node):
                    control_chars = True

        if control_chars:
            matched.append("control_chars")
        if oversized:
            matched.append("oversized_value")
        if too_deep:
            matched.append("excessive_nesting")

        return RiskFinding(
            scorer=self.name,
            category="format_violation",
            risk_score=_FORMAT_RISK if matched else 0.0,
            matched=matched,
            detail="; ".join(matched) or "no format violations",
            inline=True,
        )
