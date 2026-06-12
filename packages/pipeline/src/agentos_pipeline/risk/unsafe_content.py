"""UnsafeContentScorer — the SEC-02 inline, deterministic unsafe-content detector.

It implements the RiskScorer Protocol (agentos_contract) and returns a typed
RiskFinding (category "unsafe_content").

INVARIANTS (tested):
  - inline=True, pure CPU, sub-ms. NO model, NO network, NO LLM on the hot path
    (P0-killer Pitfall 1). stdlib re only.
  - Patterns compiled ONCE as class attributes (never per-call) with BOUNDED
    quantifiers (ReDoS-safe, Pitfall 2).
  - Inspected text is the raw 32 KiB-capped payload join (_text.payload_text);
    truncation is recorded in `detail` so a past-cap match is auditable, not
    silently missed.
  - matched holds pattern IDs only ("destructive_shell", "destructive_sql",
    "fork_bomb") — never raw payload (the RiskFinding validator enforces this).
  - Advisory only: 0.45 when matched — the sandbox band (0.4–0.7). The detector
    can only CONTRIBUTE risk, never relax the deterministic policy floor.
"""

import re

from agentos_contract import AgentAction, RiskFinding

from agentos_pipeline.risk._text import payload_text

_UNSAFE_RISK = 0.45  # sandbox band (0.4 <= risk < 0.7) by design


class UnsafeContentScorer:
    """Slice-4 inline detector: destructive shell/SQL heuristics, no model, no I/O."""

    name = "unsafe_content.v1"
    inline = True

    # Patterns compiled ONCE at class definition (never per-call - Pitfall 2, ReDoS-safe).
    # Bounded quantifiers only; no nested unbounded groups.
    _DESTRUCTIVE_SHELL = re.compile(
        r"\brm\s+-[rf]{1,4}\b"
        r"|remove-item\s+.{0,40}-recurse"
        r"|\bmkfs\b"
        r"|\bdd\s+if=",
        re.IGNORECASE,
    )
    _DESTRUCTIVE_SQL = re.compile(
        r"\bdrop\s+table\b|\btruncate\s+table\b", re.IGNORECASE
    )
    _FORK_BOMB = re.compile(re.escape(":(){ :|:& };:"))

    def score(self, action: AgentAction) -> RiskFinding:
        text, truncated = payload_text(action)
        matched: list[str] = []
        if self._DESTRUCTIVE_SHELL.search(text):
            matched.append("destructive_shell")
        if self._DESTRUCTIVE_SQL.search(text):
            matched.append("destructive_sql")
        if self._FORK_BOMB.search(text):
            matched.append("fork_bomb")

        detail = "; ".join(matched) or "no unsafe-content patterns matched"
        if truncated:
            detail += " (input truncated at 32 KB)"

        return RiskFinding(
            scorer=self.name,
            category="unsafe_content",
            risk_score=_UNSAFE_RISK if matched else 0.0,
            matched=matched,
            detail=detail,
            inline=True,
        )
