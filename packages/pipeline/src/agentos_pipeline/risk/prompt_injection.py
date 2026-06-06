"""PromptInjectionScorer - the SEC-01 inline, deterministic prompt-injection detector.

Source: 01-AI-SPEC.md S3 (pattern set) + S4 (bounded-input strategy). It implements
the RiskScorer Protocol (agentos_contract) and returns a typed RiskFinding.

INVARIANTS (tested):
  - inline=True, pure CPU, sub-ms. NO model, NO network, NO LLM on the hot path
    (P0-killer Pitfall 1). stdlib re only.
  - Patterns compiled ONCE as class attributes (never per-call) with BOUNDED
    quantifiers (ReDoS-safe, Pitfall 2).
  - Inspected text is normalize()d FIRST (trivial-obfuscation mitigation) and capped
    at 32 KB; truncation is recorded in `detail` so a past-cap injection is auditable,
    not silently missed (AI-SPEC S4 "Context Window Strategy").
  - matched holds pattern IDs only - never raw payload (the RiskFinding validator from
    plan 01-01 enforces this; threat T-01-11).
  - Advisory only: it can only CONTRIBUTE risk, never relax the deterministic policy
    floor (the floor lives in the graduated stage, plan 01-05).
"""

import re

from agentos_contract import AgentAction, RiskFinding

from agentos_pipeline.risk.normalize import normalize

# Cap inspected content so a hostile multi-megabyte page cannot turn the sub-ms regex
# pass into a latency/memory problem (AI-SPEC S4). 32 KiB, deterministic byte budget.
_MAX_INSPECT_BYTES = 32 * 1024


class PromptInjectionScorer:
    """Phase-1 inline detector: deterministic regex heuristics, no model, no I/O."""

    name = "prompt_injection.v1"
    inline = True

    # Patterns compiled ONCE at class definition (never per-call - Pitfall 2, ReDoS-safe).
    # Bounded quantifiers only ([^.\n]{0,N}); no nested unbounded groups.
    _OVERRIDE = re.compile(
        r"\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|all)\b"
        r"[^.\n]{0,20}\b(instruction|prompt|rule|constraint)s?\b",
        re.IGNORECASE,
    )
    _ROLE_HIJACK = re.compile(
        r"\b(you\s+are\s+now|developer\s+mode|system\s+override|act\s+as)\b",
        re.IGNORECASE,
    )
    _EXFIL = re.compile(
        r"\b(send|post|exfiltrate|upload|leak|fetch)\b[^.\n]{0,60}"
        r"(https?://|api[_\s-]?key|secret|token|credential)",
        re.IGNORECASE,
    )

    def score(self, action: AgentAction) -> RiskFinding:
        text, truncated = self._inspect_text(action)
        matched: list[str] = []
        if self._OVERRIDE.search(text):
            matched.append("instruction_override")
        if self._ROLE_HIJACK.search(text):
            matched.append("role_hijack")
        if self._EXFIL.search(text):
            matched.append("exfil_directive")

        risk_score = 0.0 if not matched else min(1.0, 0.4 + 0.3 * len(matched))

        detail = "; ".join(matched) or "no injection patterns matched"
        if truncated:
            detail += " (input truncated at 32 KB)"

        return RiskFinding(
            scorer=self.name,
            category="prompt_injection",
            risk_score=risk_score,
            matched=matched,
            detail=detail,
            inline=True,
        )

    @staticmethod
    def _inspect_text(action: AgentAction) -> tuple[str, bool]:
        """Join the action payload values, cap at 32 KB, normalize FIRST.

        Returns (normalized_text, truncated). Truncation is computed on the raw joined
        bytes (deterministic byte budget) BEFORE normalization, so the cap is stable and
        a localized injection planted past the cap is reported via `detail`, not silently
        scanned (silent under-coverage is Critical Failure Mode 5).
        """
        parts = [str(v) for v in (action.payload or {}).values()]
        raw = "\n".join(parts)
        encoded = raw.encode("utf-8")
        truncated = len(encoded) > _MAX_INSPECT_BYTES
        if truncated:
            # Decode the byte-budgeted prefix; drop any partial trailing multibyte char.
            raw = encoded[:_MAX_INSPECT_BYTES].decode("utf-8", "ignore")
        return normalize(raw), truncated
