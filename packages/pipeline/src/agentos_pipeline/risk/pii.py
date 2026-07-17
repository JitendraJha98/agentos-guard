"""PiiScorer — the SEC-02 inline, deterministic PII detector.

It implements the RiskScorer Protocol (agentos_contract) and returns a typed
RiskFinding (category "pii").

INVARIANTS (tested):
  - inline=True, pure CPU, bounded, no catastrophic backtracking (adversarial
    32 KB inputs measured low-single-digit ms). NO model, NO network, NO LLM on
    the hot path (P0-killer Pitfall 1). stdlib re only.
  - Patterns compiled ONCE as class attributes (never per-call) with BOUNDED
    quantifiers (ReDoS-safe, Pitfall 2).
  - Inspected text is the raw 32 KiB-capped payload join (_text.payload_text —
    NO normalize(): PII patterns match literal separators); truncation is
    recorded in `detail` so a past-cap match is auditable, not silently missed.
  - Credit-card candidates are IIN-guarded (first digit 2-6) then Luhn-verified —
    a 16-digit string alone is not a finding, and Luhn-passing digit runs that
    start "1" (epoch-ms timestamps, snowflake IDs) are not cards.
  - matched holds pattern IDs only ("email", "ssn", "credit_card", "phone") —
    never raw values (the RiskFinding validator enforces this; threat T-01-11).
  - Advisory only: 0.35 when matched — below the 0.4 sandbox band by design.
    PII to an *allowlisted* host stays allow; the 3.2 constitution floor does
    the denying when the host isn't approved.
"""

import re

from agentos_contract import AgentAction, RiskFinding

from agentos_pipeline.risk._text import payload_text

_PII_RISK = 0.35  # advisory: < sandbox_at (0.4) by design — the 3.2 floor denies


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum over a digit string."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class PiiScorer:
    """Slice-4 inline detector: deterministic PII regex heuristics, no model, no I/O."""

    name = "pii.v1"
    inline = True

    # Patterns compiled ONCE at class definition (never per-call - Pitfall 2, ReDoS-safe).
    # Bounded quantifiers only; no nested unbounded groups.
    _EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}")
    _SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    # Card CANDIDATES only — each is Luhn-checked before it becomes a finding.
    _CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
    _PHONE = re.compile(r"\+\d{7,15}\b|\(\d{3}\)\s?\d{3}-\d{4}")

    @classmethod
    def find_pii(cls, text: str) -> list[str]:
        """The PII pattern IDs present in `text` (never raw values).

        Extracted from `score` so the SEC-04 exfiltration scorer can reuse the
        exact same PII definition rather than a divergent copy.
        """
        matched: list[str] = []
        if cls._EMAIL.search(text):
            matched.append("email")
        if cls._SSN.search(text):
            matched.append("ssn")
        for candidate in cls._CARD_CANDIDATE.findall(text):
            digits = re.sub(r"[ -]", "", candidate)
            # IIN guard BEFORE Luhn: real card networks issue first digits 2-6
            # only. 13-19-digit runs starting "1" (epoch-ms timestamps until
            # 2033, snowflake IDs) Luhn-pass ~10% of the time — without this
            # they become false credit_card findings and false 3.2 denies.
            if digits[:1] not in {"2", "3", "4", "5", "6"}:
                continue
            if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                matched.append("credit_card")
                break
        if cls._PHONE.search(text):
            matched.append("phone")
        return matched

    def score(self, action: AgentAction) -> RiskFinding:
        text, truncated = payload_text(action)
        matched = self.find_pii(text)
        detail = "; ".join(matched) or "no pii patterns matched"
        if truncated:
            detail += " (input truncated at 32 KB)"

        return RiskFinding(
            scorer=self.name,
            category="pii",
            risk_score=_PII_RISK if matched else 0.0,
            matched=matched,
            detail=detail,
            inline=True,
        )
