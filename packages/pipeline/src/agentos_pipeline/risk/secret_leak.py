"""SecretLeakScorer — the SEC-05 inline, deterministic secret/credential detector.

Flags credentials and keys wherever they appear in an action — prompts, tool
args, model messages, or fetched outputs — all of which land in the joined
payload text this scans. Implements the RiskScorer Protocol and returns a typed
RiskFinding (category "secret_leak").

INVARIANTS (tested), identical discipline to `pii.py` / `unsafe_content.py`:
  - inline=True, pure CPU, bounded, ReDoS-safe; NO model/network/LLM on the hot
    path (Pitfall 1). Patterns compiled once in `_secrets.py`.
  - `matched` holds pattern IDs only ("aws_access_key", ...) — never the secret.
  - Advisory: 0.5 when matched — inside the sandbox band (0.4-0.7). A leaked
    credential is more severe than PII (0.35) but the deterministic policy floor
    still decides the outcome; the detector only CONTRIBUTES risk.
"""

from __future__ import annotations

from agentos_contract import AgentAction, RiskFinding

from agentos_pipeline.risk._secrets import find_secrets
from agentos_pipeline.risk._text import payload_text

_SECRET_RISK = 0.5  # sandbox band; > PII (0.35), a credential leak is more severe


class SecretLeakScorer:
    """SEC-05 inline detector: structured + high-entropy secret heuristics, no model, no I/O."""

    name = "secret_leak.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        text, truncated = payload_text(action)
        matched = find_secrets(text)
        detail = "; ".join(matched) or "no secret patterns matched"
        if truncated:
            detail += " (input truncated at 32 KB)"
        return RiskFinding(
            scorer=self.name,
            category="secret_leak",
            risk_score=_SECRET_RISK if matched else 0.0,
            matched=matched,
            detail=detail,
            inline=True,
        )
