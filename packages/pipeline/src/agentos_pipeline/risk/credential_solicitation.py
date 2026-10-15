"""CredentialSolicitationScorer — MCP elicitation that asks the user for secrets (Phase 17, MCP-02).

MCP's elicitation lets a SERVER ask the user for input mid-task. The spec says servers MUST NOT use
it to request sensitive information; a hostile or compromised server that does is phishing through
a trusted client UI. The request reaches governance as an `mcp_call` to `elicitation/create` whose
`args` carry the server's message and requested schema (see `agentos_sdk.normalize`).

Scoped to that one tool on purpose: a tool call that merely mentions "password reset" is not a
solicitation, and scanning every action for this vocabulary would false-positive constantly.

Same inline discipline as the other scorers: stdlib re compiled once, bounded, pure CPU. Risk 0.75
sits above the default deny band (0.7) — the spec forbids the request outright. `matched` holds a
pattern ID only, never the text.
"""

from __future__ import annotations

import re

from agentos_contract import ActionType, AgentAction, RiskFinding

from agentos_pipeline.risk._text import payload_text

ELICITATION_TOOL = "elicitation/create"
_RISK = 0.75

_CREDENTIAL = re.compile(
    r"\b(pass(?:word|code|phrase)|pwd|api[\s_-]?key|access[\s_-]?token|auth(?:entication)?[\s_-]?"
    r"token|bearer[\s_-]?token|client[\s_-]?secret|secret[\s_-]?key|private[\s_-]?key|seed[\s_-]?"
    r"phrase|recovery[\s_-]?phrase|mnemonic|one[\s_-]?time[\s_-]?(?:code|password)|otp|2fa|mfa|"
    r"verification[\s_-]?code|pin[\s_-]?(?:code|number)|ssn|social[\s_-]?security|credit[\s_-]?"
    r"card|card[\s_-]?number|cvv|cvc|security[\s_-]?code)\b",
    re.IGNORECASE,
)


class CredentialSolicitationScorer:
    name = "credential_solicitation.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        solicits = (
            action.type is ActionType.mcp_call
            and str((action.payload or {}).get("tool", "")) == ELICITATION_TOOL
            and _CREDENTIAL.search(payload_text(action)[0]) is not None
        )
        return RiskFinding(
            scorer=self.name,
            category="credential_solicitation",
            risk_score=_RISK if solicits else 0.0,
            matched=["elicits_credential"] if solicits else [],
            detail="elicitation requests a credential" if solicits else "no credential solicited",
            inline=True,
        )
