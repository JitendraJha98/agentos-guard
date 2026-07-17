"""ExfiltrationScorer — the SEC-04 inline data-exfiltration detector.

Exfiltration is a CONJUNCTION, not a single pattern: sensitive data (a secret or
PII) leaving over an OUTBOUND channel to a destination the agent does not own.
Neither half alone is exfiltration — a secret sitting in a memory write is a
different concern (SEC-05 flags the secret), and an outbound call carrying
nothing sensitive is ordinary traffic. This scorer fires only on the pair.

  category: "egress_exfil"; implements the RiskScorer Protocol.

Design:
  - Only egress-capable action types (tool_call / mcp_call) carry a destination,
    so only those can exfiltrate; other types score 0.
  - Severity depends on the DATA CLASS, which is how this honors "untrusted
    targets" without re-implementing the allowlist (a policy concern):

      * a SECRET leaving to any external host scores 0.6 (sandbox band). A
        credential is never supposed to egress anywhere — an approved analytics
        endpoint should still never receive your AWS keys — so every external
        host is untrusted for secrets.
      * PII leaving scores 0.35 (advisory, matching the bare-PII treatment). PII
        egress to an APPROVED host is the legitimate business case the Phase-2
        invariant protects ("PII to an allowlisted host stays allow"), and PII to
        an UN-approved host is already denied by the deterministic egress floor
        (`egress.host not_in allowlist`). A high PII-exfil score would contradict
        both, so PII trusts the allowlist while secrets do not.

    Either way the `guardrails.exfiltration` flag is raised, so a constitution
    MAY sandbox/deny sensitive egress by conditioning on it — the score just
    doesn't unilaterally override the existing bands. Loopback/empty hosts are
    excluded (nothing left the machine).

Reuses `find_secrets` and `PiiScorer.find_pii` so "sensitive" means exactly what
SEC-05 and SEC-02 already mean — no third, divergent definition.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from agentos_contract import ActionType, AgentAction, RiskFinding

from agentos_pipeline.risk._secrets import find_secrets
from agentos_pipeline.risk._text import payload_text
from agentos_pipeline.risk.pii import PiiScorer

_SECRET_EXFIL_RISK = 0.6  # sandbox band; a credential must never egress to ANY external host
_PII_EXFIL_RISK = 0.35    # advisory (== bare PII); PII trusts the allowlist, the egress floor denies untrusted

_EGRESS_TYPES = frozenset({ActionType.tool_call, ActionType.mcp_call})
# Destinations that are not "off the box": nothing is exfiltrated to loopback.
_LOCAL_HOSTS = frozenset({"", "localhost", "127.0.0.1", "::1", "0.0.0.0"})


def _external_host(action: AgentAction) -> str:
    host = urlsplit(str((action.payload or {}).get("url", ""))).hostname or ""
    return "" if host.lower() in _LOCAL_HOSTS else host


class ExfiltrationScorer:
    """SEC-04 inline detector: sensitive content + an outbound external destination."""

    name = "exfiltration.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        if action.type not in _EGRESS_TYPES:
            return RiskFinding(
                scorer=self.name,
                category="egress_exfil",
                risk_score=0.0,
                matched=[],
                detail="not an egress-capable action",
                inline=True,
            )

        host = _external_host(action)
        if not host:
            return RiskFinding(
                scorer=self.name,
                category="egress_exfil",
                risk_score=0.0,
                matched=[],
                detail="no external destination",
                inline=True,
            )

        text, truncated = payload_text(action)
        secrets = find_secrets(text)
        pii = PiiScorer.find_pii(text)
        sensitive = secrets + pii
        # `matched` records WHAT KIND of sensitive data would leave, plus the fact
        # of an external destination — never the host itself (kept out of the
        # audit-safe matched list; RiskFinding rejects URL-like entries anyway).
        matched = ([*sensitive, "external_destination"] if sensitive else [])

        # A secret dominates: 0.6 regardless of destination trust. PII alone stays
        # advisory so the "PII to an allowlisted host stays allow" invariant holds.
        if secrets:
            risk = _SECRET_EXFIL_RISK
        elif pii:
            risk = _PII_EXFIL_RISK
        else:
            risk = 0.0

        detail = (
            f"sensitive payload ({', '.join(sensitive)}) to external host"
            if sensitive
            else "outbound to external host, no sensitive content"
        )
        if truncated:
            detail += " (input truncated at 32 KB)"

        return RiskFinding(
            scorer=self.name,
            category="egress_exfil",
            risk_score=risk,
            matched=matched,
            detail=detail,
            inline=True,
        )
