"""payload_text — the shared bounded payload-join the guardrail scorers scan.

The same surface PromptInjectionScorer._inspect_text inspects (str(v) over the
payload values, 32 KiB deterministic byte budget), but deliberately WITHOUT
normalize(): PII patterns (emails, SSNs, card numbers, E.164 phones) match the
raw text — normalization's case-folding/whitespace-collapsing would distort the
literal separators these patterns key on, and obfuscated PII is not the threat
model here (an agent exfiltrating PII sends it verbatim so the receiver can use
it). Truncation is returned so a scorer can record it in `detail` — a planted
match past the cap is auditable, not silently missed.
"""

from agentos_contract import AgentAction

_MAX_INSPECT_BYTES = 32 * 1024


def payload_text(action: AgentAction, cap: int = _MAX_INSPECT_BYTES) -> tuple[str, bool]:
    """Join str(v) over the payload values, capped at `cap` bytes.

    Returns (raw_text, truncated). The cap is computed on the joined UTF-8 bytes
    (deterministic byte budget); a partial trailing multibyte char is dropped.
    """
    parts = [str(v) for v in (action.payload or {}).values()]
    raw = "\n".join(parts)
    encoded = raw.encode("utf-8")
    truncated = len(encoded) > cap
    if truncated:
        raw = encoded[:cap].decode("utf-8", "ignore")
    return raw, truncated
