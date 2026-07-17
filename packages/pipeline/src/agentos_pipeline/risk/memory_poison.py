"""MemoryPoisoningScorer — the SEC-09 / OWASP-ASI06 memory-poisoning detector.

Flags malicious memory writes and reads: injection/instruction content crossing
the MEMORY boundary, where it persists and re-enters a later context to steer the
agent long after the write. That persistence is exactly what makes it worse than
a transient prompt injection, and why it is a distinct detector from
`prompt_injection.py` (which scores the same shapes on any action, advisory):
this one fires ONLY on `memory_access` and raises `guardrails.memory_poison`, so
a constitution can hold *stored* instructions to a stricter standard than the
same words spoken in passing.

Inline discipline matches the other scorers (stdlib re compiled once, ReDoS-safe,
pure CPU, no model/network). The memory value is normalize()d first, since
poisoned memory is commonly obfuscated to survive a naive scan. `matched` holds
construct IDs, never the stored value. Category "memory_poisoning".

Risk 0.5 — sandbox band. Advisory to the deterministic floor.
"""

from __future__ import annotations

import re

from agentos_contract import ActionType, AgentAction, RiskFinding

from agentos_pipeline.risk.normalize import normalize

_MEMORY_POISON_RISK = 0.5  # sandbox band

# Compiled ONCE, bounded (ReDoS-safe). The shapes that make STORED content hostile.
_PATTERNS: dict[str, re.Pattern[str]] = {
    # Instruction-override planted for a future read to pick up.
    "stored_instruction_override": re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,40}"
        r"\b(previous|prior|above|all|system)\b[^.\n]{0,20}"
        r"\b(instruction|prompt|rule|constraint|context)s?\b",
        re.IGNORECASE,
    ),
    # A role/turn marker smuggled into data, so a later read re-opens as a new turn.
    "role_marker_injection": re.compile(
        r"(?m)^\s*(system|assistant|developer|tool)\s*[:>]|<\|(?:im_start|system|assistant)\|>",
        re.IGNORECASE,
    ),
    # Persona/mode hijack seeded into memory.
    "persona_hijack": re.compile(
        r"\b(you\s+are\s+now|from\s+now\s+on\s+you|developer\s+mode|jailbreak|act\s+as)\b",
        re.IGNORECASE,
    ),
    # A tool/exfil directive stored as data to be re-executed on recall.
    "embedded_tool_directive": re.compile(
        r"\b(call|invoke|run|execute|send|post|upload)\b[^.\n]{0,40}"
        r"(tool|function|https?://|api[_\s-]?key|secret|token|credential)",
        re.IGNORECASE,
    ),
}

_READ_OPS = frozenset({"read", "get", "recall", "load", "fetch"})
_WRITE_OPS = frozenset({"write", "set", "store", "save", "append", "update"})


class MemoryPoisoningScorer:
    """SEC-09 / ASI06 inline detector: injection content crossing the memory boundary."""

    name = "memory_poisoning.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        if action.type is not ActionType.memory_access:
            return RiskFinding(
                scorer=self.name, category="memory_poisoning", risk_score=0.0,
                matched=[], detail="not a memory-access action", inline=True,
            )

        payload = action.payload or {}
        operation = str(payload.get("operation", "")).lower()
        # Scan the stored/recalled value specifically — that is the poisoning surface.
        # Fall back to the whole payload when no explicit value field is present.
        value = payload.get("value")
        raw = str(value) if value is not None else "\n".join(str(v) for v in payload.values())
        text = normalize(raw[: 32 * 1024])

        matched = sorted(sid for sid, pat in _PATTERNS.items() if pat.search(text))

        # Direction is context for the finding, not a gate: a poisoned READ (recalling
        # planted content into context) is as dangerous as the WRITE that planted it.
        if operation in _WRITE_OPS:
            direction = "write"
        elif operation in _READ_OPS:
            direction = "read"
        else:
            direction = operation or "unknown"

        detail = (
            f"{direction}: " + "; ".join(matched)
            if matched
            else f"{direction}: no memory-poisoning patterns matched"
        )

        return RiskFinding(
            scorer=self.name,
            category="memory_poisoning",
            risk_score=_MEMORY_POISON_RISK if matched else 0.0,
            matched=matched,
            detail=detail,
            inline=True,
        )
