"""AUD-04 last gate — fail-closed, content-based secret detector over the about-to-be-written
audit body.

Defense-in-depth BENEATH the fail-closed field classifier (audit.py `_redact_or_raise`): it
catches a secret that slipped into a verbatim-kept field (`model`, `to_agent`) or a free-text
field the runner/interpreter produced (`rationale`, `inferred_intent`, `remediation`). Honest
scope: best-effort RECALL — regex + entropy will MISS novel / low-entropy secrets. It shrinks
the blast radius of a misclassification; it is NOT a guarantee. The guarantee stays the
allowlist classifier; Presidio-grade ML PII is the later upgrade noted in audit.py.

Deterministic: stdlib `re` compiled once + Shannon entropy; no LLM/network; bounded patterns
(ReDoS-safe). On a hit the writer raises `SecretLeakError` and writes NOTHING.

Critical FP discipline: the audit body legitimately carries the redactor's own {len,
sha256:<64hex>} digest, prev_hash (64-hex), action_id (UUID), and "sha256:..." version strings.
NONE may trip the gate — they are single-class lowercase-hex / uuid / version strings, which the
entropy gate excludes by requiring an OPAQUE-SECRET shape (mixed character classes).
"""
from __future__ import annotations

import math
import re


class SecretLeakError(Exception):
    """A secret was detected in the audit body — fail closed, write NOTHING (RedactionError peer)."""


# High-precision structured-secret patterns (gitleaks/detect-secrets family), compiled once,
# bounded (ReDoS-safe — no nested/unbounded quantifiers).
_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),
}

# Opaque-token candidates for the entropy gate.
_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
_ENTROPY_THRESHOLD = 4.0  # bits/char


def _shannon(s: str) -> float:
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in counts.values()) if n else 0.0


def _looks_opaque_secret(tok: str) -> bool:
    # Real keys mix character classes; the audit body's hex digests / UUIDs / "sha256:" prefixes
    # are single-class lowercase-hex and must NOT trip. Require (uppercase AND digit) OR a
    # base64-special char — excludes lowercase-hex/uuid/version, catches AWS-secret/base64 tokens.
    has_upper = any(c.isupper() for c in tok)
    has_digit = any(c.isdigit() for c in tok)
    has_b64 = any(c in "+/=" for c in tok)
    return (has_upper and has_digit) or has_b64


def scan(text: str) -> list[str]:
    """Return finding ids for secrets detected in `text`; empty list == clean."""
    findings = [name for name, pat in _PATTERNS.items() if pat.search(text)]
    for tok in _TOKEN.findall(text):
        if _looks_opaque_secret(tok) and _shannon(tok) >= _ENTROPY_THRESHOLD:
            findings.append("high_entropy_token")
            break
    return findings
