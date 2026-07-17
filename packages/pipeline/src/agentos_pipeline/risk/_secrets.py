"""Shared deterministic secret/credential detection (SEC-05 core).

One compiled pattern set, used by BOTH the SEC-05 secret-leak scorer and the
SEC-04 exfiltration scorer, so the two never disagree about what a secret is.

Discipline mirrors the other hot-path detectors (`pii.py`, `unsafe_content.py`)
and the audit-side `secret_scan.py`: stdlib `re` compiled ONCE, bounded
quantifiers (ReDoS-safe), pure CPU, no model/network. Honest scope — this is
best-effort RECALL over the well-known structured-secret shapes (gitleaks /
detect-secrets family) plus a high-entropy fallback; it will MISS novel or
low-entropy secrets. Returned values are pattern IDs, never the secret itself,
so a finding is safe to write into the hash-covered audit log.
"""

from __future__ import annotations

import math
import re

# High-precision structured-secret patterns, each keyed by a stable ID.
_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "bearer_token": re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*", re.IGNORECASE),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    # A password/secret/token/apikey assigned an opaque value, in a URL, env line, or JSON.
    "credential_assignment": re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
        r"\s*[=:]\s*['\"]?[^\s'\"&]{6,}",
    ),
    "basic_auth_url": re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s:@]{3,}@", re.IGNORECASE),
}

# High-entropy opaque-token fallback: a long mixed-class run that the structured
# patterns missed. The length floor (32) clears realistic non-secret ids (request /
# trace / correlation ids are shorter) while keeping recall on real >=32-char keys —
# the same trade `secret_scan.py` documents.
_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{32,}")
_ENTROPY_BITS_PER_CHAR = 3.6  # ~ mixed-class base64; below this a run is not opaque-secret shaped


def _shannon_bits_per_char(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _has_mixed_classes(s: str) -> bool:
    """An opaque secret mixes character classes; a single-class run (all-hex digest,
    all-lowercase word) does not — this excludes the audit body's own sha256/uuid
    digests, matching the false-positive discipline in `secret_scan.py`."""
    classes = (
        any(c.islower() for c in s),
        any(c.isupper() for c in s),
        any(c.isdigit() for c in s),
    )
    return sum(classes) >= 2


def find_secrets(text: str) -> list[str]:
    """Return the sorted, de-duplicated IDs of secret shapes present in `text`.

    Never returns the secret itself. `high_entropy_token` covers opaque keys the
    structured patterns miss.
    """
    hits = {sid for sid, pat in _PATTERNS.items() if pat.search(text)}
    for candidate in _TOKEN.findall(text):
        if _has_mixed_classes(candidate) and _shannon_bits_per_char(candidate) >= _ENTROPY_BITS_PER_CHAR:
            hits.add("high_entropy_token")
            break
    return sorted(hits)
