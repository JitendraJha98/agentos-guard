"""AUD-04 content-based secret scanner — the flag / not-flag matrix.

`scan(text)` returns a list of finding ids (empty == clean). It must catch structured
secrets (regex) and high-entropy opaque tokens (entropy gate) while NEVER tripping on the
audit body's own legitimate high-information strings: the redactor's {len, sha256:<64hex>}
digest, prev_hash (64-hex), action_id (UUID), and "sha256:..." version prefixes. Those are
single-class lowercase-hex / uuid / version strings and must stay clean — the FP discipline
is the whole point of the gate.
"""

import hashlib

import pytest

from agentos_controlplane.secret_scan import SecretLeakError, scan

# --- FLAGGED: real structured secrets + a high-entropy opaque token ------------------

FLAGGED = {
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "github_token": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",  # gh prefix + 36 alnum
    "slack_token": "xoxb-" + "1234567890-abcdefghijklmnop",
    "private_key_pem": "-----BEGIN PRIVATE KEY-----\nMIIBVgIBADANB...\n-----END PRIVATE KEY-----",
    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    "bearer_token": "Authorization: Bearer abcDEF123ghiJKL456mnoPQR789",
    "high_entropy_token": "Xk7Pq2Lm9Rt4Vn8Zb3Cw6Yd1Fg5Hj0Ks8Mp2Qr4",  # mixed case + digits
}


@pytest.mark.parametrize("name,text", sorted(FLAGGED.items()))
def test_flags_real_secret(name: str, text: str) -> None:
    findings = scan(text)
    assert findings, f"{name} should be flagged but was not: {text!r}"


# --- NOT FLAGGED: the audit body's own legitimate high-information strings -----------

_HEX64 = hashlib.sha256(b"any audit body content").hexdigest()  # 64-char lowercase hex
_UUID = "11111111-1111-1111-1111-111111111111"

CLEAN = {
    "plain_english": "The agent attempted an egress to an unapproved host and was denied.",
    "sha256_hex_digest": _HEX64,
    "uuid": _UUID,
    "sha256_version_prefix": "sha256:" + _HEX64,
    "https_host": "https://api.example.com/v1/messages",
    "nvidia_model_id": "meta/llama-3.1-8b-instruct",
    "redactor_digest_fragment": '{"len": 5, "sha256": "' + _HEX64 + '"}',
    "prev_hash_field": '{"prev_hash": "' + _HEX64 + '", "seq": 3}',
    "empty": "",
    # FP-floor (4d review): a short contiguous opaque-looking run (24-31 chars) — the
    # realistic correlation/trace/request id echoed into free-text reasons — must NOT
    # fail-close a legitimate audit write. Below the 32-char entropy floor, it is clean.
    "request_id_in_intent": "user op for RequestId-A1B2C3D4E5F6G7H8I9J0",  # 30-char token
    "trace_id_field": "trace_id=Ab12Cd34Ef56Gh78Ij90Kl",                   # 31-char token
    "correlation_id": "X-Correlation-Id: Ab12Cd34Ef56Gh78Ij90Kl",         # 28-char token
}


@pytest.mark.parametrize("name,text", sorted(CLEAN.items()))
def test_does_not_flag_legitimate_body_string(name: str, text: str) -> None:
    findings = scan(text)
    assert findings == [], f"{name} must NOT be flagged but was: {findings} on {text!r}"


def test_empty_string_is_clean() -> None:
    assert scan("") == []


# --- entropy-floor recall lock (4d review): the floor must NOT drop real opaque secrets ----

# Bare opaque secrets caught ONLY by the entropy gate (no high-precision regex covers them):
# an AWS *secret* access key (40-char base64) and a Google API key (~39 char). Both are well
# above the 32-char floor, so raising the floor to cut short correlation-id FPs must NOT cost
# their recall — this locks that trade-off (the review's explicit "do NOT drop AWS-secret/
# Google-API-key recall").
ENTROPY_ONLY_SECRETS = {
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # 40-char base64
    "google_api_key": "AIzaSyA1234567890abcdefGHIJKLMNOPqrstuvw",        # 40-char mixed
    "base64_of_32_random_bytes": "f3Kp9QvX2mNz7LwR0bYtUaHcEdGsJkMn",      # exactly 32 chars
}


@pytest.mark.parametrize("name,text", sorted(ENTROPY_ONLY_SECRETS.items()))
def test_entropy_floor_still_catches_real_opaque_secrets(name: str, text: str) -> None:
    assert scan(text) == ["high_entropy_token"], f"{name} must still be caught: {text!r}"


def test_secretleakerror_is_an_exception() -> None:
    assert issubclass(SecretLeakError, Exception)
