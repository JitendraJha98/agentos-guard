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
}


@pytest.mark.parametrize("name,text", sorted(CLEAN.items()))
def test_does_not_flag_legitimate_body_string(name: str, text: str) -> None:
    findings = scan(text)
    assert findings == [], f"{name} must NOT be flagged but was: {findings} on {text!r}"


def test_empty_string_is_clean() -> None:
    assert scan("") == []


def test_secretleakerror_is_an_exception() -> None:
    assert issubclass(SecretLeakError, Exception)
