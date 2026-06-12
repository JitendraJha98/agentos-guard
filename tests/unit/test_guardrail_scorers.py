"""Slice-4 guardrail scorers (SEC-02) — PII / unsafe-content / format-violation.

Behavior (plan 2026-06-12 Tasks 2–3):
  - PiiScorer: email / SSN / Luhn-verified credit card / E.164 phone detection,
    0.35 when matched (advisory — below the 0.4 sandbox band; the 3.2 floor does
    the denying when the host isn't approved), 0.0 clean. `matched` carries
    pattern IDs only — never raw values.
  - UnsafeContentScorer: destructive shell/SQL/fork-bomb patterns at 0.45
    (sandbox band).
  - FormatViolationScorer: control chars / oversized value / excessive nesting
    at 0.2.
"""

from agentos_contract import ActionType, AgentAction
from agentos_pipeline.risk import FormatViolationScorer, PiiScorer, UnsafeContentScorer


def _tool(payload):  # helper used across this file
    return AgentAction(agent_id="a", type=ActionType.tool_call, target="http_post", payload=payload)


# --- PiiScorer (Task 2) --------------------------------------------------------


def test_email_detected():
    f = PiiScorer().score(_tool({"content": "contact: jane.doe@example.com"}))
    assert f.category == "pii" and "email" in f.matched and f.risk_score == 0.35


def test_ssn_detected():
    assert "ssn" in PiiScorer().score(_tool({"content": "ssn 123-45-6789"})).matched


def test_credit_card_requires_luhn():
    assert "credit_card" in PiiScorer().score(_tool({"content": "4111 1111 1111 1111"})).matched   # Luhn-valid
    assert "credit_card" not in PiiScorer().score(_tool({"content": "1234 5678 9012 3456"})).matched  # Luhn-invalid


def test_phone_e164_detected():
    assert "phone" in PiiScorer().score(_tool({"content": "+14155550123"})).matched


def test_clean_payload_scores_zero():
    f = PiiScorer().score(_tool({"content": "the weather is nice"}))
    assert f.risk_score == 0.0 and f.matched == []


def test_matched_never_carries_raw_values():
    f = PiiScorer().score(_tool({"content": "jane.doe@example.com 123-45-6789"}))
    assert all(m in {"email", "ssn", "credit_card", "phone"} for m in f.matched)


# --- UnsafeContentScorer (Task 3) ----------------------------------------------


def test_destructive_shell_rm_detected():
    f = UnsafeContentScorer().score(_tool({"content": "run rm -rf / now"}))
    assert f.category == "unsafe_content"
    assert "destructive_shell" in f.matched and f.risk_score == 0.45


def test_destructive_sql_in_payload_content_detected():
    f = UnsafeContentScorer().score(_tool({"content": "then DROP TABLE users;"}))
    assert "destructive_sql" in f.matched


def test_fork_bomb_detected():
    assert "fork_bomb" in UnsafeContentScorer().score(_tool({"content": ":(){ :|:& };:"})).matched


def test_destructive_powershell_detected():
    f = UnsafeContentScorer().score(_tool({"content": "Remove-Item -Recurse -Force C:\\data"}))
    assert "destructive_shell" in f.matched


def test_unsafe_clean_payload_scores_zero():
    f = UnsafeContentScorer().score(_tool({"content": "list the files please"}))
    assert f.risk_score == 0.0 and f.matched == []


# --- FormatViolationScorer (Task 3) ---------------------------------------------


def test_control_chars_detected():
    f = FormatViolationScorer().score(_tool({"content": "abc\x00def"}))
    assert f.category == "format_violation"
    assert "control_chars" in f.matched and f.risk_score == 0.2


def test_oversized_value_detected():
    f = FormatViolationScorer().score(_tool({"content": "a" * (32_768 + 1)}))
    assert "oversized_value" in f.matched


def test_excessive_nesting_detected():
    nested = "leaf"
    for _ in range(9):  # 9 levels of dict around the leaf — deeper than 8
        nested = {"k": nested}
    f = FormatViolationScorer().score(_tool({"content": nested}))
    assert "excessive_nesting" in f.matched


def test_format_clean_payload_scores_zero():
    f = FormatViolationScorer().score(_tool({"content": "plain\ttext\nwith\r\nallowed ws"}))
    assert f.risk_score == 0.0 and f.matched == []
