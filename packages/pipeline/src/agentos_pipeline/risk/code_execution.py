"""CodeExecutionScorer — the SEC-11 / OWASP-ASI05 unsafe code-execution detector.

Flags an agent trying to run dynamic code or shell commands — the ASI05
"unbounded consequence" surface: `eval`/`exec`, `subprocess`/`os.system`,
`child_process`, a bare shell pipeline, `curl … | sh`, and the like. Same
inline discipline as the other Phase-2/8 scorers (stdlib re compiled once,
ReDoS-safe, pure CPU, no model/network); returns a RiskFinding, category
"code_execution".

Scope, honestly: this is a HEURISTIC over the action's payload text — the tool
name, the args, the command string. It catches the common dynamic-execution
shapes; it is not a parser and will miss heavily obfuscated ones (the SEC-14
embedding classifier and the sandbox outcome, Phase 9, are the deeper layers).
`matched` holds construct IDs ("eval_exec", "shell_pipeline", ...), never the
command.

Risk 0.55 — sandbox band, above a bare secret (0.5): dynamic execution is a
direct path to arbitrary consequence. Advisory to the deterministic floor; a
constitution conditions on `guardrails.code_exec` to sandbox/deny it.
"""

from __future__ import annotations

import re

from agentos_contract import AgentAction, RiskFinding

from agentos_pipeline.risk._text import payload_text

_CODE_EXEC_RISK = 0.55  # sandbox band

# Compiled ONCE, bounded quantifiers only (ReDoS-safe). Keyed by construct ID.
_PATTERNS: dict[str, re.Pattern[str]] = {
    # Dynamic code evaluation in the common languages.
    "eval_exec": re.compile(r"\b(?:eval|exec|compile)\s*\(", re.IGNORECASE),
    "python_dunder_import": re.compile(r"\b__import__\s*\(|\bgetattr\s*\(\s*__builtins__"),
    "node_dynamic": re.compile(r"\bnew\s+Function\s*\(|\brequire\s*\(\s*['\"]child_process['\"]"),
    # Spawning OS processes / shells.
    "process_spawn": re.compile(
        r"\b(?:os\.system|subprocess\.(?:run|call|Popen|check_output)|popen|"
        r"child_process\.(?:exec|spawn)|Runtime\.getRuntime\(\)\.exec)\b",
        re.IGNORECASE,
    ),
    "shell_invocation": re.compile(r"\b(?:/bin/)?(?:ba|z|k)?sh\s+-c\b|\bcmd(?:\.exe)?\s+/c\b", re.IGNORECASE),
    # Pipe-to-shell: the classic remote-code bootstrap.
    "curl_pipe_shell": re.compile(
        r"\b(?:curl|wget)\b[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", re.IGNORECASE
    ),
    # A shell pipeline / chaining in what is presented as a single command.
    "shell_pipeline": re.compile(r"[;&]{1,2}\s*\w|\|\s*\w+\s"),
}


class CodeExecutionScorer:
    """SEC-11 / ASI05 inline detector: dynamic code + shell-execution heuristics."""

    name = "code_execution.v1"
    inline = True

    def score(self, action: AgentAction) -> RiskFinding:
        text, truncated = payload_text(action)
        matched = sorted(sid for sid, pat in _PATTERNS.items() if pat.search(text))
        detail = "; ".join(matched) or "no code-execution patterns matched"
        if truncated:
            detail += " (input truncated at 32 KB)"
        return RiskFinding(
            scorer=self.name,
            category="code_execution",
            risk_score=_CODE_EXEC_RISK if matched else 0.0,
            matched=matched,
            detail=detail,
            inline=True,
        )
