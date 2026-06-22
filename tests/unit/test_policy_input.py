"""build_policy_input — the versioned D4 input builder (Slice-3 Task 3).

Locked semantics: every registry field applicable to the action type is ALWAYS
emitted, using ""/False/[] defaults — never an absent key. A tool_call with an
unparseable URL gets egress.host == "", which is in no allowlist, so principle
1.1 (not_in) fires -> deny (fail-closed, mirrors the Phase-1 _host behavior).
Keys/values must match the POLICY_INPUT_FIELDS registry paths exactly.
"""

from agentos_contract import ActionType, AgentAction
from agentos_contract.policy_io import POLICY_INPUT_FIELDS
from agentos_pipeline.enrichment import enrich
from agentos_pipeline.policy_input import build_policy_input

_BASE_GUARDRAILS = {"pii": False, "unsafe": False, "format": False}


def _act(type_: ActionType, target: str, payload: dict | None = None) -> AgentAction:
    return AgentAction(agent_id="a", type=type_, target=target, payload=payload or {})


def test_tool_call_input_complete_and_fail_closed() -> None:
    a = _act(ActionType.tool_call, "http_get",
             {"url": "https://API.Example.com:443/p?q=1"})
    doc = build_policy_input(a, enrich(a))
    assert doc == {
        "type": "tool_call", "target": "http_get",
        "intent": {"class": ""}, "guardrails": _BASE_GUARDRAILS,
        "sequence": {"matched_refs": []},
        "egress": {"host": "api.example.com"},
    }


def test_unparseable_url_yields_empty_host_fail_closed() -> None:
    a = _act(ActionType.tool_call, "http_get", {})
    assert build_policy_input(a, enrich(a))["egress"]["host"] == ""


def test_intent_class_flows_from_enrichment() -> None:
    a = _act(ActionType.tool_call, "drop_table", {})
    assert build_policy_input(a, enrich(a))["intent"]["class"] == "DATA_DESTRUCTION"


def test_memory_access_input_with_defaults() -> None:
    a = _act(ActionType.memory_access, "memory:read", {"operation": "read"})
    doc = build_policy_input(a, enrich(a))
    assert doc == {
        "type": "memory_access", "target": "memory:read",
        "intent": {"class": ""}, "guardrails": _BASE_GUARDRAILS,
        "sequence": {"matched_refs": []},
        "memory": {"operation": "read", "key": ""},   # absent key -> "" default
    }


def test_mcp_call_input_emits_mcp_and_egress_sections() -> None:
    a = _act(ActionType.mcp_call, "github:list_issues",
             {"server": "github", "tool": "list_issues", "args": ""})
    doc = build_policy_input(a, enrich(a))
    assert doc == {
        "type": "mcp_call", "target": "github:list_issues",
        "intent": {"class": ""}, "guardrails": _BASE_GUARDRAILS,
        "sequence": {"matched_refs": []},
        "mcp": {"server": "github", "tool": "list_issues"},
        "egress": {"host": ""},   # no url in payload -> fail-closed empty host
    }


def test_mcp_call_with_url_parses_egress_host() -> None:
    a = _act(ActionType.mcp_call, "fetch:get",
             {"server": "fetch", "tool": "get", "url": "https://api.example.com/x"})
    assert build_policy_input(a, enrich(a))["egress"]["host"] == "api.example.com"


def test_delegation_input() -> None:
    a = _act(ActionType.delegation, "worker", {"to_agent": "worker", "task": "t"})
    doc = build_policy_input(a, enrich(a))
    assert doc == {
        "type": "delegation", "target": "worker",
        "intent": {"class": ""}, "guardrails": _BASE_GUARDRAILS,
        "sequence": {"matched_refs": []},
        "delegation": {"to_agent": "worker"},
    }


def test_model_invocation_input() -> None:
    a = _act(ActionType.model_invocation, "claude-opus-4-8",
             {"model": "claude-opus-4-8", "messages": "hi"})
    doc = build_policy_input(a, enrich(a))
    assert doc == {
        "type": "model_invocation", "target": "claude-opus-4-8",
        "intent": {"class": ""}, "guardrails": _BASE_GUARDRAILS,
        "sequence": {"matched_refs": []},
        "model": {"name": "claude-opus-4-8"},
    }


def test_model_invocation_missing_model_defaults_empty() -> None:
    a = _act(ActionType.model_invocation, "m", {})
    assert build_policy_input(a, enrich(a))["model"]["name"] == ""


def _dotted_paths(node: dict, prefix: str = "") -> set[str]:
    """Flatten a policy-input document to its dotted leaf paths."""
    paths: set[str] = set()
    for key, val in node.items():
        dotted = f"{prefix}{key}"
        if isinstance(val, dict):
            paths |= _dotted_paths(val, dotted + ".")
        else:
            paths.add(dotted)
    return paths


def test_builder_emits_exactly_the_registry_fields_for_every_type() -> None:
    """M3 drift lock: the builder and the POLICY_INPUT_FIELDS registry are the
    SAME versioned schema — for every ActionType, the emitted dotted paths must
    equal the registry entries applicable to that type (in BOTH directions)."""
    for type_ in ActionType:
        a = _act(type_, "t", {})
        emitted = _dotted_paths(build_policy_input(a, enrich(a)))
        applicable = {
            field
            for field, (_, scope) in POLICY_INPUT_FIELDS.items()
            if scope == "all" or type_.value in scope
        }
        assert emitted == applicable, f"registry/builder drift for {type_.value}"
