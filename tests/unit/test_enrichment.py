"""Deterministic pre-policy enrichment (SEC-12 / D6) — intent tagger + flags seam.

Behavior (Slice-3 Task 2):
  - destruction-shaped targets (exact or prefix, case-insensitive) tag DATA_DESTRUCTION;
  - rename-shaped targets tag RESOURCE_RENAME;
  - a memory_access with operation=delete tags DATA_DESTRUCTION (payload signal);
  - benign targets tag None;
  - enrich() bundles the intent class with the Slice-4 guardrail-flag seam
    (always {pii, unsafe, format} = False until the real detectors land);
  - IntentScorer mirrors the RiskScorer protocol: advisory finding (category
    "intent"), risk_score 0.15 when tagged — never alone reaching the sandbox band.
"""

from agentos_contract import ActionType, AgentAction
from agentos_pipeline.enrichment import INTENT_CLASSES, enrich, tag_intent


def _act(type_: ActionType, target: str, payload: dict | None = None) -> AgentAction:
    return AgentAction(agent_id="a", type=type_, target=target, payload=payload or {})


def test_destruction_targets_tagged() -> None:
    for t in ("drop_table", "DROP_TABLE", "delete_user", "truncate_logs", "rm"):
        assert tag_intent(_act(ActionType.tool_call, t)) == "DATA_DESTRUCTION"


def test_rename_targets_tagged() -> None:
    for t in ("rename_table", "mv", "move_file"):
        assert tag_intent(_act(ActionType.tool_call, t)) == "RESOURCE_RENAME"


def test_memory_delete_operation_tagged() -> None:
    a = _act(ActionType.memory_access, "memory", {"operation": "delete", "key": "k"})
    assert tag_intent(a) == "DATA_DESTRUCTION"


def test_benign_target_untagged() -> None:
    assert tag_intent(_act(ActionType.tool_call, "http_get")) is None


def test_remove_prefixed_targets_are_not_destruction() -> None:
    """M2: remove_* was a false-positive trigger (remove_formatting/_duplicates
    are not data destruction) — the prefix is dropped from the tagger."""
    for t in ("remove_formatting", "remove_duplicates"):
        assert tag_intent(_act(ActionType.tool_call, t)) is None


def test_intent_classes_export_is_the_emitted_vocabulary() -> None:
    """M2: the tagger's output vocabulary is exported for principle authors."""
    assert INTENT_CLASSES == frozenset({"DATA_DESTRUCTION", "RESOURCE_RENAME"})


def test_enrich_shape() -> None:
    e = enrich(_act(ActionType.tool_call, "drop_table"))
    assert e.intent_class == "DATA_DESTRUCTION"
    assert e.guardrails == {"pii": False, "unsafe": False, "format": False}  # Slice-4 seam


def test_intent_scorer_contributes_advisory_finding() -> None:
    from agentos_pipeline.risk import IntentScorer

    finding = IntentScorer().score(_act(ActionType.tool_call, "drop_table"))
    assert 0.0 < finding.risk_score < 0.4  # advisory: never reaches the sandbox band alone
    assert finding.category == "intent"
    assert finding.detail == "DATA_DESTRUCTION"
    assert finding.matched == ["DATA_DESTRUCTION"]


def test_intent_scorer_untagged_is_zero() -> None:
    from agentos_pipeline.risk import IntentScorer

    finding = IntentScorer().score(_act(ActionType.tool_call, "http_get"))
    assert finding.risk_score == 0.0
    assert finding.matched == []
