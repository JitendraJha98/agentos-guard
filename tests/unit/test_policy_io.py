"""D4 policy I/O contract — input-field registry, result types, precedence."""
import pytest
from agentos_contract import Outcome
from agentos_contract.policy_io import (
    AUTHORABLE_EFFECTS, OUTCOME_RESTRICTIVENESS, POLICY_INPUT_FIELDS,
    POLICY_INPUT_SCHEMA_VERSION, ConstitutionResult, MatchedPrinciple, select_floor,
)


def test_authorable_effects_exclude_temporary_exception():
    assert Outcome.temporary_exception.value not in AUTHORABLE_EFFECTS
    assert AUTHORABLE_EFFECTS == {
        "allow", "warn", "sandbox", "require_consensus",
        "require_approval", "governance_review", "deny",
    }


def test_restrictiveness_covers_all_outcomes_deny_max():
    assert set(OUTCOME_RESTRICTIVENESS) == set(Outcome)
    assert max(OUTCOME_RESTRICTIVENESS, key=OUTCOME_RESTRICTIVENESS.get) is Outcome.deny
    assert OUTCOME_RESTRICTIVENESS[Outcome.allow] == 0


def test_registry_has_core_fields_and_version():
    assert POLICY_INPUT_SCHEMA_VERSION == 1
    for f in ("type", "target", "intent.class", "guardrails.pii",
              "egress.host", "sequence.matched_refs"):
        assert f in POLICY_INPUT_FIELDS


def test_select_floor_most_restrictive_wins():
    m = lambda ref, eff: MatchedPrinciple(principle_ref=ref, effect=eff)
    assert select_floor([m("1", "allow"), m("2", "deny")]) is Outcome.deny
    assert select_floor([m("1", "warn"), m("2", "require_approval")]) is Outcome.require_approval
    assert select_floor([m("1", "allow")]) is Outcome.allow
    assert select_floor([]) is None  # no_match — floor is the per-class posture (Slice 3)


def test_matched_principle_is_frozen():
    mp = MatchedPrinciple(principle_ref="3.2", effect="deny")
    with pytest.raises(Exception):
        mp.effect = "allow"
