"""PostureMap — per-action-class control-plane-failure posture + no-match floor
(PIPE-05 / D4, Slice-3 Task 5).

Defaults: every class fail-CLOSED with a no-match floor of allow. Fail-open is
explicit, per-class, never a default — and the runner guarantees every fail-open
is audited (no record -> no allow; proven in test_pipeline.py).
"""

from agentos_contract import ActionType, Outcome
from agentos_pipeline.posture import FailPosture, PostureMap


def test_defaults_all_closed_allow_floor() -> None:
    p = PostureMap()
    for t in ActionType:
        assert p.fail_posture(t) is FailPosture.closed
        assert p.no_match_floor(t) is Outcome.allow


def test_override_per_class() -> None:
    p = PostureMap(fail_open_types=frozenset({ActionType.model_invocation}))
    assert p.fail_posture(ActionType.model_invocation) is FailPosture.open
    # Every OTHER class keeps the fail-closed default.
    for t in ActionType:
        if t is not ActionType.model_invocation:
            assert p.fail_posture(t) is FailPosture.closed


def test_no_match_floor_override_per_class() -> None:
    p = PostureMap(no_match_floors={ActionType.delegation: Outcome.require_approval})
    assert p.no_match_floor(ActionType.delegation) is Outcome.require_approval
    assert p.no_match_floor(ActionType.tool_call) is Outcome.allow
