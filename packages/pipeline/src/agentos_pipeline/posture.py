"""Per-action-class control-plane-failure posture + no-match floor (PIPE-05 / D4).

Defaults: every class fail-CLOSED, no-match floor allow. Fail-open is explicit,
per-class, and every fail-open MUST be audited — the runner demotes a fail-open
it cannot audit to a deny (no record -> no allow).

One classification, two uses (D4): the same map supplies the floor when NO
principle matches and the outcome when the control plane itself fails (and,
in Slice 6a, the approval-timeout default).

Caching note (PIPE-06): there is deliberately NO whole-Decision cache anywhere
in the pipeline — trust drifts between calls and every action must produce its
own audit record. The control plane's own caches are the compiled-policy WASM
(see policy.ConstitutionPolicyEngine) and identity verification (TTL); the
interpreter-verdict cache arrives in Slice 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping

from agentos_contract import ActionType, Outcome


class FailPosture(Enum):
    closed = "closed"
    open = "open"


@dataclass(frozen=True)
class PostureMap:
    """Per-action-class posture: which classes fail OPEN (explicit, none by
    default) and each class's no-match floor (allow by default)."""

    fail_open_types: frozenset[ActionType] = frozenset()
    no_match_floors: Mapping[ActionType, Outcome] = field(default_factory=dict)

    def fail_posture(self, t: ActionType) -> FailPosture:
        return FailPosture.open if t in self.fail_open_types else FailPosture.closed

    def no_match_floor(self, t: ActionType) -> Outcome:
        return self.no_match_floors.get(t, Outcome.allow)
