"""TRST-04 — delegation trust as a bounded budget, delegated scope as an intersection.

Phase 2 captured the delegation EDGE (`parent_action_id` lineage, INT-05). This
module gives that edge semantics: what authority actually crosses it.

## Trust is a budget, not an inheritance

    effective_trust(child) = min(child_own_trust, parent_trust * decay)

Both halves are load-bearing, and each kills a distinct attack:

  * `parent_trust * decay` caps the child by its delegator. Without it,
    delegation is a **trust-laundering machine**: an agent ground down to 0.1 by
    the reputation engine (TRST-03) simply asks a fully-trusted sub-agent to act
    for it and recovers full authority in one hop — every violation it ever
    committed made irrelevant. Trust must not be borrowable.
  * `min(child_own_trust, ...)` stops a trusted parent from *promoting* an
    untrusted child above its own standing.

Because `0 <= decay <= 1` and the result is a `min`, trust is monotonically
non-increasing along any chain: authority can only be spent, never minted. That
is the "bounded budget". A `max_depth` makes it terminate.

## Scope is an intersection, never a union

    effective_scope(child) = parent_scope ∩ child_scope

The union reading is the bug the requirement is written to forbid. If A may
`read` and B may `db.drop`, then under a union A delegating to B yields
`{read, db.drop}` — a capability neither party could exercise alone has been
conjured by the act of asking. Under intersection the delegation confers `{}`,
which this module treats as a hard `DelegationDenied` rather than a silent
no-op: a delegation that grants nothing is an escalation attempt or a
misconfiguration, and both deserve to be seen.

Pure CPU, no I/O, no clock — the same hot-path discipline as `sequence.py`.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Protocol

from agentos_contract import AgentAction

# The scope wildcard: `frozenset({"*"})` means "every capability". Kept as a
# sentinel set (rather than None) so intersection stays total set algebra.
WILDCARD = "*"
ALL: frozenset[str] = frozenset({WILDCARD})

DEFAULT_DECAY = 0.8
DEFAULT_MAX_DEPTH = 5


class DelegationDenied(Exception):
    """A delegation that may not proceed: exhausted budget, or an empty granted scope."""


@dataclass(frozen=True)
class Authority:
    """The effective authority in force at one point in a delegation chain.

    `trust` and `scope` are the EFFECTIVE values (already intersected/decayed),
    not the agent's own standing — an agent's own trust is an input to
    `delegate`, never a property of a resolved link.
    """

    agent_id: str
    trust: float
    scope: frozenset[str] = ALL
    depth: int = 0

    def __post_init__(self) -> None:
        if not (0.0 <= self.trust <= 1.0):
            raise ValueError(f"trust must be in [0,1], got {self.trust}")
        if self.depth < 0:
            raise ValueError(f"depth must be >= 0, got {self.depth}")

    def permits(self, capability: str) -> bool:
        return permits(self.scope, capability)


def permits(scope: frozenset[str], capability: str) -> bool:
    """True iff `scope` confers `capability` (the wildcard confers everything)."""
    return WILDCARD in scope or capability in scope


def intersect_scope(parent: frozenset[str], child: frozenset[str]) -> frozenset[str]:
    """The delegated scope: what BOTH parties may do. Never a union (TRST-04).

    The wildcard is the set-algebra identity here: intersecting "everything" with
    a concrete scope yields that concrete scope, so a wildcard parent confers the
    child's own scope and no more — and a wildcard child is still bounded by its
    parent.
    """
    if WILDCARD in parent:
        return child
    if WILDCARD in child:
        return parent
    return parent & child


def delegate(
    parent: Authority,
    child_id: str,
    *,
    child_trust: float,
    child_scope: frozenset[str] = ALL,
    decay: float = DEFAULT_DECAY,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> Authority:
    """Resolve the authority conferred on `child_id` by `parent` (TRST-04).

    Raises `DelegationDenied` when the budget is exhausted (`max_depth`) or the
    intersected scope is empty.
    """
    if not (0.0 <= decay <= 1.0):
        # decay > 1 would let a delegation GROW trust — the precise inverse of a
        # bounded budget, so this is a hard error rather than a clamp.
        raise ValueError(f"decay must be in [0,1], got {decay}")
    if not (0.0 <= child_trust <= 1.0):
        raise ValueError(f"child_trust must be in [0,1], got {child_trust}")

    depth = parent.depth + 1
    if depth > max_depth:
        raise DelegationDenied(
            f"delegation depth {depth} exceeds max_depth {max_depth} "
            f"(chain from {parent.agent_id!r} to {child_id!r})"
        )

    scope = intersect_scope(parent.scope, child_scope)
    if not scope:
        raise DelegationDenied(
            f"delegation from {parent.agent_id!r} to {child_id!r} confers an empty scope: "
            f"parent scope {sorted(parent.scope)} shares nothing with child scope "
            f"{sorted(child_scope)}"
        )

    return Authority(
        agent_id=child_id,
        trust=min(child_trust, parent.trust * decay),
        scope=scope,
        depth=depth,
    )


@dataclass
class DelegationLedger:
    """Bounded `action_id -> Authority` map so a child action inherits its parent's link.

    State honesty (mirrors `sequence.py`'s bounded-window stance): this lives
    in-process with no TTL — correct for the single-process deployment, and the
    distributed/persistent form is reconciler territory (API-04). Bounded by
    `max_entries` with FIFO eviction so a hostile flood of action ids cannot grow
    memory without limit.

    The flip side of that bound, stated honestly: eviction makes a parent's
    authority unresolvable, and `authority_for` then returns None. Callers MUST
    treat None as "unknown lineage" and fail closed — never as "no parent, so
    root authority", which would make ledger overflow an escalation channel.
    """

    max_entries: int = 4096
    _entries: OrderedDict[str, Authority] = field(default_factory=OrderedDict)

    def record(self, action_id: str, authority: Authority) -> None:
        if action_id not in self._entries and len(self._entries) >= self.max_entries:
            self._entries.popitem(last=False)  # FIFO: evict oldest
        self._entries[action_id] = authority

    def authority_for(self, action_id: str | None) -> Authority | None:
        """The authority recorded for `action_id`, or None if unknown/evicted."""
        if action_id is None:
            return None
        return self._entries.get(action_id)


class ScopeLookup(Protocol):
    """The injected per-agent scope seam (the control-plane ResourceStore satisfies it).

    Structural, like `PolicyEngine`/`IdentityEngineProtocol`, so this package keeps
    its single internal dependency on `agentos-contract`.
    """

    def scope_for(self, agent_id: str) -> frozenset[str]: ...


class DelegationResolver:
    """Resolves the authority in force for an action, following its lineage (TRST-04).

    An action with no `parent_action_id` is a chain ROOT and acts with its own
    trust and scope. An action WITH one inherits through `delegate()`, so its
    authority is capped by the delegator's.

    ## Unknown lineage fails closed

    If the parent's authority is not in the ledger, this denies. That is the whole
    security property: treating unknown lineage as "no parent, therefore root"
    would hand an attacker the laundering path back — a distrusted principal
    delegates to a trusted agent, the parent link is missing (evicted, or simply
    never recorded because the attacker invented the id), and the delegate acts
    with its own full trust. Ledger misses must never be an escalation channel.

    The honest cost: the ledger is in-process and non-persistent (see
    `DelegationLedger`), so after a restart an action referencing a pre-restart
    parent is denied until its chain is re-rooted. That is a deliberate
    availability-for-safety trade, consistent with the project's fail-closed
    posture. `allow_unknown_lineage=True` inverts it for deployments that would
    rather serve than be safe — it is NOT the default, and it reopens the
    laundering hole it names.
    """

    def __init__(
        self,
        scope_lookup: ScopeLookup,
        *,
        ledger: DelegationLedger | None = None,
        decay: float = DEFAULT_DECAY,
        max_depth: int = DEFAULT_MAX_DEPTH,
        allow_unknown_lineage: bool = False,
    ) -> None:
        self._scope = scope_lookup
        self._ledger = ledger or DelegationLedger()
        self._decay = decay
        self._max_depth = max_depth
        self._allow_unknown_lineage = allow_unknown_lineage

    def resolve(self, action: AgentAction, own_trust: float) -> Authority:
        """The authority `action` acts with. Raises `DelegationDenied` to block it.

        Records the result in the ledger keyed by this action's id, so actions
        delegated FROM it inherit this link rather than a root.
        """
        own_scope = self._scope.scope_for(action.agent_id)
        parent_id = action.context.parent_action_id
        parent = self._ledger.authority_for(str(parent_id) if parent_id else None)

        if parent_id is None:
            authority = Authority(
                agent_id=action.agent_id, trust=own_trust, scope=own_scope, depth=0
            )
        elif parent is None:
            if not self._allow_unknown_lineage:
                raise DelegationDenied(
                    f"unresolvable delegation lineage: parent action {parent_id} is not in the "
                    f"ledger, so {action.agent_id!r} cannot be bounded by its delegator"
                )
            authority = Authority(
                agent_id=action.agent_id, trust=own_trust, scope=own_scope, depth=0
            )
        else:
            authority = delegate(
                parent,
                action.agent_id,
                child_trust=own_trust,
                child_scope=own_scope,
                decay=self._decay,
                max_depth=self._max_depth,
            )

        self._ledger.record(str(action.id), authority)
        return authority
