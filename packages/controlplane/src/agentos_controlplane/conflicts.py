"""POL-11 — transitive permissions across delegation chains, and the conflicts they emerge into.

WHY A CLOSURE AND NOT A LOOKUP. One hop is already answered: TRST-04 intersects parent and child
scope at delegation time. What no single hop can answer is what an agent five hops down actually
holds, or whether two routes to the same agent agree about it. Those are properties of the CHAIN, and
an operator granting a capability at the top has no way to see them.

INTERSECTION ALONG THE WHOLE PATH, NEVER A UNION. `effective_scope` narrows at every hop. A union
would let a chain manufacture a capability nobody in it held — trust laundering by composition, which
is the escalation TRST-04 exists to stop. The subset property is tested over RANDOM chains, because
that is the invariant a refactor inverts while every hand-written example still passes.

IT REPORTS; IT DOES NOT DENY. POL-11 says "flags". The floor invariant (POL-05/TRST-02) is that the
constitution decides and everything else may only restrict, so an engine that denied on its own
authority would be a second enforcer beside the policy floor — exactly what ECON-02 was written to
avoid. A test asserts an action's outcome is unchanged by the presence of a finding.

WHAT A LINEAGE FINDING CAN AND CANNOT SAY. Phase 12 shipped the evidence graph with lineage labelled
CLAIMED, because `identity_verified` authenticates who ACTED and `parent_action_id` is supplied by the
caller. This module can now cross-check a claimed edge against recorded delegation authority — which
upgrades the claim to CORROBORATED or NOT CORROBORATED, and no further. It cannot say the delegation
did not happen: the TRST-04 ledger is in-process, non-persistent and FIFO-evicted by its own
documentation, so an absent entry is routine rather than evidence. "Unverified" and "false" are
different accusations, and only one of them is supportable here.

BOUNDED AND CYCLE-SAFE, for the reason 12e's walk is: the edges are caller-supplied, a cycle is
assertable by the agent under investigation, and this is a tool an operator reaches for DURING an
incident. The chain walking itself REUSES `forensics.EvidenceGraph` rather than reimplementing a
second bounded walk — two walks over one lineage would drift, and the one that drifted would be the
one nobody was looking at.
"""

from __future__ import annotations

from dataclasses import dataclass

from agentos_pipeline.delegation import WILDCARD, intersect_scope

# One agent's closure. A fan-out explodes the path count long before the depth cap is reached, so
# both are bounded and both truncations are reported.
_MAX_PATHS = 200
_MAX_FINDINGS = 200

_NOT_CORROBORATED = (
    "the delegation ledger holds no authority for the claimed parent, so this edge is NOT "
    "CORROBORATED. That is weaker than false: the ledger is in-process, non-persistent and "
    "FIFO-evicted, so an absent entry is routine and is not proof the delegation never happened."
)


@dataclass(frozen=True)
class Finding:
    """One conflict. `kind` is a stable key so a consumer filters on it rather than on prose."""

    kind: str
    agent_id: str
    detail: str
    capabilities: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "agent_id": self.agent_id,
            "detail": self.detail,
            "capabilities": list(self.capabilities),
        }


def effective_scope(scopes) -> frozenset[str]:
    """Fold TRST-04's own `intersect_scope` along a path of per-hop scopes.

    Reuses that function rather than reimplementing the rule, so the one-hop and many-hop semantics
    cannot drift. An empty path is the wildcard — there is no hop to narrow anything — which is the
    identity for intersection and not a grant.
    """
    result = frozenset({WILDCARD})
    for scope in scopes:
        result = intersect_scope(result, frozenset(scope))
    return result


class ConflictEngine:
    """Computes permission closures over delegation chains and reports conflicts (POL-11).

    `graph` is a `forensics.EvidenceGraph` (the bounded, cycle-safe lineage walk from 12e).
    `ledger` is the TRST-04 `DelegationLedger`. `scopes` is an optional `ScopeLookup`; without it the
    closure reports structure without capability detail rather than inventing a scope.
    """

    def __init__(self, graph, session_factory, ledger=None, scopes=None) -> None:
        self._graph = graph
        # Taken explicitly rather than read off `graph._sf`: reaching into another object's private
        # attribute makes this module break the moment that one is refactored, and the coupling would
        # not show up in either class's signature.
        self._sf = session_factory
        self._ledger = ledger
        self._scopes = scopes

    def _scope_of(self, agent_id: str) -> frozenset[str]:
        """The agent's own declared scope, or the wildcard when no lookup is wired.

        The wildcard is the honest default here: with no scope source, "unconstrained" is what we
        know, and substituting the empty set would report every capability as lost by every chain.
        """
        if self._scopes is None:
            return frozenset({WILDCARD})
        try:
            return frozenset(self._scopes.scope_for(agent_id))
        except Exception:
            return frozenset({WILDCARD})

    def closure(self, action_id: str) -> dict:
        """The chain reaching `action_id`, with the effective scope at its end.

        Built from the audit lineage rather than a separate graph, so what this reports is what the
        chain actually recorded.
        """
        chain = self._graph.ancestors(str(action_id))
        # `ancestors` is nearest-first; a permission narrows from the ROOT down, so fold in the
        # opposite order to the one the walk returns.
        hops = list(reversed(chain.records))
        agents = [r.get("agent_id") for r in hops if r.get("agent_id")]
        scope = effective_scope(self._scope_of(a) for a in agents)
        return {
            "action_id": str(action_id),
            "chain": [{"seq": r.get("seq"), "agent_id": r.get("agent_id"),
                       "action_type": r.get("action_type")} for r in hops],
            "agents": agents,
            "effective_scope": sorted(scope),
            "truncated": chain.truncated,
            "lineage": chain.lineage,
        }

    def conflicts(self, limit: int = _MAX_FINDINGS) -> dict:
        """The three emergent findings, each a thing no single hop can show."""
        findings: list[Finding] = []
        truncated = False

        by_agent: dict[str, set[frozenset[str]]] = {}

        for record in self._recent_delegated_records():
            if len(findings) >= limit:
                truncated = True
                break
            agent_id = record.get("agent_id") or ""
            parent = record.get("parent_action_id")
            # (1) unauthorized_lineage — a claimed edge the ledger does not corroborate.
            if parent and self._ledger is not None:
                if self._ledger.authority_for(str(parent)) is None:
                    findings.append(
                        Finding("unauthorized_lineage", agent_id, _NOT_CORROBORATED)
                    )
            closure = self.closure(record.get("action_id") or "")
            by_agent.setdefault(agent_id, set()).add(frozenset(closure["effective_scope"]))

        for agent_id, seen in sorted(by_agent.items()):
            if len(findings) >= limit:
                truncated = True
                break
            # (2) divergent_paths — two routes conferring different effective scope. The agent's
            # capability then depends on which route a caller used, which is not a permission model
            # anyone can reason about.
            if len(seen) > 1:
                differing = sorted(set().union(*seen) - set.intersection(*(set(s) for s in seen)))
                findings.append(
                    Finding(
                        "divergent_paths",
                        agent_id,
                        "two or more delegation paths reach this agent conferring different "
                        "effective scope, so what it may do depends on which path a caller used",
                        tuple(differing),
                    )
                )
            # (3) capability_lost — held directly, intersected away by every path that reaches it.
            own = self._scope_of(agent_id)
            if WILDCARD not in own and seen:
                reachable = set().union(*(set(s) for s in seen))
                lost = sorted(c for c in own if c not in reachable and WILDCARD not in reachable)
                if lost:
                    findings.append(
                        Finding(
                            "capability_lost",
                            agent_id,
                            "this agent holds these capabilities directly, but every delegation "
                            "path reaching it intersects them away — an operator who granted at "
                            "the top cannot see the hop that removed them",
                            tuple(lost),
                        )
                    )

        return {
            "findings": [f.as_dict() for f in findings[:limit]],
            "truncated": truncated or len(findings) > limit,
        }

    def _recent_delegated_records(self) -> list[dict]:
        """Audit records that CLAIM a parent — the only ones a chain conflict can arise from."""
        from sqlalchemy import select

        from agentos_controlplane.store.models import AuditRecord

        with self._sf() as session:
            rows = session.scalars(
                select(AuditRecord).order_by(AuditRecord.seq.desc()).limit(_MAX_PATHS)
            ).all()
        out = []
        for row in rows:
            body = row.body or {}
            if body.get("parent_action_id"):
                out.append(
                    {
                        "action_id": body.get("action_id"),
                        "agent_id": body.get("agent_id"),
                        "parent_action_id": body.get("parent_action_id"),
                    }
                )
        return out
