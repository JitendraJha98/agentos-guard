"""ABOM-03 — vulnerability impact analysis: which agents use compromised component vX?

THE QUESTION THIS ANSWERS, AND WHY SPEED IS THE REQUIREMENT. A CVE lands, or a threat feed names a
backdoored package, and the only question that matters in the next ten minutes is *who is exposed*.
An operator who has to grep manifests or ask each team is doing incident response by interview. The
requirement says "instantly" for that reason: the answer has to come from data the control plane
already holds, in one query, while the incident is live.

IT READS WHAT ABOM-01/02 ALREADY RECORD. Phase 8 persists each agent's components with a content
DIGEST and provenance (`first_seen`, `version`, `source`). SEC-08 already cross-references a known-bad
set for the *pipeline* decision. This module asks the same set the other way round: not "may this
action proceed" but "given this component, who is affected" — the inverse index over the same facts,
so the two can never disagree about what is compromised.

DIGEST FIRST, NAME SECOND, AND THE DIFFERENCE MATTERS. A digest identifies a specific compromised
BUILD; a name identifies a component pulled in its entirety. An operator told "you use `left-pad`"
when only one build was backdoored will rip out something that was fine; one told only about the
digest will miss agents on an unrecorded build of the same bad package. Both are reported, and each
match says WHICH it was, because the remediation differs.

WHAT A MISS MEANS. An agent absent from this answer is an agent with no matching ABOM entry — which
is not the same as an agent that is safe. An agent that never declared an ABOM has nothing to match,
so the result reports how many agents were searched and how many hold no ABOM at all. Silence about
that would let a fleet with two declared manifests out of two hundred read as "only two exposed".
"""

from __future__ import annotations

from dataclasses import dataclass

# One incident read. Bounded like every other operator route: the answer is a list of agents, and a
# fleet is unbounded. Truncation is reported, never silent — an under-reported blast radius during an
# incident is the worst possible time to discover a cap.
_MAX_AGENTS = 1000
_MAX_MATCHES = 2000

MATCH_DIGEST = "digest"
MATCH_NAME = "name"


@dataclass(frozen=True)
class Match:
    """One affected agent, and what it was matched on.

    `matched_on` is a stable key rather than prose because the remediation differs: a digest match
    means "this agent is on the compromised build", a name match means "this agent uses the component
    but we could not confirm which build".
    """

    agent_id: str
    kind: str
    name: str
    digest: str
    matched_on: str
    version: int | None = None
    first_seen: str | None = None

    def as_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "kind": self.kind,
            "name": self.name,
            "digest": self.digest,
            "matched_on": self.matched_on,
            "version": self.version,
            "first_seen": self.first_seen,
        }


class ImpactAnalyzer:
    """ABOM-03 — the inverse index over ABOM components.

    `resources` is the Phase-5 `ResourceStore` (it owns `get_abom_components`). Deliberately not a
    new table: a second copy of the component set would be a second answer to "who uses this", and
    the stale one would be the one consulted during an incident.
    """

    def __init__(self, resources, session_factory) -> None:
        self._resources = resources
        self._sf = session_factory

    def _agent_ids(self, limit: int) -> tuple[list[str], int]:
        """Every agent holding an ABOM row, and the total that exist."""
        from sqlalchemy import func, select

        from agentos_controlplane.store.models import Abom

        with self._sf() as session:
            total = session.scalar(select(func.count()).select_from(Abom)) or 0
            ids = list(
                session.scalars(select(Abom.agent_id).order_by(Abom.agent_id).limit(limit)).all()
            )
        return ids, total

    def who_uses(
        self,
        *,
        digest: str | None = None,
        name: str | None = None,
        limit: int = _MAX_AGENTS,
    ) -> dict:
        """Which agents hold a component matching `digest` and/or `name`.

        At least one of the two is required. A call with neither would return the whole fleet, which
        is not an impact analysis — it is an inventory, and answering it here would let a typo read
        as "everything is compromised".
        """
        if not digest and not name:
            raise ValueError(
                "an impact query needs a digest or a name: with neither, the answer is the whole "
                "fleet, which is an inventory rather than an impact analysis"
            )
        bound = max(1, min(int(limit), _MAX_AGENTS))
        agent_ids, total_agents = self._agent_ids(bound)
        matches: list[Match] = []
        without_abom = 0
        for agent_id in agent_ids:
            components = self._resources.get_abom_components(agent_id)
            if not components:
                # An ABOM row with no provenance-tracked components (a raw Phase-5 put_abom). It has
                # nothing to match, and counting it as unaffected would be a claim about an agent we
                # know nothing about.
                without_abom += 1
                continue
            for component in components:
                if len(matches) >= _MAX_MATCHES:
                    break
                matched_on = _match(component, digest, name)
                if matched_on is None:
                    continue
                matches.append(
                    Match(
                        agent_id=agent_id,
                        kind=str(component.get("kind", "")),
                        name=str(component.get("name", "")),
                        digest=str(component.get("digest", "")),
                        matched_on=matched_on,
                        version=component.get("version"),
                        first_seen=component.get("first_seen"),
                    )
                )
        return {
            "query": {"digest": digest, "name": name},
            "matches": [m.as_dict() for m in matches[:_MAX_MATCHES]],
            "affected_agents": sorted({m.agent_id for m in matches[:_MAX_MATCHES]}),
            # The three counts that keep a small answer from reading as a small blast radius.
            "agents_searched": len(agent_ids),
            "agents_total": total_agents,
            "agents_without_components": without_abom,
            "truncated": total_agents > len(agent_ids) or len(matches) > _MAX_MATCHES,
        }

    def impact_of(self, known_bad, *, limit: int = _MAX_AGENTS) -> dict:
        """The whole known-bad set at once, for the "a feed just updated" case.

        Takes SEC-08's own `KnownBad` rather than a private copy of it, so the set this reports on is
        the set the pipeline is actually denying against.
        """
        digests = sorted(getattr(known_bad, "digests", set()) or set())
        names = sorted(getattr(known_bad, "names", set()) or set())
        if not digests and not names:
            return {
                "matches": [], "affected_agents": [], "agents_searched": 0,
                "agents_total": 0, "agents_without_components": 0, "truncated": False,
                "query": {"digests": [], "names": []},
            }
        seen: dict[tuple, dict] = {}
        searched = total = without = 0
        truncated = False
        for value, key in [(d, "digest") for d in digests] + [(n, "name") for n in names]:
            result = self.who_uses(**{key: value}, limit=limit)
            searched = max(searched, result["agents_searched"])
            total = max(total, result["agents_total"])
            without = max(without, result["agents_without_components"])
            truncated = truncated or result["truncated"]
            for match in result["matches"]:
                # Keyed so one component matching on BOTH digest and name is one finding, not two —
                # an inflated affected-count is as misleading as a deflated one during an incident.
                seen[(match["agent_id"], match["kind"], match["name"], match["digest"])] = match
        matches = sorted(seen.values(), key=lambda m: (m["agent_id"], m["kind"], m["name"]))
        return {
            "query": {"digests": digests, "names": names},
            "matches": matches,
            "affected_agents": sorted({m["agent_id"] for m in matches}),
            "agents_searched": searched,
            "agents_total": total,
            "agents_without_components": without,
            "truncated": truncated,
        }


def _match(component: dict, digest: str | None, name: str | None) -> str | None:
    """Which criterion this component matched, or None.

    Digest is checked FIRST: it is the more specific claim, and when both match an operator should be
    told they are on the compromised build rather than merely using the component.
    """
    if digest and str(component.get("digest", "")) == digest:
        return MATCH_DIGEST
    if name and str(component.get("name", "")) == name:
        return MATCH_NAME
    return None
