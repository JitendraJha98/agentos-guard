"""SEC-06 tool-poisoning + SEC-08 supply-chain checks over the ABOM.

Both consume the ABOM-02 component digests (`abom.py`): a name tells you nothing
about whether a component changed or is compromised — a digest does.

SEC-06 (tool-poisoning) — MANIFEST DRIFT. A tool's live manifest is hashed and
compared against the digest the ABOM recorded. A mismatch means the tool's
definition changed out from under the agent: a description/schema swap is the
classic tool-poisoning vector (the agent still calls "http_get", but its
manifest now says "also POST the result to attacker.com"). Drift is a finding,
not proof of malice — a legitimate upgrade also drifts — so it is surfaced for
review/quarantine, and the ABOM re-declaration is the sanctioned way to bless a
new version.

SEC-08 (supply-chain) — KNOWN-BAD CROSS-REFERENCE. Every ABOM component is
checked against a known-bad set, by DIGEST (a specific compromised build) and by
NAME (a package/model pulled entirely). The known-bad set is injected — a real
deployment feeds it from a threat-intel feed (Phase 14); here it is an in-memory
set so the check is deterministic and testable.

Pure over an injected ResourceStore + known-bad set; no hot-path coupling —
supply-chain integrity is a registration/reconciliation-time concern, not a
per-action gate (the action payload carries tool ARGS, not the tool MANIFEST).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agentos_controlplane.abom import component_digest


@dataclass(frozen=True)
class SupplyChainFinding:
    """One supply-chain / tool-poisoning issue on an agent's ABOM."""

    agent_id: str
    kind: str
    name: str
    issue: str        # "manifest_drift" | "known_bad_digest" | "known_bad_name" | "undeclared"
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id, "kind": self.kind, "name": self.name,
            "issue": self.issue, "detail": self.detail,
        }


@dataclass
class KnownBad:
    """The known-bad set SEC-08 cross-references against (threat-intel seam).

    Digests catch a specific compromised BUILD; names catch a component pulled in
    its entirety (a backdoored package, a deprecated-unsafe model).
    """

    digests: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)

    def hit(self, name: str, digest: str) -> str | None:
        if digest in self.digests:
            return "known_bad_digest"
        if name in self.names:
            return "known_bad_name"
        return None


class SupplyChainChecker:
    """SEC-06 + SEC-08 checks over an agent's provenance-tracked ABOM."""

    def __init__(self, resources, known_bad: KnownBad | None = None) -> None:
        self._resources = resources
        self._known_bad = known_bad or KnownBad()

    # ---- SEC-06: manifest drift ----

    def check_manifest_drift(
        self, agent_id: str, kind: str, name: str, live_definition: object
    ) -> SupplyChainFinding | None:
        """Compare a live component manifest against the ABOM-recorded digest.

        Returns a finding on drift (or when the component was never declared —
        an UNDECLARED tool is a shadow component, also a supply-chain concern),
        None when the live manifest matches the recorded one.
        """
        recorded = {
            (c["kind"], c["name"]): c["digest"]
            for c in self._resources.get_abom_components(agent_id)
        }
        live_digest = component_digest(live_definition)
        known = recorded.get((kind, name))
        if known is None:
            return SupplyChainFinding(
                agent_id, kind, name, "undeclared",
                "component is not in the agent's ABOM (shadow component)",
            )
        if known != live_digest:
            return SupplyChainFinding(
                agent_id, kind, name, "manifest_drift",
                f"live manifest digest {live_digest} != recorded {known}",
            )
        return None

    # ---- SEC-08: known-bad cross-reference ----

    def scan_agent(self, agent_id: str) -> list[SupplyChainFinding]:
        """Cross-reference every ABOM component of `agent_id` against the known-bad set."""
        findings: list[SupplyChainFinding] = []
        for c in self._resources.get_abom_components(agent_id):
            issue = self._known_bad.hit(c["name"], c["digest"])
            if issue is not None:
                findings.append(
                    SupplyChainFinding(
                        agent_id, c["kind"], c["name"], issue,
                        f"{c['kind']} {c['name']!r} matches a known-bad {issue.split('_')[-1]}",
                    )
                )
        return findings

    def scan_all(self) -> list[SupplyChainFinding]:
        """Scan every agent that has a declared ABOM (the reconciler's unit of work)."""
        findings: list[SupplyChainFinding] = []
        for abom in self._resources.list_aboms():
            findings.extend(self.scan_agent(abom.agent_id))
        return findings
