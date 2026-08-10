"""POL-09 — application-level 2-of-3 consensus: the concrete ConsensusCoordinator.

`governed_call` routes a `require_consensus` outcome HERE instead of the real handler, and
the handler runs only if this returns True. Everything about that return is fail-closed:

* voters are asked CONCURRENTLY, each with its own timeout, so one unreachable voter cannot
  stall the action — but it cannot silently permit it either;
* a voter that RAISES or TIMES OUT counts as a NO-VOTE. An error is not consent, and neither
  is silence;
* only a genuine boolean `True` is an approval. A truthy non-bool (`"yes"`, `1`, an object)
  is recorded as a rejection, so a mis-implemented voter cannot smuggle an action past the
  quorum on Python's truthiness rules — the same rule the SDK gate applies to this class's
  own return value;
* voters must be DISTINCT (refused at construction) and are handed read-only COPIES of the
  action and decision, so a compromised voter can neither fill the quorum by itself nor
  rewrite what its peers judge, what the round attributes, or what then executes.

The round and every vote are persisted; each vote plus the resolution is audited with short
identifiers + counts only, so the AUD-04 secret gate on `append_event` can never refuse — and
thereby block the recording of — a consensus decision. Protocol-level BFT is POL-12 (Phase 13);
this is the application-level voting the roadmap scopes to Phase 9.
"""

from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

from agentos_contract import AgentAction, Decision

from agentos_controlplane.audit import AuditWriter
from agentos_controlplane.store.models import ConsensusRound, ConsensusVote


class StoreConsensusCoordinator:
    """Satisfies the SDK's `ConsensusCoordinator` Protocol structurally (no inheritance)."""

    def __init__(
        self,
        session_factory,
        audit: AuditWriter,
        voters,
        *,
        quorum: int = 2,
        timeout_s: float = 10.0,
    ) -> None:
        voters = list(voters)
        # A coordinator that cannot reach quorum by construction would deny every action
        # forever, and one whose quorum is 0 would approve every action without asking
        # anyone. Both are configuration bugs; refuse at construction, not per action.
        if not voters:
            raise ValueError("consensus requires at least one voter")
        if quorum < 1 or quorum > len(voters):
            raise ValueError(f"quorum must be between 1 and {len(voters)}, got {quorum}")
        # INDEPENDENCE is the security value of consensus: a duplicated entry silently reduces
        # 2-of-3 to 1-of-3 while the audit still shows three votes. Same class of configuration
        # bug as an impossible quorum — refuse at construction, not per action.
        if len({id(v) for v in voters}) != len(voters):
            raise ValueError("the same voter instance was supplied more than once")
        names = [v.name for v in voters]
        if len(set(names)) != len(names):
            raise ValueError(f"voter names must be distinct, got {names}")
        self._session_factory = session_factory
        self._audit = audit
        self._voters = voters
        self._quorum = quorum
        self._timeout_s = timeout_s

    async def _one_vote(self, voter, action, decision) -> tuple[str, bool, str | None]:
        """One voter's verdict, never raising: every failure mode becomes a NO-VOTE."""
        try:
            # A COPY per voter: consensus exists for the case where a voter is compromised or
            # disagrees, so no voter may rewrite the action its peers judge, the attribution the
            # round records, or the action the caller then executes under RUN-05/RUN-06. The
            # coordinator persists and audits from its own untouched `action`.
            verdict = await asyncio.wait_for(
                voter.vote(action.model_copy(deep=True), decision.model_copy(deep=True)),
                timeout=self._timeout_s,
            )
            # `is True`, not truthiness: only an explicit boolean approval counts.
            return (voter.name, verdict is True, None)
        except (asyncio.TimeoutError, TimeoutError):
            return (voter.name, False, "timeout")  # a timeout is a NO-VOTE, never an approval
        except Exception as exc:
            # The exception TYPE only — a voter's message is free text that could carry
            # secrets or attacker-influenced content into the record.
            return (voter.name, False, type(exc).__name__)

    async def reach_consensus(self, action: AgentAction, decision: Decision) -> bool:
        round_id = uuid4()
        # Concurrent: the round costs one voter's latency, not the sum of all of them.
        results = await asyncio.gather(
            *(self._one_vote(voter, action, decision) for voter in self._voters)
        )
        approvals = sum(1 for _, approved, _ in results if approved)
        reached = approvals >= self._quorum
        self._persist(round_id, action, results, approvals, reached)
        for name, approved, error in results:
            await self._audit.append_event(
                "consensus_vote",
                {
                    "round_id": str(round_id),
                    "action_id": str(action.id),
                    "voter": name,
                    "approved": approved,
                    "error": error or "",
                },
            )
        await self._audit.append_event(
            "consensus_resolved",
            {
                "round_id": str(round_id),
                "action_id": str(action.id),
                "agent_id": action.agent_id,
                "approvals": approvals,
                "voters": len(self._voters),
                "quorum": self._quorum,
                "reached": reached,
            },
        )
        return reached

    def _persist(
        self,
        round_id: UUID,
        action: AgentAction,
        results: list[tuple[str, bool, str | None]],
        approvals: int,
        reached: bool,
    ) -> None:
        with self._session_factory() as session:
            session.add(
                ConsensusRound(
                    id=round_id,
                    action_id=action.id,
                    agent_id=action.agent_id,
                    voters=len(self._voters),
                    approvals=approvals,
                    quorum=self._quorum,
                    reached=reached,
                )
            )
            for name, approved, error in results:
                session.add(
                    ConsensusVote(
                        round_id=round_id, voter=name, approved=approved, error=error
                    )
                )
            session.commit()
