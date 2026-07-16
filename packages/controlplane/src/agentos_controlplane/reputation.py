"""TRST-03 — longitudinal reputation derived from violation/approval history.

Phase 1 seeded trust as a flat, hand-set 0-1 number (`Agent.trust_score`,
`DEFAULT_TRUST_SCORE`). This module earns it instead: every governed action the
agent has already taken, and every human ruling on its parked approvals, is
replayed as a time-decayed signal into a single 0-1 score that the
graduated-response stage consumes (via `Registry.load_trust`).

## The model

Two terms, deliberately:

1. **Earned score** — a Beta-style posterior over good/bad evidence with a
   symmetric prior, so *no history returns the seed* rather than inventing an
   opinion, and the score moves smoothly as evidence accrues.

2. **Violation ceiling** — a hard cap `1 / (1 + bad)` that no amount of good
   behaviour can lift.

`reputation = min(earned, ceiling)`.

The ceiling is the whole point, and it is why this is not a success-rate counter.
Without it, an agent farms trust: 1000 compliant calls bury one exfiltration
attempt and the ratio barely twitches (Pitfall 10 — the same trust-farming attack
`graduated.py` defends against by refusing to let trust ever RELAX a decision).
With it, good conduct is diluted by volume while a violation is not:

    1 fresh deny + 1000 allows -> ceiling 1/(1+4) = 0.2, earned ~0.99 -> **0.2**

Only *time* heals. Every signal's weight decays by `0.5 ** (age / HALF_LIFE_S)`,
so `bad` shrinks as the violation recedes, the ceiling rises back toward 1.0, and
a reformed agent recovers on its own. That is the "longitudinal" in TRST-03: the
score reflects conduct over time, not a lifetime tally.

Advisory posture is unchanged (TRST-02): this only produces a *number*. Trust
still modulates within the policy-defined band and can never relax the
deterministic policy floor — see `agentos_pipeline.graduated`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.store.models import Agent, ApprovalRequest, AuditRecord, TrustProfile


class UnknownAgentError(Exception):
    """Raised when scoring an agent that was never registered."""

# One week: a violation loses half its weight every 7 days, so an agent that stops
# offending recovers over ~a month rather than being branded for life.
HALF_LIFE_S = 7 * 86400.0

# Symmetric Beta prior. Chosen so that with no evidence the posterior is exactly
# 0.5 == DEFAULT_TRUST_SCORE, letting `score([])` return the seed by construction
# rather than by a special case.
PRIOR = 2.0

# Evidence weights. Adverse signals outweigh compliant ones by design: one deny is
# far more informative about an agent than one uneventful allow.
#
# `require_approval` is deliberately weightless HERE — parking an action is not
# itself misconduct, and its true signal is the human's ruling, counted from the
# approval table. Weighting both would double-count the same event.
_AUDIT_WEIGHTS: dict[str, tuple[float, float]] = {
    # label:                (good, bad)
    "allow": (1.0, 0.0),
    "warn": (0.0, 0.5),
    "governance_review": (0.0, 0.5),
    "sandbox": (0.0, 1.0),
    "require_consensus": (0.0, 0.5),
    "temporary_exception": (0.0, 0.5),
    "require_approval": (0.0, 0.0),  # see above — the resolution carries the signal
    "deny": (0.0, 4.0),
}

_APPROVAL_WEIGHTS: dict[str, tuple[float, float]] = {
    "approved": (2.0, 0.0),  # a human vouched for it
    "denied": (0.0, 8.0),    # a human judged it bad — the strongest signal we have
    "timed_out": (0.0, 1.0),  # nobody was willing to vouch
    "pending": (0.0, 0.0),   # unresolved: no evidence yet
}


@dataclass(frozen=True)
class ReputationSignal:
    """One piece of dated evidence about an agent.

    `kind` selects the weight table ("audit" | "approval"), `label` is the outcome
    or approval status, and `age_s` is the signal's age in seconds at scoring time.
    """

    kind: str
    label: str
    age_s: float


@dataclass(frozen=True)
class ReputationBreakdown:
    """The explainable form of a score (pillar 5 — never emit a bare number).

    `good`/`bad` are the decayed evidence masses; `ceiling` is the anti-farming cap.
    """

    agent_id: str
    score: float
    good: float
    bad: float
    earned: float
    ceiling: float
    signals: int


class ReputationScorer:
    """Turns dated evidence into a 0-1 reputation. Pure — no I/O, no clock."""

    def __init__(self, *, half_life_s: float = HALF_LIFE_S, prior: float = PRIOR) -> None:
        if half_life_s <= 0:
            raise ValueError(f"half_life_s must be > 0, got {half_life_s}")
        if prior <= 0:
            raise ValueError(f"prior must be > 0, got {prior}")
        self._half_life_s = half_life_s
        self._prior = prior

    def _decay(self, age_s: float) -> float:
        # Guard against clock skew producing a future-dated signal weighing >1.
        return 0.5 ** (max(age_s, 0.0) / self._half_life_s)

    def masses(self, signals: list[ReputationSignal]) -> tuple[float, float]:
        """Decayed (good, bad) evidence masses."""
        good = bad = 0.0
        for s in signals:
            table = _AUDIT_WEIGHTS if s.kind == "audit" else _APPROVAL_WEIGHTS
            # An unrecognized label contributes nothing rather than guessing a
            # weight — a new outcome must be scored deliberately, not by default.
            g, b = table.get(s.label, (0.0, 0.0))
            d = self._decay(s.age_s)
            good += g * d
            bad += b * d
        return good, bad

    def breakdown(
        self, signals: list[ReputationSignal], *, seed: float = 0.5, agent_id: str = ""
    ) -> ReputationBreakdown:
        good, bad = self.masses(signals)
        if good == 0.0 and bad == 0.0:
            # No evidence (or only weightless evidence): defer to the seed rather
            # than assert the prior's 0.5 over an operator's explicit choice.
            return ReputationBreakdown(agent_id, seed, 0.0, 0.0, seed, 1.0, len(signals))
        earned = (self._prior + good) / (2 * self._prior + good + bad)
        ceiling = 1.0 / (1.0 + bad)
        return ReputationBreakdown(
            agent_id=agent_id,
            score=min(earned, ceiling),
            good=good,
            bad=bad,
            earned=earned,
            ceiling=ceiling,
            signals=len(signals),
        )

    def score(self, signals: list[ReputationSignal], *, seed: float = 0.5) -> float:
        return self.breakdown(signals, seed=seed).score


def _age_s(then: datetime | None, now: float) -> float:
    if then is None:
        return 0.0
    # Rows are written UTC-aware on Postgres but come back naive from SQLite (D-14);
    # normalize both to an aware UTC instant before differencing.
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return now - then.timestamp()


class ReputationEngine:
    """Loads an agent's history and derives its reputation (TRST-03).

    Evidence sources are the two the requirement names: the audit log's decision
    outcomes (violation history) and the approval table's human rulings (approval
    history). Both are already written by the existing pipeline — reputation is a
    *derived* view, so it introduces no new write path on the hot path.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        scorer: ReputationScorer | None = None,
        window_s: float = 90 * 86400.0,
        max_signals: int = 5000,
    ) -> None:
        self._sf = session_factory
        self._scorer = scorer or ReputationScorer()
        # Bound the replay: past ~13 half-lives a signal's weight is <1e-4, so a
        # wider window costs I/O and changes nothing. `max_signals` bounds the
        # query for a hot agent (newest first — the ones that still carry weight).
        self._window_s = window_s
        self._max_signals = max_signals

    def signals_for(self, agent_id: str, *, now: float | None = None) -> list[ReputationSignal]:
        now = time.time() if now is None else now
        cutoff = datetime.fromtimestamp(now - self._window_s, tz=timezone.utc).replace(tzinfo=None)
        out: list[ReputationSignal] = []
        with self._sf() as s:
            audit_rows = s.scalars(
                select(AuditRecord)
                .where(AuditRecord.created_at >= cutoff)
                .order_by(AuditRecord.seq.desc())
                .limit(self._max_signals)
            ).all()
            for r in audit_rows:
                body = r.body or {}
                # Action records carry agent_id + outcome; lifecycle EVENT records
                # (append_event) carry neither and are skipped by these guards.
                if body.get("agent_id") != agent_id:
                    continue
                outcome = body.get("outcome")
                if not outcome:
                    continue
                out.append(
                    ReputationSignal(kind="audit", label=outcome, age_s=_age_s(r.created_at, now))
                )

            approval_rows = s.scalars(
                select(ApprovalRequest)
                .where(ApprovalRequest.agent_id == agent_id)
                .order_by(ApprovalRequest.created_at.desc())
                .limit(self._max_signals)
            ).all()
            for a in approval_rows:
                if a.status == "pending":
                    continue
                out.append(
                    ReputationSignal(
                        kind="approval",
                        label=a.status,
                        age_s=_age_s(a.resolved_at or a.created_at, now),
                    )
                )
        return out

    def breakdown(
        self, agent_id: str, *, seed: float = 0.5, now: float | None = None
    ) -> ReputationBreakdown:
        return self._scorer.breakdown(
            self.signals_for(agent_id, now=now), seed=seed, agent_id=agent_id
        )

    def score(self, agent_id: str, *, seed: float = 0.5, now: float | None = None) -> float:
        return self.breakdown(agent_id, seed=seed, now=now).score

    def refresh(self, agent_id: str, *, now: float | None = None) -> ReputationBreakdown:
        """Derive `agent_id`'s reputation and persist it to its TrustProfile.

        This is the write half of TRST-03 — the step that makes the derived score
        actually FEED graduated response, since `Registry.load_trust` resolves the
        TrustProfile first. Called on a schedule by the API-04 trust reconciler.

        The agent's existing profile trust (else its `Agent` seed) is the seed the
        scorer falls back to, so an agent with no history keeps the operator's
        chosen value instead of being reset to the prior.
        """
        with self._sf() as s:
            profile = s.get(TrustProfile, agent_id)
            agent = s.get(Agent, agent_id)
            if profile is None and agent is None:
                raise UnknownAgentError(f"cannot score unregistered agent {agent_id!r}")
            seed = profile.trust_score if profile is not None else agent.trust_score
            band = profile.band if profile is not None else None

        result = self.breakdown(agent_id, seed=seed, now=now)

        with self._sf() as s:
            profile = s.get(TrustProfile, agent_id)
            if profile is None:
                s.add(TrustProfile(agent_id=agent_id, trust_score=result.score, band=band, version=1))
            else:
                # No expected_version guard: the reconciler is a derived-state writer,
                # not a competing author. A racing operator PUT wins the row and the
                # next reconcile pass re-derives from it — last-writer-wins is correct
                # here precisely because reputation is recomputable from the audit log.
                profile.trust_score = result.score
            s.commit()
        return result

    def refresh_all(self, *, now: float | None = None) -> list[ReputationBreakdown]:
        """Refresh every registered agent (the reconciler's per-pass unit of work)."""
        with self._sf() as s:
            agent_ids = list(s.scalars(select(Agent.agent_id).order_by(Agent.agent_id)).all())
        return [self.refresh(a, now=now) for a in agent_ids]
