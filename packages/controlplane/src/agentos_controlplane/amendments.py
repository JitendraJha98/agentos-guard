"""POL-10 — the Constitution as an amendable governing document.

A CONSTITUTION THAT CANNOT BE AMENDED IS EDITED INSTEAD. Operators change the rules either way; the
only question is whether the change leaves a record of who asked, who agreed, and what it replaced.
This module makes that change a first-class, audited act rather than a resource write nobody can
reconstruct afterwards.

WHO MAY DO WHAT. An agent may PROPOSE — that is the point of POL-10's "agents or the self-play
trainer". Only a human may RATIFY. This is the POL-13 rule applied to the governing document itself:
the interpreter may recommend a temporary exception and may never grant one, and by the same
reasoning a system that could ratify its own amendments could rewrite the rules it is governed by.

A PROPOSAL IS INERT. Nothing on the decision path reads this table. A pending proposal changes no
outcome, and the test suite asserts that by evaluating an action against one — because the entire
value of a ratification step is that the un-ratified state means nothing.

WHAT THIS DOES NOT REBUILD. `ConstitutionResource` is already append-only: `version` is a unique
content hash, `source` is the authored document verbatim, and `apply_constitution` inserts rather
than edits. So "the old text survives" is already structurally true, and POL-08 already pins
`constitution_version` on every Decision. Ratification therefore goes through that SAME
`apply_constitution` path — compile-on-write, versioning and the policy row all behave identically to
any other constitution write — and this module adds the provenance and the history that make the
existing version chain readable as a record of authority. Building a parallel version store would
have created a second source of truth about what the constitution said, and the disagreement would
surface during an audit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import select

from agentos_controlplane.approvals import AlreadyResolvedError
from agentos_controlplane.store.models import Amendment, ConstitutionResource

_TITLE_MAX = 255
_RATIFIER_MAX = 128
_MAX_ROWS = 200

PROPOSED = "proposed"
RATIFIED = "ratified"
REJECTED = "rejected"
WITHDRAWN = "withdrawn"
_TERMINAL = frozenset({RATIFIED, REJECTED, WITHDRAWN})


@dataclass(frozen=True)
class AmendmentData:
    id: str
    title: str
    rationale: str
    proposed_by: str
    status: str
    ratified_by: str | None
    resolution_note: str | None
    constitution_version: str | None
    proposed_at: str | None
    resolved_at: str | None

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "rationale": self.rationale,
            "proposed_by": self.proposed_by,
            "status": self.status,
            "ratified_by": self.ratified_by,
            "resolution_note": self.resolution_note,
            "constitution_version": self.constitution_version,
            "proposed_at": self.proposed_at,
            "resolved_at": self.resolved_at,
        }


def _row(row: Amendment) -> AmendmentData:
    return AmendmentData(
        id=str(row.id),
        title=row.title,
        rationale=row.rationale,
        proposed_by=row.proposed_by,
        status=row.status,
        ratified_by=row.ratified_by,
        resolution_note=row.resolution_note,
        constitution_version=row.constitution_version,
        proposed_at=row.proposed_at.isoformat() if row.proposed_at else None,
        resolved_at=row.resolved_at.isoformat() if row.resolved_at else None,
    )


def _utcnow() -> datetime:
    """UTC-naive, matching every other datetime this schema stores (SQLite drops tz offsets)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AmendmentStore:
    """Proposals, ratification, and the constitution history that results.

    `resources` is the Phase-5 `ResourceStore`. It is REQUIRED for `propose` and `ratify` — a store
    that could not compile a proposal would accept text nobody had checked, and a store that could
    not apply one could mark an amendment `ratified` while the constitution never changed. Either
    would be a lie recorded in the audit chain.
    """

    def __init__(self, session_factory, audit, resources) -> None:
        self._sf = session_factory
        self._audit = audit
        self._resources = resources

    async def propose(self, title: str, rationale: str, proposed_by: str, source: dict) -> str:
        """Record a proposed amendment. Returns its id.

        COMPILES THE PROPOSAL FIRST. An amendment that cannot compile is not something a human should
        be asked to review: the error belongs in front of the proposer, who can fix it, rather than in
        front of the ratifier, who cannot. `validate_constitution` raises `ConstitutionError` and
        nothing is written.
        """
        title = (title or "").strip()
        if not title or len(title) > _TITLE_MAX:
            raise ValueError(f"title must be 1..{_TITLE_MAX} characters")
        if not (proposed_by or "").strip():
            raise ValueError("proposed_by is required: an unattributed proposal has no proposer")
        # Raises ConstitutionError on invalid/uncompilable source, before any write.
        self._resources.validate_constitution(source)
        amendment_id = uuid4()
        with self._sf() as s:
            s.add(
                Amendment(
                    id=amendment_id,
                    title=title,
                    rationale=rationale or "",
                    proposed_by=proposed_by.strip(),
                    source=source,
                    status=PROPOSED,
                )
            )
            s.commit()
        # Audited AFTER the commit, with identifiers only. The proposed document already has a row;
        # putting it in the hash chain would bloat every verification pass for no gain, and the text
        # is the one part of an amendment that can be arbitrarily large.
        await self._audit.append_event(
            "amendment_proposed",
            {"amendment_id": str(amendment_id), "title": title, "proposed_by": proposed_by.strip()},
        )
        return str(amendment_id)

    async def ratify(self, amendment_id, ratified_by: str, note: str | None = None) -> str:
        """The human half, and the ONLY transition that changes what the Constitution says.

        Applies the proposal through `apply_constitution`, so compile-on-write, versioning and the
        policy row behave exactly as they do for any other constitution write. Returns the new
        version.
        """
        ratifier = (ratified_by or "").strip()
        if not ratifier or len(ratifier) > _RATIFIER_MAX:
            # An amendment with no ratifier named is not human-ratified, whatever the status column
            # says — and "human-ratified" is the entire claim POL-10 makes about this transition.
            raise ValueError("ratified_by is required: an unattributed ratification is not one")
        with self._sf() as s:
            row = s.get(Amendment, _as_uuid(amendment_id))
            if row is None:
                raise KeyError(f"unknown amendment {amendment_id}")
            if row.status in _TERMINAL:
                raise AlreadyResolvedError(f"amendment is already {row.status}")
            source, title = row.source, row.title
        # Applied OUTSIDE the session above so a compile failure cannot leave a half-written
        # transition, and applied BEFORE the status flip so an amendment is never marked ratified
        # against a constitution that was never written.
        constitution, _policy = self._resources.apply_constitution(title, source)
        with self._sf() as s:
            row = s.get(Amendment, _as_uuid(amendment_id))
            if row.status in _TERMINAL:
                raise AlreadyResolvedError(f"amendment is already {row.status}")
            row.status = RATIFIED
            row.ratified_by = ratifier
            row.resolution_note = note
            row.constitution_version = constitution.version
            row.resolved_at = _utcnow()
            s.commit()
        await self._audit.append_event(
            "amendment_resolved",
            {
                "amendment_id": str(amendment_id),
                "status": RATIFIED,
                "resolved_by": ratifier,
                "constitution_version": constitution.version,
            },
        )
        return constitution.version

    async def resolve_without_ratifying(self, amendment_id, status: str, by: str,
                                        note: str | None = None) -> None:
        """Reject or withdraw: terminal, audited, and constitutionally inert.

        One method for both because they differ only in who is declining and why, and a separate
        near-identical transition is where a missing guard hides.
        """
        if status not in {REJECTED, WITHDRAWN}:
            raise ValueError(f"status must be {REJECTED!r} or {WITHDRAWN!r}, got {status!r}")
        actor = (by or "").strip()
        if not actor:
            raise ValueError("an unattributed resolution has no resolver")
        with self._sf() as s:
            row = s.get(Amendment, _as_uuid(amendment_id))
            if row is None:
                raise KeyError(f"unknown amendment {amendment_id}")
            if row.status in _TERMINAL:
                raise AlreadyResolvedError(f"amendment is already {row.status}")
            row.status = status
            row.resolution_note = note
            row.resolved_at = _utcnow()
            # constitution_version deliberately untouched: nothing was applied, so claiming a version
            # would attribute a constitution to an amendment that never took effect.
            s.commit()
        await self._audit.append_event(
            "amendment_resolved",
            {"amendment_id": str(amendment_id), "status": status, "resolved_by": actor},
        )

    def get(self, amendment_id) -> AmendmentData | None:
        with self._sf() as s:
            row = s.get(Amendment, _as_uuid(amendment_id))
            return None if row is None else _row(row)

    def list_amendments(self, status: str | None = None, limit: int = _MAX_ROWS) -> list[dict]:
        bound = max(1, min(int(limit), _MAX_ROWS))
        with self._sf() as s:
            stmt = select(Amendment).order_by(Amendment.proposed_at.desc(), Amendment.id.desc())
            if status is not None:
                stmt = stmt.where(Amendment.status == status)
            return [_row(r).as_dict() for r in s.scalars(stmt.limit(bound)).all()]

    def constitution_history(self, limit: int = _MAX_ROWS) -> list[dict]:
        """What the Constitution has said, when, and on whose authority.

        A version with no amendment behind it was an operator's DIRECT write — a different act from a
        ratified amendment, and shown as `amendment: null` rather than left blank, because a reader
        needs to tell "nobody ratified this" from "we lost the record".
        """
        bound = max(1, min(int(limit), _MAX_ROWS))
        with self._sf() as s:
            versions = s.scalars(
                select(ConstitutionResource)
                .order_by(ConstitutionResource.created_at.desc(), ConstitutionResource.id.desc())
                .limit(bound)
            ).all()
            by_version = {
                a.constitution_version: a
                for a in s.scalars(
                    select(Amendment).where(Amendment.constitution_version.is_not(None))
                ).all()
            }
            out = []
            for v in versions:
                amendment = by_version.get(v.version)
                out.append(
                    {
                        "version": v.version,
                        "name": v.name,
                        "created_at": v.created_at.isoformat() if v.created_at else None,
                        "amendment": None
                        if amendment is None
                        else {
                            "id": str(amendment.id),
                            "title": amendment.title,
                            "proposed_by": amendment.proposed_by,
                            "ratified_by": amendment.ratified_by,
                        },
                    }
                )
            return out


def _as_uuid(value) -> UUID:
    return value if isinstance(value, UUID) else UUID(str(value))
