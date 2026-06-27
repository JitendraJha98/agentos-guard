"""API-01 — declarative resource persistence with optimistic versioning.

Sync store over the shared session_factory (D-14 SQLite now, Postgres target). Each mutable
resource is keyed by agent_id and carries a monotonic `version`; an update supplying a stale
(or missing) version raises VersionConflict -> the API maps it to 409. A create supplies no
version (or 0/1) and starts at version 1.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from agentos_controlplane.store.models import Abom, TrustProfile


class VersionConflict(Exception):
    """Optimistic-concurrency failure: the supplied version != the current row version."""


@dataclass(frozen=True)
class TrustProfileData:
    agent_id: str
    trust_score: float
    band: dict | None
    version: int
    updated_at: str | None


@dataclass(frozen=True)
class AbomData:
    agent_id: str
    components: dict
    version: int
    created_at: str | None


class ResourceStore:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    # ---- TrustProfile ----
    def put_trust_profile(
        self, agent_id: str, *, trust_score: float, band: dict | None, expected_version: int | None
    ) -> TrustProfileData:
        with self._sf() as s:
            row = s.get(TrustProfile, agent_id)
            if row is None:
                row = TrustProfile(agent_id=agent_id, trust_score=trust_score, band=band, version=1)
                s.add(row)
            else:
                if expected_version != row.version:
                    raise VersionConflict(
                        f"trust_profile {agent_id}: expected version {row.version}, got {expected_version}"
                    )
                row.trust_score, row.band, row.version = trust_score, band, row.version + 1
            s.commit()
            return self._tp(row)

    def get_trust_profile(self, agent_id: str) -> TrustProfileData | None:
        with self._sf() as s:
            row = s.get(TrustProfile, agent_id)
            return self._tp(row) if row else None

    def list_trust_profiles(self) -> list[TrustProfileData]:
        with self._sf() as s:
            return [
                self._tp(r)
                for r in s.scalars(select(TrustProfile).order_by(TrustProfile.agent_id)).all()
            ]

    # ---- Abom ----
    def put_abom(self, agent_id: str, *, components: dict, expected_version: int | None) -> AbomData:
        with self._sf() as s:
            row = s.get(Abom, agent_id)
            if row is None:
                row = Abom(agent_id=agent_id, components=components, version=1)
                s.add(row)
            else:
                if expected_version != row.version:
                    raise VersionConflict(
                        f"abom {agent_id}: expected version {row.version}, got {expected_version}"
                    )
                row.components, row.version = components, row.version + 1
            s.commit()
            return self._abom(row)

    def get_abom(self, agent_id: str) -> AbomData | None:
        with self._sf() as s:
            row = s.get(Abom, agent_id)
            return self._abom(row) if row else None

    def list_aboms(self) -> list[AbomData]:
        with self._sf() as s:
            return [self._abom(r) for r in s.scalars(select(Abom).order_by(Abom.agent_id)).all()]

    @staticmethod
    def _tp(r: TrustProfile) -> TrustProfileData:
        return TrustProfileData(
            r.agent_id, r.trust_score, r.band, r.version,
            r.updated_at.isoformat() if r.updated_at else None,
        )

    @staticmethod
    def _abom(r: Abom) -> AbomData:
        return AbomData(
            r.agent_id, r.components, r.version,
            r.created_at.isoformat() if r.created_at else None,
        )
