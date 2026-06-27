"""API-01 — declarative resource persistence with optimistic versioning.

Sync store over the shared session_factory (D-14 SQLite now, Postgres target). Each mutable
resource is keyed by agent_id and carries a monotonic `version`; an update supplying a stale
(or missing) version raises VersionConflict -> the API maps it to 409. A create supplies no
version (or 0/1) and starts at version 1.

The conflict guard is atomic at the SQL layer: `version` is the models' `version_id_col`, so
SQLAlchemy emits every UPDATE as `... WHERE agent_id = :id AND version = :current`. A writer
holding a stale image matches zero rows and the commit raises StaleDataError, mapped here to
VersionConflict. This holds under the Postgres target (distinct connections, READ COMMITTED)
where a non-atomic Python read-then-compare would silently drop the second write.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from agentos_constitution import Constitution, compile_constitution
from agentos_controlplane.store.models import (
    Abom,
    ConstitutionResource,
    PolicyResource,
    TrustProfile,
)


class VersionConflict(Exception):
    """Optimistic-concurrency failure: the supplied version != the current row version."""


class ConstitutionError(Exception):
    """The authored Constitution failed validation or compilation — the API maps it to 422
    and NOTHING is persisted (fail-closed compile-on-write)."""


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


@dataclass(frozen=True)
class ConstitutionData:
    id: str
    name: str
    version: str
    source: dict
    created_at: str | None


@dataclass(frozen=True)
class PolicyData:
    constitution_version: str
    yaml_policy: str
    rego: str
    graduated_config: dict
    lists: dict
    sequences: list
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
                # Fast-fail an obviously stale/missing version without a DB round-trip; the
                # version_id_col WHERE-guard is the authoritative atomic check on commit.
                if expected_version != row.version:
                    raise VersionConflict(
                        f"trust_profile {agent_id}: expected version {row.version}, got {expected_version}"
                    )
                row.trust_score, row.band = trust_score, band  # version bumped by version_id_col
            try:
                s.commit()
            except StaleDataError as exc:
                raise VersionConflict(f"trust_profile {agent_id}: concurrent update") from exc
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
                # Fast-fail an obviously stale/missing version without a DB round-trip; the
                # version_id_col WHERE-guard is the authoritative atomic check on commit.
                if expected_version != row.version:
                    raise VersionConflict(
                        f"abom {agent_id}: expected version {row.version}, got {expected_version}"
                    )
                row.components = components  # version bumped by version_id_col
            try:
                s.commit()
            except StaleDataError as exc:
                raise VersionConflict(f"abom {agent_id}: concurrent update") from exc
            return self._abom(row)

    def get_abom(self, agent_id: str) -> AbomData | None:
        with self._sf() as s:
            row = s.get(Abom, agent_id)
            return self._abom(row) if row else None

    def list_aboms(self) -> list[AbomData]:
        with self._sf() as s:
            return [self._abom(r) for r in s.scalars(select(Abom).order_by(Abom.agent_id)).all()]

    # ---- Constitution / Policy (compile-on-write, API-02) ----
    def apply_constitution(self, name: str, source: dict) -> tuple[ConstitutionData, PolicyData]:
        """API-02 — validate + compile + persist Constitution and its Policy in ONE transaction.
        Idempotent on the content-hash version: re-applying the same source returns the existing
        rows. Validation/compile failure -> ConstitutionError (no write)."""
        # 1) validate + compile FIRST — no DB work happens if either fails (fail-closed).
        try:
            constitution = Constitution.model_validate(source)
            bundle = compile_constitution(constitution)
        except (ValidationError, ValueError) as exc:
            raise ConstitutionError(str(exc)) from exc
        version = bundle.constitution_version
        # 2) persist atomically; idempotent on version.
        with self._sf() as s:
            existing = self._fetch_version(s, version)
            if existing is not None:
                return existing
            con = ConstitutionResource(name=name, version=version, source=source)
            pol = PolicyResource(
                constitution_version=version,
                yaml_policy=bundle.yaml_policy,
                rego=bundle.rego,
                graduated_config=bundle.graduated_config,
                lists=bundle.lists,
                sequences=bundle.sequences,
            )
            s.add(con)
            s.add(pol)
            try:
                s.commit()
            except IntegrityError:
                # IDEMPOTENCY race: a concurrent apply of the SAME version committed between our
                # existing-check and this commit, tripping UNIQUE(version). Collapse the loser into
                # the idempotent path — re-fetch the winner's committed rows and return 200, never 500.
                s.rollback()
                return self._fetch_version(s, version)
            return self._con(con), self._pol(pol)

    def _fetch_version(
        self, s: Session, version: str
    ) -> tuple[ConstitutionData, PolicyData] | None:
        con = s.scalar(select(ConstitutionResource).where(ConstitutionResource.version == version))
        if con is None:
            return None
        pol = s.scalar(
            select(PolicyResource).where(PolicyResource.constitution_version == version)
        )
        return self._con(con), self._pol(pol)

    def get_constitution(self, version: str) -> ConstitutionData | None:
        with self._sf() as s:
            row = s.scalar(
                select(ConstitutionResource).where(ConstitutionResource.version == version)
            )
            return self._con(row) if row else None

    def list_constitutions(self) -> list[ConstitutionData]:
        with self._sf() as s:
            rows = s.scalars(
                select(ConstitutionResource).order_by(ConstitutionResource.created_at)
            ).all()
            return [self._con(r) for r in rows]

    def get_latest_policy(self) -> PolicyData | None:
        with self._sf() as s:
            row = s.scalar(
                select(PolicyResource).order_by(PolicyResource.created_at.desc()).limit(1)
            )
            return self._pol(row) if row else None

    def get_policy(self, version: str) -> PolicyData | None:
        with self._sf() as s:
            row = s.scalar(
                select(PolicyResource).where(PolicyResource.constitution_version == version)
            )
            return self._pol(row) if row else None

    @staticmethod
    def _con(r: ConstitutionResource) -> ConstitutionData:
        return ConstitutionData(
            str(r.id), r.name, r.version, r.source,
            r.created_at.isoformat() if r.created_at else None,
        )

    @staticmethod
    def _pol(r: PolicyResource) -> PolicyData:
        return PolicyData(
            r.constitution_version, r.yaml_policy, r.rego, r.graduated_config,
            r.lists, r.sequences, r.created_at.isoformat() if r.created_at else None,
        )

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
