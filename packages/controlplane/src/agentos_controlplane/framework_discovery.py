"""DISC-03 — framework discovery. You cannot govern what you cannot see.

Detection is EVIDENCE-BASED: a framework counts as present only when its distribution is genuinely
installed, resolved through `importlib.metadata`. Guessing from a stray import name would put
frameworks in the operator's inventory that are not actually there, which is worse than silence —
an inventory is only useful if it is true.

This is a SCAN, not a hot path: findings go straight to the table (no in-memory cache) and the
detector is driven by an operator call or a reconciler pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata

from sqlalchemy import select

from agentos_controlplane.store.models import DiscoveredFramework

# name -> the candidate PyPI distributions that indicate it. Several names per framework because
# these projects have renamed/split (autogen -> autogen-agentchat/pyautogen; the OpenAI Agents SDK
# ships as `openai-agents` but imports as `agents`).
FRAMEWORK_CATALOGUE: dict[str, tuple[str, ...]] = {
    "langchain": ("langchain",),
    "langgraph": ("langgraph",),
    "crewai": ("crewai",),
    "autogen": ("autogen-agentchat", "pyautogen", "autogen"),
    "openai_agents": ("openai-agents",),
    "mcp": ("mcp",),
}


@dataclass(frozen=True)
class FrameworkFinding:
    name: str
    distribution: str
    version: str


def detect_frameworks(
    catalogue: dict[str, tuple[str, ...]] | None = None,
) -> list[FrameworkFinding]:
    """Resolve the catalogue against the INSTALLED distributions. Pure — no DB, no audit."""
    found: list[FrameworkFinding] = []
    for name, distributions in sorted((catalogue or FRAMEWORK_CATALOGUE).items()):
        for dist in distributions:
            try:
                version = metadata.version(dist)
            except metadata.PackageNotFoundError:
                continue
            found.append(FrameworkFinding(name=name, distribution=dist, version=version))
            break  # first match wins: the catalogue lists aliases, not separate installs
    return found


class FrameworkDetector:
    """Persists + audits what `detect_frameworks` finds."""

    def __init__(
        self,
        session_factory,
        audit,
        *,
        catalogue: dict[str, tuple[str, ...]] | None = None,
    ) -> None:
        self._sf = session_factory
        self._audit = audit
        self._catalogue = catalogue

    async def scan(self) -> list[FrameworkFinding]:
        """Detect, upsert, and audit each framework whose presence or version is NEW. Returns
        everything found (not only the new ones) so a caller can report the full picture."""
        findings = detect_frameworks(self._catalogue)
        newly: list[FrameworkFinding] = []
        with self._sf() as s:
            for f in findings:
                row = s.get(DiscoveredFramework, f.name)
                if row is None:
                    s.add(
                        DiscoveredFramework(
                            name=f.name, distribution=f.distribution, version=f.version
                        )
                    )
                    newly.append(f)
                elif row.version != f.version or row.distribution != f.distribution:
                    row.version, row.distribution = f.version, f.distribution
                    newly.append(f)
                else:
                    row.last_seen_at = datetime.now(timezone.utc).replace(tzinfo=None)
            s.commit()
        # Audit AFTER the commit, and only for genuine changes — a scan on a schedule must not
        # append an identical event on every pass and bloat the chain.
        for f in newly:
            await self._audit.append_event(
                "framework_discovered",
                {"framework": f.name, "distribution": f.distribution, "version": f.version},
            )
        return findings

    def list_frameworks(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(select(DiscoveredFramework).order_by(DiscoveredFramework.name)).all()
            return [
                {
                    "name": r.name,
                    "distribution": r.distribution,
                    "version": r.version,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                    "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                }
                for r in rows
            ]
