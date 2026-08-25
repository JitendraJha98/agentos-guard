"""DISC-03 — framework discovery. You cannot govern what you cannot see.

Detection is EVIDENCE-BASED: a framework counts as present only when its distribution is genuinely
installed, resolved through `importlib.metadata`. Guessing from a stray import name would put
frameworks in the operator's inventory that are not actually there, which is worse than silence —
an inventory is only useful if it is true.

## Whose environment this describes

The scan reads the interpreter the CONTROL PLANE runs in — not the governed agent's. Two
consequences are handled explicitly rather than left implicit:

  * agentos-guard DEPENDS on several catalogue entries itself (langchain + langgraph via
    agentos-sdk). Those rows are constant-true in every install: they describe the guard's own
    dependency graph, not the fleet, and in the sidecar topology they describe the wrong process
    entirely. `guard_dependencies()` resolves what the guard declares and those distributions are
    excluded by default. Discovering the GOVERNED agent's frameworks is DISC-01/02's registration
    channel (the agent reports its own view, keyed by agent_id), not this scan.
  * every row is labelled with the `observer` that saw it, and the table is keyed by
    (observer, name). Without that, two replicas (or a rolling deploy, or a control plane plus a
    sidecar) that disagree about a version flip one shared row on every pass — an unbounded event
    stream in steady state. Per observer, an unchanged environment converges to silence.

## Externally-sourced text

A distribution's METADATA is SUPPLY-CHAIN input: a compromised dependency, a hand-rolled
`.dist-info`, or a writable PYTHONPATH entry can put any bytes in `Version:`. So:

  * versions are bounded to the column width and a conservative charset before they are persisted
    (an oversized or control-character-bearing version becomes `UNPARSEABLE`). SQLite does not
    enforce VARCHAR length and Postgres does — and Postgres rejects NUL in varchar/json outright —
    so bounding at the source is what makes the two backends behave identically;
  * the audit body NEVER carries the version text, only a sha256 `version_digest`. The raw string
    stays in the table. `append_event`'s contract is ids/enums/short strings constructed by the
    control plane, and the writer's fail-closed secret gate would otherwise let one poisoned
    version permanently destroy the evidence for this framework;
  * `metadata.version()` also has a NON-exception failure mode — it returns None when METADATA has
    no `Version:` field — and any dist-info can be unreadable, so resolution is guarded on both.
    A distribution that cannot be resolved is simply not evidence: that ONE alias is skipped.

## Evidence ordering

The chain entry is appended BEFORE the row is written, and each finding gets its OWN transaction.
So a framework is never recorded as seen without a chain entry (the failure direction is a retry
on the next pass, never silent evidence loss), and one corrupt distribution degrades to "that one
framework is unknown" instead of rolling the whole pass back.

This is a SCAN, not a hot path: findings go straight to the table (no in-memory cache) and the
detector is driven by an operator call — POST /discovery/scan — or the quickstart wiring. It is
deliberately NOT an API-04 reconciler: those run in a worker thread via `asyncio.to_thread`, and
driving the shared (single-writer, asyncio-locked) AuditWriter from a second event loop in another
thread could stall the pipeline's own audit appends. Observation must never degrade enforcement.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
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

# Placeholders for strings that arrived unusable. `<` and `>` are OUTSIDE every accepted charset
# below, so no externally-sourced string can sanitize INTO a placeholder and impersonate one.
UNPARSEABLE = "<unparseable>"
UNKNOWN_OBSERVER = "<unknown>"

# Bounds match the column widths (version 64, distribution 128, observer 128) so the row that
# SQLite silently accepts is exactly the row Postgres accepts.
_VERSION_RE = re.compile(r"[A-Za-z0-9._+!-]{1,64}")  # PEP 440: epochs, locals, pre-releases
_DISTRIBUTION_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")  # PEP 503 names
_OBSERVER_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")  # hostnames / pod names / operator ids

_GUARD_PREFIX = "agentos-"


@dataclass(frozen=True)
class FrameworkFinding:
    name: str
    distribution: str
    version: str


def _bounded(value: object, pattern: re.Pattern[str]) -> str | None:
    """`value` if it is a non-empty string within `pattern`, the placeholder if it is a string that
    is not, None if it is not a usable string at all (the "not resolvable" case)."""
    if not isinstance(value, str) or not value.strip():
        return None
    return value if pattern.fullmatch(value) else UNPARSEABLE


def _normalize(name: str) -> str:
    """PEP 503 distribution-name normalization — `Foo_Bar` and `foo-bar` are one distribution."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _requirement_name(requirement: str) -> str:
    """The distribution name out of a requirement string (`sqlalchemy[asyncio]<3,>=2.0` ->
    `sqlalchemy`, `pytest; extra == 'dev'` -> `pytest`)."""
    return _normalize(re.split(r"[\s\[<>=!~;(]", requirement, maxsplit=1)[0])


def guard_dependencies() -> frozenset[str]:
    """Normalized names of the distributions agentos-guard itself declares.

    Seeded from the root distribution AND every installed `agentos-*` workspace member, because a
    uv workspace install registers the members while the root project may not be installed at all —
    langchain/langgraph are declared by `agentos-sdk`, and only walking the members finds them.

    Scope, honestly: this sees RUNTIME requirements. PEP-735 dependency groups (the repo's own
    `dev` / `adapters` groups) are not distribution metadata and cannot be resolved, so in a
    development checkout a group-installed distribution still reports as a discovery. In a
    production install of agentos-guard those groups are absent, where finding one IS news.
    """
    queue: list[str] = ["agentos-guard"]
    try:
        for dist in metadata.distributions():
            name = dist.metadata["Name"] if dist.metadata else None
            if isinstance(name, str) and _normalize(name).startswith(_GUARD_PREFIX):
                queue.append(_normalize(name))
    except Exception:  # a broken dist-info must not make the exclusion set unavailable
        pass

    seen: set[str] = set()
    declared: set[str] = set()
    while queue:
        dist = queue.pop()
        if dist in seen:
            continue
        seen.add(dist)
        try:
            requires = metadata.requires(dist) or []
        except Exception:
            continue
        for requirement in requires:
            name = _requirement_name(requirement)
            declared.add(name)
            if name.startswith(_GUARD_PREFIX):
                queue.append(name)  # walk into the workspace members' own declarations
    return frozenset(declared)


def detect_frameworks(
    catalogue: dict[str, tuple[str, ...]] | None = None,
    *,
    exclude_guard_dependencies: bool = True,
) -> list[FrameworkFinding]:
    """Resolve the catalogue against the INSTALLED distributions. Pure — no DB, no audit.

    Distributions agentos-guard declares itself are skipped by default: they are constant-true and
    would report the guard's dependency graph as a discovery. Pass
    `exclude_guard_dependencies=False` for the unfiltered view of this interpreter.
    """
    excluded = guard_dependencies() if exclude_guard_dependencies else frozenset()
    found: list[FrameworkFinding] = []
    for name, distributions in sorted((catalogue or FRAMEWORK_CATALOGUE).items()):
        for dist in distributions:
            if _normalize(dist) in excluded:
                continue
            try:
                version = _bounded(metadata.version(dist), _VERSION_RE)
            except Exception:
                # Not installed, a dist-info this interpreter cannot read, or the KeyError that
                # importlib is deprecating the None return in favour of. Either way it is not
                # evidence — try the next alias rather than abandoning the scan.
                continue
            if version is None:
                continue  # installed but no resolvable version: unknown, not "present at None"
            found.append(
                FrameworkFinding(
                    name=name,
                    distribution=_bounded(dist, _DISTRIBUTION_RE) or UNPARSEABLE,
                    version=version,
                )
            )
            break  # first match wins: the catalogue lists aliases, not separate installs
    return found


def _this_observer(observer: str | None) -> str:
    """Which process observed these frameworks — an operator-pinned id, else the hostname."""
    raw = observer or os.environ.get("AGENTOS_INSTANCE_ID") or platform.node()
    return _bounded(raw, _OBSERVER_RE) or UNKNOWN_OBSERVER


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class FrameworkDetector:
    """Persists + audits what `detect_frameworks` finds, for ONE observing instance."""

    def __init__(
        self,
        session_factory,
        audit,
        *,
        catalogue: dict[str, tuple[str, ...]] | None = None,
        observer: str | None = None,
    ) -> None:
        self._sf = session_factory
        self._audit = audit
        self._catalogue = catalogue
        self.observer = _this_observer(observer)

    async def scan(self) -> list[FrameworkFinding]:
        """Detect, audit, and upsert each framework whose presence or version is NEW for this
        observer. Returns everything found (not only the new ones) so a caller can report the full
        picture."""
        findings = detect_frameworks(self._catalogue)
        for finding in findings:
            try:
                await self._record(finding)
            except Exception:
                # Per-finding isolation: one framework that cannot be recorded (a refused chain
                # append, a rejected row) leaves the OTHERS in this pass untouched and is retried
                # on the next scan — it can neither roll them back nor abort the pass.
                continue
        return findings

    async def _record(self, f: FrameworkFinding) -> bool:
        """Record one finding. True iff it was news. Own transaction; chain entry FIRST."""
        with self._sf() as s:
            row = s.get(DiscoveredFramework, (self.observer, f.name))
            if row is not None and (row.version, row.distribution) == (f.version, f.distribution):
                # Converged: refresh the observation WITHOUT appending to the chain — a scheduled
                # scan over an unchanged environment must not bloat it.
                row.last_seen_at = _now()
                s.commit()
                return False

        # News. The chain entry is written BEFORE the row: if the append fails, nothing claims the
        # framework was seen, and the next scan tries again. The body is identifiers + a digest —
        # the version text itself stays out of the hash-covered record.
        await self._audit.append_event(
            "framework_discovered",
            {
                "observer": self.observer,
                "framework": f.name,
                "distribution": f.distribution,
                "version_digest": hashlib.sha256(f.version.encode("utf-8")).hexdigest(),
            },
        )
        with self._sf() as s:
            row = s.get(DiscoveredFramework, (self.observer, f.name))
            if row is None:
                s.add(
                    DiscoveredFramework(
                        observer=self.observer,
                        name=f.name,
                        distribution=f.distribution,
                        version=f.version,
                    )
                )
            else:
                row.version, row.distribution = f.version, f.distribution
                row.last_seen_at = _now()
            s.commit()
        return True

    def list_frameworks(self) -> list[dict]:
        with self._sf() as s:
            rows = s.scalars(
                select(DiscoveredFramework).order_by(
                    DiscoveredFramework.name, DiscoveredFramework.observer
                )
            ).all()
            return [
                {
                    "observer": r.observer,
                    "name": r.name,
                    "distribution": r.distribution,
                    "version": r.version,
                    "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
                    "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
                }
                for r in rows
            ]
