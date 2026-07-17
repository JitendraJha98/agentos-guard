"""ABOM-01 / ABOM-02 — the Agent Bill of Materials with per-component provenance.

Phase 5 stored a flat ABOM: `{tools: [...], models: [...]}` — names only, no
history (ABOM-01 seed). Phase 8 makes it provenance-tracked (ABOM-02): every
component carries a content DIGEST, a SOURCE, a component-level VERSION, and the
timestamps bounding when this exact definition has been in force.

Why the digest is the load-bearing field: it is what the Phase-8 supply-chain
and tool-poisoning checks consume. SEC-06 (tool-poisoning) detects manifest
DRIFT by comparing a live tool's digest against the one recorded here; SEC-08
(supply-chain) cross-references these digests against a known-bad set. A
name-only ABOM cannot support either — "http_get" tells you nothing about
whether the tool's definition changed under you.

Provenance semantics on re-declaration (`merge_components`):
  * an UNCHANGED component (same digest) keeps its original `first_seen` and
    `version` — provenance is continuous, not reset on every write;
  * a CHANGED component (same name+kind, new digest) bumps its `version` and
    stamps `updated_at` — the drift is dated and countable;
  * a REMOVED component drops out; a NEW one enters at version 1.

Pure/deterministic given an injected clock; digests are canonical-JSON sha256,
the same canonicalization the audit chain uses, so a digest is reproducible.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from agentos_controlplane.audit import canonical_json

# The four component kinds an ABOM declares (ABOM-01).
ABOM_KINDS = ("models", "prompts", "tools", "mcp")


def component_digest(definition: object) -> str:
    """`sha256:<hex>` over the canonical JSON of a component definition.

    A bare string (just a name) and a rich manifest dict both hash stably, so a
    tool declared as `"http_get"` and later as `{"name": "http_get", ...}` are
    distinguishable — the manifest carries more, so its digest differs, which is
    exactly the drift SEC-06 must catch.
    """
    import hashlib

    return "sha256:" + hashlib.sha256(canonical_json({"d": definition})).hexdigest()


@dataclass(frozen=True)
class AbomComponent:
    """One provenance-tracked ABOM entry."""

    kind: str
    name: str
    digest: str
    source: str = "declared"          # declared (manifest) | observed (reconciled)
    version: int = 1                  # component-level; bumps when the digest changes
    first_seen: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _name_of(entry: object) -> str:
    """A component entry is either a bare name or a manifest dict carrying `name`."""
    if isinstance(entry, dict):
        return str(entry.get("name", ""))
    return str(entry)


def build_components(
    declaration: dict, *, source: str = "declared", now: datetime | None = None
) -> list[dict]:
    """Turn a raw `{kind: [entries]}` declaration into provenance-tracked components.

    Each entry may be a name or a manifest dict; the digest covers the whole entry.
    Used for a first declaration (no prior) — `merge_components` handles updates.
    """
    ts = (now or datetime.now(timezone.utc)).isoformat()
    out: list[dict] = []
    for kind in ABOM_KINDS:
        for entry in declaration.get(kind, []) or []:
            name = _name_of(entry)
            if not name:
                continue
            out.append(
                AbomComponent(
                    kind=kind,
                    name=name,
                    digest=component_digest(entry),
                    source=source,
                    version=1,
                    first_seen=ts,
                    updated_at=ts,
                ).to_dict()
            )
    return out


def merge_components(
    prior: list[dict],
    declaration: dict,
    *,
    source: str = "declared",
    now: datetime | None = None,
) -> list[dict]:
    """Merge a new declaration onto the prior components, preserving provenance.

    Unchanged components keep their `first_seen`/`version`; changed ones bump the
    version and stamp `updated_at`; removed ones drop; new ones enter at v1.
    """
    ts = (now or datetime.now(timezone.utc)).isoformat()
    prior_by_key = {(c["kind"], c["name"]): c for c in prior}
    out: list[dict] = []
    for kind in ABOM_KINDS:
        for entry in declaration.get(kind, []) or []:
            name = _name_of(entry)
            if not name:
                continue
            digest = component_digest(entry)
            was = prior_by_key.get((kind, name))
            if was is None:
                comp = AbomComponent(kind, name, digest, source, 1, ts, ts)
            elif was["digest"] == digest:
                # Unchanged — provenance continuous.
                comp = AbomComponent(
                    kind, name, digest, was.get("source", source),
                    was.get("version", 1), was.get("first_seen", ts), was.get("updated_at", ts),
                )
            else:
                # Drifted — date and count it.
                comp = AbomComponent(
                    kind, name, digest, source,
                    int(was.get("version", 1)) + 1, was.get("first_seen", ts), ts,
                )
            out.append(comp.to_dict())
    return out
