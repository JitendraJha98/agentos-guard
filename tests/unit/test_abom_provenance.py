"""ABOM-01 / ABOM-02 — versioned, provenance-tracked Agent Bill of Materials."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from agentos_controlplane.abom import (
    ABOM_KINDS,
    build_components,
    component_digest,
    merge_components,
)
from agentos_controlplane.resources import ResourceStore, VersionConflict
from agentos_controlplane.store.models import Base

T0 = datetime(2026, 7, 17, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=1)


@pytest.fixture()
def store():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return ResourceStore(sessionmaker(bind=engine))


DECL = {
    "models": ["gpt-5"],
    "prompts": ["system-v1"],
    "tools": [{"name": "http_get", "schema": {"url": "string"}}],
    "mcp": ["files-server"],
}


# ------------------------------------------------------------------ digests


def test_digest_is_stable_and_definition_sensitive():
    assert component_digest("http_get") == component_digest("http_get")
    assert component_digest({"name": "http_get", "x": 1}) != component_digest({"name": "http_get", "x": 2})


def test_a_name_and_its_manifest_have_different_digests():
    """A tool declared by name vs by full manifest must be distinguishable (drift surface)."""
    assert component_digest("http_get") != component_digest({"name": "http_get"})


# ------------------------------------------------------------------ build


def test_build_covers_every_declared_kind():
    comps = build_components(DECL, now=T0)
    kinds = {c["kind"] for c in comps}
    assert kinds == {"models", "prompts", "tools", "mcp"}
    assert all(c["digest"].startswith("sha256:") for c in comps)
    assert all(c["version"] == 1 and c["source"] == "declared" for c in comps)


def test_build_records_provenance_timestamps():
    comps = build_components(DECL, now=T0)
    assert all(c["first_seen"] == T0.isoformat() == c["updated_at"] for c in comps)


# ------------------------------------------------------- merge / provenance


def test_unchanged_component_keeps_its_provenance():
    first = build_components(DECL, now=T0)
    merged = merge_components(first, DECL, now=T1)
    http = next(c for c in merged if c["name"] == "http_get")
    assert http["version"] == 1, "an unchanged component was bumped"
    assert http["first_seen"] == T0.isoformat(), "first_seen was reset"


def test_a_drifted_component_bumps_version_and_dates_the_change():
    first = build_components(DECL, now=T0)
    drifted = dict(DECL, tools=[{"name": "http_get", "schema": {"url": "string", "method": "string"}}])
    merged = merge_components(first, drifted, now=T1)
    http = next(c for c in merged if c["name"] == "http_get")
    assert http["version"] == 2
    assert http["first_seen"] == T0.isoformat()  # provenance preserved
    assert http["updated_at"] == T1.isoformat()  # drift dated


def test_a_new_component_enters_at_version_one():
    first = build_components(DECL, now=T0)
    added = dict(DECL, tools=DECL["tools"] + ["drop_table"])
    merged = merge_components(first, added, now=T1)
    drop = next(c for c in merged if c["name"] == "drop_table")
    assert drop["version"] == 1 and drop["first_seen"] == T1.isoformat()


def test_a_removed_component_drops_out():
    first = build_components(DECL, now=T0)
    merged = merge_components(first, dict(DECL, mcp=[]), now=T1)
    assert not any(c["kind"] == "mcp" for c in merged)


# ----------------------------------------------------------- store round-trip


def test_declare_abom_persists_provenance_components(store):
    store.declare_abom("a", DECL, expected_version=None, now=T0)
    comps = store.get_abom_components("a")
    assert {c["name"] for c in comps} == {"gpt-5", "system-v1", "http_get", "files-server"}


def test_redeclare_preserves_history_and_bumps_only_drift(store):
    store.declare_abom("a", DECL, expected_version=None, now=T0)
    drifted = dict(DECL, tools=[{"name": "http_get", "schema": {"url": "string", "method": "string"}}])
    store.declare_abom("a", drifted, expected_version=1, now=T1)

    comps = {c["name"]: c for c in store.get_abom_components("a")}
    assert comps["http_get"]["version"] == 2  # drifted
    assert comps["gpt-5"]["version"] == 1      # untouched
    assert comps["gpt-5"]["first_seen"] == T0.isoformat()


def test_declare_abom_is_optimistically_versioned(store):
    store.declare_abom("a", DECL, expected_version=None, now=T0)
    with pytest.raises(VersionConflict):
        store.declare_abom("a", DECL, expected_version=99, now=T1)


def test_get_components_empty_for_unknown_agent(store):
    assert store.get_abom_components("ghost") == []
