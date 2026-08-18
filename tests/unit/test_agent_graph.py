"""DISC-06 — the live agent graph: nodes, edges and delegation lineage (Slice 10f).

The schema half first: a `graph_node` is unique on (kind, name) and a `graph_edge` on the
(src, dst, relation) 5-tuple, so a repeated materialization pass converges on the SAME rows instead
of growing a new copy of the graph on every sweep. That idempotence is enforced by the schema, not
only by the store's read-before-write.
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.pool import StaticPool

from agentos_controlplane.store.engine import create_all, create_session_factory
from agentos_controlplane.store.models import GraphEdge, GraphNode


@pytest.fixture
def store():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    create_all(engine)
    return create_session_factory(engine)


def test_node_and_edge_round_trip(store) -> None:
    with store() as s:
        s.add(GraphNode(kind="agent", name="a"))
        s.add(
            GraphEdge(
                src_kind="agent", src_name="a", dst_kind="tool", dst_name="tool", relation="uses"
            )
        )
        s.commit()

    with store() as s:
        node = s.scalar(select(GraphNode))
        edge = s.scalar(select(GraphEdge))
        assert (node.kind, node.name) == ("agent", "a")
        assert (edge.src_name, edge.dst_name, edge.relation) == ("a", "tool", "uses")
        assert edge.observations == 1
        assert node.first_seen_at is not None and node.last_seen_at is not None


def test_a_duplicate_node_is_rejected_by_the_schema(store) -> None:
    with store() as s:
        s.add(GraphNode(kind="agent", name="a"))
        s.commit()

    with pytest.raises(IntegrityError):
        with store() as s:
            s.add(GraphNode(kind="agent", name="a"))
            s.commit()


def test_a_duplicate_edge_is_rejected_by_the_schema(store) -> None:
    """The 5-tuple is the key: the same pair with a DIFFERENT relation is a different edge."""
    with store() as s:
        s.add(
            GraphEdge(
                src_kind="agent", src_name="a", dst_kind="agent", dst_name="b", relation="delegates"
            )
        )
        s.commit()

    with store() as s:
        # Same pair, different relation — allowed.
        s.add(
            GraphEdge(
                src_kind="agent", src_name="a", dst_kind="agent", dst_name="b", relation="uses"
            )
        )
        s.commit()

    with pytest.raises(IntegrityError):
        with store() as s:
            s.add(
                GraphEdge(
                    src_kind="agent",
                    src_name="a",
                    dst_kind="agent",
                    dst_name="b",
                    relation="delegates",
                )
            )
            s.commit()
