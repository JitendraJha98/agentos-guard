"""SEC-14 — the embedding-similarity intent-classifier seam.

Mirrors the POL-04 interpreter toggle: a Protocol with a deterministic offline
default (`HashingEmbedder`) and an optional real-embedding adapter. The default
keeps the pipeline and its tests network-free; a deployment swaps in a real
embedding model for genuine semantic reach.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ForbiddenExemplar:
    """A labelled example of a forbidden intent (e.g. label=DATA_DESTRUCTION,
    text="permanently delete every customer record"). The classifier flags novel
    actions that land near one of these in embedding space."""

    label: str
    text: str


@dataclass(frozen=True)
class SimilarityVerdict:
    """The outcome of classifying an action against the forbidden exemplars."""

    matched: bool
    label: str | None = None       # the nearest forbidden intent when matched
    score: float = 0.0             # cosine similarity to that exemplar, 0-1
    exemplar_text: str = ""        # the exemplar it was near (for the audit reason)


@runtime_checkable
class Embedder(Protocol):
    """Turns text into a fixed-dimension vector. Async so a real adapter can do a
    network call; the offline default returns immediately."""

    name: str

    async def embed(self, text: str) -> tuple[float, ...]: ...
