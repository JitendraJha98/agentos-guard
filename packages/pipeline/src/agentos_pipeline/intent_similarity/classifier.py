"""IntentSimilarityClassifier — SEC-14 embedding-similarity forbidden-intent flag.

Flags a novel action whose text lands near a FORBIDDEN-intent exemplar in
embedding space, and — per the requirement — runs ONLY when the deterministic
SEC-12 tagger was ambiguous (returned no class). Deterministic tags are exact and
cheap; this probabilistic classifier is the fallback for the actions they miss,
not a replacement (the same "expensive tier runs only on a gap" discipline as the
POL-04 interpreter and the SEC-03 scorer tiering).

Strictly advisory. A probabilistic signal must never fire a deterministic policy
floor, so the classifier's output is surfaced as an inferred-intent label and an
advisory RISK finding — the risk stage can only RESTRICT via graduated response,
never relax the floor. It does not inject a `intent.class` into the policy input
(that field is for deterministic tags a constitution may treat as a floor).
"""

from __future__ import annotations

from agentos_pipeline.intent_similarity.hashing_embedder import HashingEmbedder, cosine
from agentos_pipeline.intent_similarity.protocol import (
    Embedder,
    ForbiddenExemplar,
    SimilarityVerdict,
)

# Default threshold. Cosine >= this to the nearest exemplar counts as "near".
# 0.6 is tuned for the lexical HashingEmbedder default (shared words/morphology);
# a real semantic embedder would justify a different, likely higher, cut.
DEFAULT_THRESHOLD = 0.6


class IntentSimilarityClassifier:
    """Classifies action text against forbidden-intent exemplars (SEC-14)."""

    def __init__(
        self,
        exemplars: list[ForbiddenExemplar],
        *,
        embedder: Embedder | None = None,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:
        if not (0.0 < threshold <= 1.0):
            raise ValueError(f"threshold must be in (0,1], got {threshold}")
        self._embedder = embedder or HashingEmbedder()
        self._exemplars = list(exemplars)
        self._threshold = threshold
        # Exemplar vectors are computed lazily on first use and cached — the
        # forbidden set is fixed for the classifier's lifetime.
        self._exemplar_vecs: list[tuple[ForbiddenExemplar, tuple[float, ...]]] | None = None

    async def _vectors(self) -> list[tuple[ForbiddenExemplar, tuple[float, ...]]]:
        if self._exemplar_vecs is None:
            self._exemplar_vecs = [
                (ex, await self._embedder.embed(ex.text)) for ex in self._exemplars
            ]
        return self._exemplar_vecs

    async def classify(self, text: str) -> SimilarityVerdict:
        """Nearest forbidden exemplar to `text`; matched iff cosine >= threshold."""
        if not text.strip() or not self._exemplars:
            return SimilarityVerdict(matched=False)
        query = await self._embedder.embed(text)
        best_ex: ForbiddenExemplar | None = None
        best_score = 0.0
        for ex, vec in await self._vectors():
            score = cosine(query, vec)
            if score > best_score:
                best_score, best_ex = score, ex
        if best_ex is not None and best_score >= self._threshold:
            return SimilarityVerdict(
                matched=True, label=best_ex.label, score=best_score, exemplar_text=best_ex.text,
            )
        return SimilarityVerdict(matched=False, label=None, score=best_score)
