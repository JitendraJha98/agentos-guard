"""SEC-14 embedding-similarity intent classification (advisory, ambiguity-gated)."""

from agentos_pipeline.intent_similarity.classifier import (
    DEFAULT_THRESHOLD,
    IntentSimilarityClassifier,
)
from agentos_pipeline.intent_similarity.hashing_embedder import HashingEmbedder
from agentos_pipeline.intent_similarity.protocol import (
    Embedder,
    ForbiddenExemplar,
    SimilarityVerdict,
)

__all__ = [
    "DEFAULT_THRESHOLD",
    "Embedder",
    "ForbiddenExemplar",
    "HashingEmbedder",
    "IntentSimilarityClassifier",
    "SimilarityVerdict",
]
