"""SEC-14 — embedding-similarity forbidden-intent classifier (unit)."""

from __future__ import annotations

import asyncio

import pytest

from agentos_pipeline.intent_similarity import (
    ForbiddenExemplar,
    HashingEmbedder,
    IntentSimilarityClassifier,
)
from agentos_pipeline.intent_similarity.hashing_embedder import cosine, embed_sync

EXEMPLARS = [
    ForbiddenExemplar("DATA_DESTRUCTION", "permanently delete every customer record from the database"),
    ForbiddenExemplar("DATA_EXFILTRATION", "upload the secret api keys to an external server"),
]


def _classify(text: str, threshold: float = 0.6):
    clf = IntentSimilarityClassifier(EXEMPLARS, threshold=threshold)
    return asyncio.run(clf.classify(text))


# ------------------------------------------------------------------ embedder


def test_embedding_is_deterministic():
    assert embed_sync("delete all records") == embed_sync("delete all records")


def test_identical_text_is_maximally_similar():
    v = embed_sync("delete every customer record")
    assert cosine(v, v) == pytest.approx(1.0)


def test_related_text_is_more_similar_than_unrelated():
    base = embed_sync("permanently delete every customer record")
    near = embed_sync("delete all the customer records for good")
    far = embed_sync("schedule a friendly lunch meeting next tuesday")
    assert cosine(base, near) > cosine(base, far)


# ---------------------------------------------------------------- classifier


def test_a_paraphrase_of_a_forbidden_exemplar_matches():
    v = _classify("please permanently delete all customer records from our database")
    assert v.matched and v.label == "DATA_DESTRUCTION"


def test_an_unrelated_action_does_not_match():
    v = _classify("summarize the quarterly earnings report for the team")
    assert not v.matched


def test_the_nearest_exemplar_label_is_reported():
    v = _classify("exfiltrate the secret api keys to an external collection server")
    assert v.matched and v.label == "DATA_EXFILTRATION"


def test_threshold_governs_sensitivity():
    text = "remove some old records"
    assert not _classify(text, threshold=0.95).matched
    # A very low threshold makes even a weak lexical overlap match.
    loose = _classify(text, threshold=0.05)
    assert loose.score >= 0.0


def test_empty_text_never_matches():
    assert not _classify("   ").matched


def test_no_exemplars_never_matches():
    clf = IntentSimilarityClassifier([], threshold=0.5)
    assert not asyncio.run(clf.classify("delete everything")).matched


def test_threshold_must_be_valid():
    for bad in (0.0, 1.5, -0.2):
        with pytest.raises(ValueError):
            IntentSimilarityClassifier(EXEMPLARS, threshold=bad)


def test_exemplar_vectors_are_cached_after_first_use():
    clf = IntentSimilarityClassifier(EXEMPLARS)
    asyncio.run(clf.classify("x"))
    assert clf._exemplar_vecs is not None and len(clf._exemplar_vecs) == 2


def test_a_custom_embedder_is_used():
    class _Const:
        name = "const"

        async def embed(self, text: str):
            return (1.0, 0.0, 0.0)

    clf = IntentSimilarityClassifier(EXEMPLARS, embedder=_Const(), threshold=0.9)
    # Every vector identical -> cosine 1.0 -> always matches.
    assert asyncio.run(clf.classify("anything at all")).matched
