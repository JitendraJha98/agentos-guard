"""HashingEmbedder — the deterministic offline default embedder (SEC-14).

Honest framing, because it matters: this is NOT a semantic model. It is a
deterministic feature-hashing embedder over word tokens and character n-grams —
a LEXICAL-similarity proxy. It clusters text that shares words and morphology
("delete all records" vs "delete every record"), which catches paraphrase and
light obfuscation, but it does not understand meaning: a true synonym swap with
no shared substrings ("erase" for "delete") is beyond it.

That is deliberate and mirrors the POL-04 interpreter's stub: the DEFAULT is
deterministic and offline so the pipeline and its tests carry no model
dependency, and a deployment that needs real semantic reach injects a real
embedding adapter behind the same `Embedder` Protocol. The SEC-14 *architecture*
— embed the action, cosine-compare to forbidden exemplars, threshold — is
identical either way; only the embedder's quality changes.

Deterministic: same text -> same vector, always. Pure CPU, stdlib only.
"""

from __future__ import annotations

import hashlib
import math
import re

_DIM = 256  # fixed embedding dimension
_TOKEN = re.compile(r"[a-z0-9]+")


def _feature_index(feature: str) -> int:
    # Stable hash -> bucket. hashlib (not builtin hash) so it is reproducible across
    # processes/runs — builtin hash is salted per interpreter start.
    return int.from_bytes(hashlib.blake2b(feature.encode(), digest_size=4).digest(), "big") % _DIM


def _char_ngrams(token: str, n: int = 3) -> list[str]:
    padded = f"^{token}$"
    if len(padded) <= n:
        return [padded]
    return [padded[i : i + n] for i in range(len(padded) - n + 1)]


def embed_sync(text: str) -> tuple[float, ...]:
    """The deterministic vector for `text` (word + char-trigram feature hashing, L2-normalized)."""
    vec = [0.0] * _DIM
    tokens = _TOKEN.findall(text.lower())
    for tok in tokens:
        vec[_feature_index(f"w:{tok}")] += 1.0
        for ng in _char_ngrams(tok):
            vec[_feature_index(f"c:{ng}")] += 0.5
    norm = math.sqrt(sum(v * v for v in vec))
    if norm == 0.0:
        return tuple(vec)
    return tuple(v / norm for v in vec)


def cosine(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    """Cosine similarity of two already-... not-necessarily-normalized vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


class HashingEmbedder:
    """The offline default Embedder — deterministic lexical feature hashing."""

    name = "hashing.v1"

    async def embed(self, text: str) -> tuple[float, ...]:
        return embed_sync(text)
