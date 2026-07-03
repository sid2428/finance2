"""Deterministic text embedder for intent<->cart semantic-drift measurement.

Production serves a sentence-embedding model via ONNX. Here we use a hashed
bag-of-tokens (word unigrams + bigrams) vector with cosine similarity. It is
fully deterministic — same text always maps to the same vector — which is
exactly what audit replay needs, while still capturing "these two descriptions
are about different things" for the drift check.
"""

from __future__ import annotations

import hashlib
import math
import re

_TOKEN = re.compile(r"[a-z0-9£$€]+")
_DIM = 512

MODEL_NAME = "aegis-drift-embedder"
MODEL_VERSION = "hashed-bow-v1"


def _tokens(text: str) -> list[str]:
    words = _TOKEN.findall(text.lower())
    grams = list(words)
    grams += [f"{a}_{b}" for a, b in zip(words, words[1:])]
    return grams


def _bucket(token: str) -> int:
    h = hashlib.blake2b(token.encode("utf-8"), digest_size=4).digest()
    return int.from_bytes(h, "big") % _DIM


class DriftEmbedder:
    name = MODEL_NAME
    version = MODEL_VERSION

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * _DIM
        for tok in _tokens(text):
            vec[_bucket(tok)] += 1.0
        return vec

    def cosine_similarity(self, a: str, b: str) -> float:
        va, vb = self.embed(a), self.embed(b)
        dot = sum(x * y for x, y in zip(va, vb))
        na = math.sqrt(sum(x * x for x in va))
        nb = math.sqrt(sum(y * y for y in vb))
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)


_DEFAULT = DriftEmbedder()


def default_embedder() -> DriftEmbedder:
    return _DEFAULT
