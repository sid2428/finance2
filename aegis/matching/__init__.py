"""Fuzzy name-matching primitives for sanctions screening."""

from .fuzzy import jaro_winkler_similarity, phonetic_key

__all__ = ["jaro_winkler_similarity", "phonetic_key"]
