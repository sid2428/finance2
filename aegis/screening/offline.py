"""Offline fixture provider — the zero-infrastructure demo default.

AEGIS's built-in Jaro-Winkler + phonetic matcher over the bundled synthetic
watchlist. Provenance pins the fixture file's content hash as the dataset
version; ``generated_at`` is ``None`` (static fixtures, exempt from the
freshness bound — demo mode only, never a production posture).
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Optional

from ..config import PHONETIC_MATCH_BONUS, SANCTIONS_MATCH_THRESHOLD
from ..data import WatchlistEntry, default_watchlist
from ..data.reference import _DATA_FILE
from ..matching import jaro_winkler_similarity, phonetic_key
from .provider import ListProvenance, ScreeningCandidate


@lru_cache(maxsize=1)
def _fixture_version() -> str:
    return hashlib.sha256(_DATA_FILE.read_bytes()).hexdigest()[:12]


class OfflineFixtureProvider:
    name = "offline-fixture"

    def __init__(self, entries: Optional[list[WatchlistEntry]] = None,
                 min_score: float = SANCTIONS_MATCH_THRESHOLD):
        self._entries = entries if entries is not None else default_watchlist()
        self._min_score = min_score

    def provenance(self) -> ListProvenance:
        return ListProvenance(
            provider=self.name,
            dataset="aegis-demo-fixtures",
            dataset_version=_fixture_version(),
            generated_at=None,
        )

    def screen(self, name: str) -> list[ScreeningCandidate]:
        if not name:
            return []
        cand_phon = phonetic_key(name)
        cand_l = name.lower()
        out: list[ScreeningCandidate] = []
        for entry in self._entries:
            jw = jaro_winkler_similarity(cand_l, entry.name.lower())
            bonus = PHONETIC_MATCH_BONUS if entry.phonetic == cand_phon else 0.0
            score = min(jw + bonus, 1.0)
            if score >= self._min_score:
                out.append(ScreeningCandidate(
                    entity_id=entry.entity_id,
                    name=entry.name,
                    score=score,
                    list_name=entry.list_name,
                    is_pep=entry.is_pep,
                    kind=entry.kind,
                ))
        return sorted(out, key=lambda c: c.score, reverse=True)
