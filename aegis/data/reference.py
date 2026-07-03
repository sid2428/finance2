"""Loaders for sanctions/PEP watchlists, the beneficial-ownership graph, and
FATF Travel-Rule thresholds."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..config import (
    TRAVEL_RULE_THRESHOLD_DEFAULT_USD,
    TRAVEL_RULE_THRESHOLDS_USD,
)
from ..matching import phonetic_key

_DATA_FILE = Path(__file__).with_name("sanctions.json")


@dataclass(frozen=True)
class WatchlistEntry:
    entity_id: str
    name: str
    list_name: str
    is_pep: bool
    kind: str
    phonetic: str = field(default="")


class OwnershipGraph:
    """Directed ownership edges for the OFAC 50% Rule.

    Edge owner_id --pct--> owned_id means owner holds ``pct`` of owned.
    """

    def __init__(self, edges: list[dict], sanctioned_ids: set[str]):
        self._by_owned: dict[str, list[tuple[str, float]]] = {}
        for e in edges:
            self._by_owned.setdefault(e["owned_id"], []).append(
                (e["owner_id"], float(e["pct"]))
            )
        self._sanctioned = sanctioned_ids

    def owners_of(self, entity_id: str) -> list[tuple[str, float]]:
        return self._by_owned.get(entity_id, [])

    def is_sanctioned(self, entity_id: str) -> bool:
        return entity_id in self._sanctioned

    def sanctioned_share(self, entity_id: str, _depth: int = 0) -> float:
        """Aggregate sanctioned ownership share, resolving one level of
        indirect ownership through non-sanctioned intermediaries."""
        if _depth > 4:
            return 0.0
        total = 0.0
        for owner_id, pct in self.owners_of(entity_id):
            if self.is_sanctioned(owner_id):
                total += pct
            else:
                # Indirect: sanctioned parties owning the owner.
                total += pct * self.sanctioned_share(owner_id, _depth + 1)
        return total


@lru_cache(maxsize=1)
def _load() -> dict:
    return json.loads(_DATA_FILE.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def default_watchlist() -> list[WatchlistEntry]:
    raw = _load()
    return [
        WatchlistEntry(
            entity_id=e["entity_id"],
            name=e["name"],
            list_name=e["list"],
            is_pep=bool(e.get("is_pep", False)),
            kind=e.get("kind", "entity"),
            phonetic=phonetic_key(e["name"]),
        )
        for e in raw["entries"]
    ]


@lru_cache(maxsize=1)
def default_ownership_graph() -> OwnershipGraph:
    raw = _load()
    sanctioned = {e["entity_id"] for e in raw["entries"]}
    return OwnershipGraph(raw.get("ownership", []), sanctioned)


def travel_rule_threshold(iso: str) -> float:
    return TRAVEL_RULE_THRESHOLDS_USD.get(iso, TRAVEL_RULE_THRESHOLD_DEFAULT_USD)
