"""Sliding-window counters for structuring & velocity analysis.

Redis analogue: each key is a sorted set scored by timestamp (``zadd`` /
``zremrangebyscore`` / ``zrange``). Here we back it with an in-memory dict of
timestamped entries. Timestamps are supplied by the caller (the pinned
``ctx.now``) so windows are deterministic and replayable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field


@dataclass
class VelocityStore:
    # key -> list of (timestamp, amount_usd)
    _data: dict[str, list[tuple[float, float]]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, key: str, ts: float, amount_usd: float) -> None:
        with self._lock:
            self._data.setdefault(key, []).append((ts, amount_usd))

    def window(self, key: str, now: float, window_seconds: float) -> list[tuple[float, float]]:
        """Return entries within [now - window, now], pruning older ones."""
        cutoff = now - window_seconds
        with self._lock:
            entries = [e for e in self._data.get(key, []) if e[0] >= cutoff]
            self._data[key] = entries
            return list(entries)

    def seed(self, mapping: dict) -> None:
        """Load window entries verbatim (used to reconstruct a decision's
        exact sliding window during audit replay)."""
        with self._lock:
            for key, entries in mapping.items():
                self._data[key] = [(float(ts), float(amt)) for ts, amt in entries]

    def reset(self) -> None:
        with self._lock:
            self._data.clear()


_DEFAULT = VelocityStore()


def default_velocity_store() -> VelocityStore:
    return _DEFAULT
