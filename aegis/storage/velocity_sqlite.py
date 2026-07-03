"""Durable sliding-window counters — same contract as the in-memory
``VelocityStore`` so Feature 3 (structuring/velocity) works unmodified.
Windows must survive restarts: a smurfing cluster spread across process
lifetimes is exactly the case the in-memory demo store cannot catch.
"""

from __future__ import annotations

from .sqlite_util import SqliteBase

_SCHEMA = """
CREATE TABLE IF NOT EXISTS velocity_events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    key    TEXT NOT NULL,
    ts     REAL NOT NULL,
    amount REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_velocity_key_ts ON velocity_events (key, ts);
"""


class SqliteVelocityStore(SqliteBase):
    def __init__(self, path):
        super().__init__(path)
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def record(self, key: str, ts: float, amount_usd: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO velocity_events (key, ts, amount) VALUES (?, ?, ?)",
                (key, ts, amount_usd),
            )
            self._conn.commit()

    def window(self, key: str, now: float, window_seconds: float) -> list[tuple[float, float]]:
        """Entries within [now - window, now], pruning expired rows.

        Pruning is retention management, not history mutation — the decision
        evidence (the exact window each verdict saw) lives in the WORM ledger's
        archives, so expiring raw counter rows is safe and keeps the store
        bounded.
        """
        cutoff = now - window_seconds
        with self._lock:
            self._conn.execute(
                "DELETE FROM velocity_events WHERE key = ? AND ts < ?",
                (key, cutoff),
            )
            rows = self._conn.execute(
                "SELECT ts, amount FROM velocity_events "
                "WHERE key = ? AND ts >= ? AND ts <= ? ORDER BY ts, id",
                (key, cutoff, now),
            ).fetchall()
            self._conn.commit()
        return [(float(ts), float(a)) for ts, a in rows]

    def seed(self, mapping: dict) -> None:
        with self._lock:
            for key, entries in mapping.items():
                for ts, amt in entries:
                    self._conn.execute(
                        "INSERT INTO velocity_events (key, ts, amount) VALUES (?, ?, ?)",
                        (key, float(ts), float(amt)),
                    )
            self._conn.commit()

    def reset(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM velocity_events")
            self._conn.commit()
